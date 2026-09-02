// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package alerts is the calm-alerting model behind `whisper alerts`: the plane's own
// rows decoded, the derivations the CLI is allowed to make on top of them, and the
// renderers that turn both into the block a person reads in ten seconds.
//
// It holds NO network code and imports nothing from internal/cli, so every rule in
// here is testable against a fixture with no server, no key and no terminal. The
// command file wires it to internal/client.
//
// Two rules govern everything in this package, and both come from the design:
//
//	The plane serves the words; the surface renders them. The lane vocabulary
//	(act-now / review / handled) and the thresholds behind it are SERVED cells
//	(op:list{kind:'coverage'} publishes act_now_at and review_at precisely so no
//	consumer re-derives them). Nothing here contains a local copy of a served
//	threshold, and a missing served field renders as unknown rather than falling
//	back to a local default - a silent fallback is how two surfaces come to
//	disagree during a rollout.
//
//	Silence is not quiet. A read that failed and a read that came back empty are
//	different facts and must render as different TEXT. Every count in here is
//	nullable, and a nil count means "not read", never zero.
package alerts

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// The lane tokens the plane serves on a standing row. They are constants here so the
// renderer and the filters spell them identically, NOT so that anything re-derives
// them: a lane arrives on the wire and is never computed from a score in this package.
const (
	LaneActNow = "act-now"
	LaneReview = "review"
	// LaneQuiet is the plane's third lane. It is accepted as a FILTER token and it is
	// never printed as prose: "handled" would assert that somebody handled it, and the
	// band only means the row is not asking for anyone.
	LaneQuiet = "handled"
	// LaneUnscored is the empty lane a never-scored row carries. Unscored is not quiet:
	// a finding nobody measured is an unknown, and filing it under the quietest lane
	// would hide every unmeasured detection.
	LaneUnscored = ""
)

// LaneProse is how a lane is spoken to a person. "handled" deliberately has no prose
// form of its own: a row in that band is not asking for anyone, which is a statement
// about the queue and not a claim that work was done.
func LaneProse(lane string) string {
	switch lane {
	case LaneActNow:
		return "act now"
	case LaneReview:
		return "review"
	case LaneQuiet:
		return "not asking"
	default:
		return "unscored"
	}
}

// LaneRank orders the lanes worst-first for display. Unscored sorts between review and
// the quiet band: it is not an emergency, and it is certainly not settled.
func LaneRank(lane string) int {
	switch lane {
	case LaneActNow:
		return 0
	case LaneReview:
		return 1
	case LaneUnscored:
		return 2
	default:
		return 3
	}
}

// StateOpen is the only standing state the plane emits on kind:'standing'; the others
// (done, snoozed, auto_resolved) drop out of the listing by construction. It is named
// here because the question is "is it still true", and that question has to
// be answerable from a fixture row that carries any state at all.
const StateOpen = "open"

// Row is one standing condition exactly as the plane serves it, plus nothing. Every
// cell is a decode of a served key; no cell is invented here.
//
// The nullable cells are nullable on purpose. A score of nil means the row was never
// scored, which is a different fact from a score of zero, and an age of nil means the
// row carries no first-seen stamp rather than that it began at the epoch.
type Row struct {
	Agent       string
	Address     string
	ID          string // the plane's own task id: a technique, a cve-, a plumbing condition
	Technique   string // set only when the id IS an ATT&CK technique, per the plane
	Kind        string
	Title       string
	Lane        string // SERVED. Never derived here.
	Priority    *float64
	Fused       *float64
	Exposure    string
	State       string
	FirstSeen   int64
	AgeMs       *int64
	Confidence  float64
	Origin      string
	Evidence    string
	Remediation string
	Ack         string
	AckAt       *int64
	Assignee    string
}

// Ref is how a person says a row out loud, and it is the plane's own dedupe identity
// spelled for a keyboard: a detection dedupes on (address, technique), so the CLI needs
// no id namespace of its own. The subject half prefers the agent name because that is
// what a person types; the address is what the row is actually keyed on and `show`
// prints it.
func (r Row) Ref() string {
	subject := r.Agent
	if subject == "" {
		subject = r.Address
	}
	condition := r.Technique
	if condition == "" {
		condition = r.ID
	}
	if subject == "" {
		return condition
	}
	return subject + "/" + condition
}

// Held reports whether a human has already taken this row: an acknowledgement or an
// assignee, both served cells. It is the fourth thing an alert must answer, and it is the
// reason the CLI never builds a second acknowledgement plane of its own.
func (r Row) Held() bool { return r.Ack != "" || r.Assignee != "" }

// Holder names the person who has it, preferring the assignee (a commitment) over the
// acknowledger (a glance). Empty when nobody has it.
func (r Row) Holder() string {
	if r.Assignee != "" {
		return r.Assignee
	}
	return r.Ack
}

// RowFrom decodes one op:list{kind:'standing'} item. Unknown keys are ignored and
// missing keys leave their zero value, so a plane that grows a cell never breaks this
// decode and a plane that has not grown one yet never fabricates it.
func RowFrom(item map[string]any) Row {
	return Row{
		Agent:       str(item["agent"]),
		Address:     str(item["address"]),
		ID:          str(item["id"]),
		Technique:   str(item["technique"]),
		Kind:        str(item["kind"]),
		Title:       str(item["title"]),
		Lane:        str(item["lane"]),
		Priority:    num(item["priority"]),
		Fused:       num(item["fusedPriority"]),
		Exposure:    str(item["exposure"]),
		State:       str(item["state"]),
		FirstSeen:   int64OrZero(item["firstSeen"]),
		AgeMs:       int64Ptr(item["ageMs"]),
		Confidence:  floatOrZero(item["confidence"]),
		Origin:      str(item["origin"]),
		Evidence:    str(item["evidence"]),
		Remediation: str(item["remediation"]),
		Ack:         str(item["ack"]),
		AckAt:       int64Ptr(item["ackAt"]),
		Assignee:    str(item["assignee"]),
	}
}

// Endpoint is the half of an op:list{kind:'agents'} row the alerting surface needs:
// where the row lives, whether it can still get worse, and whether we can still hear it.
type Endpoint struct {
	Agent            string
	Address          string
	Label            string
	FQDN             string
	Connectivity     string // online | idle | offline | unknown - SERVED
	Sensor           string // shipping | slow | stale | absent | unknown - SERVED
	SensorLastReport int64
	ConnLastSeen     int64
	known            bool
}

// Known reports whether this endpoint was actually read, as opposed to being the zero
// value handed back for an address the agents read did not cover. An unknown endpoint
// must never be treated as an offline one: absence is not evidence.
func (e Endpoint) Known() bool { return e.known }

// Offline is true only on the plane's own positive statement that the endpoint is
// offline. Unknown, idle and unread all read as still-live, because that question may
// only be closed by evidence, never by silence.
func (e Endpoint) Offline() bool { return e.Connectivity == "offline" }

// Blind reports that the endpoint has no host sensor shipping at all. It is a coverage
// fact, not an alert: a network-governed endpoint still cannot tell you what ran on it.
func (e Endpoint) Blind() bool { return e.Sensor == "absent" || e.Sensor == "" }

// EndpointFrom decodes one op:list{kind:'agents'} item.
func EndpointFrom(item map[string]any) Endpoint {
	return Endpoint{
		Agent:            first(str(item["agent"]), str(item["id"]), str(item["label"])),
		Address:          first(str(item["address"]), str(item["addr128"])),
		Label:            str(item["label"]),
		FQDN:             str(item["fqdn"]),
		Connectivity:     str(item["connectivity_status"]),
		Sensor:           str(item["sensor"]),
		SensorLastReport: int64OrZero(item["sensor_last_report"]),
		ConnLastSeen:     int64OrZero(item["connectivity_last_seen"]),
		known:            true,
	}
}

// Coverage is the tenant's whole envelope as the plane folds it: one row, and the only
// place the denominators come from. Every count is a value and every OMITTED cell stays
// nil, which is the plane's own discipline: an absent key is unknown, and there is no
// such thing here as an empty finding.
type Coverage struct {
	Present        bool
	ComputedAtMs   int64
	Endpoints      int64
	SensorShipping int64
	SensorSlow     int64
	SensorStale    int64
	SensorAbsent   int64
	SensorUnknown  int64
	TierWireguard  int64
	TierSocks      int64
	TierResolver   int64
	TierUnknown    int64
	ConnOnline     int64
	ConnIdle       int64
	ConnOffline    int64
	ConnUnknown    int64
	// ActNowAt and ReviewAt are the SERVED lane thresholds. They are carried so `show`
	// can print the number behind a lane, and so a future check can prove a surface is
	// not using a local copy. Nothing in this package computes a lane from them.
	ActNowAt               *float64
	ReviewAt               *float64
	Open                   int64
	ActNow                 int64
	Review                 int64
	Quiet                  int64
	Unscored               int64
	Unacknowledged         int64
	OldestOpenMs           *int64
	OldestActNowMs         *int64
	OldestUnacknowledgedMs *int64
}

// HeardFrom is the numerator of the spanning invariant: endpoints whose sensor is
// actually shipping, on cadence or slowly. Stale and absent are NOT heard from, which
// is the whole point of printing the fraction.
func (c Coverage) HeardFrom() int64 { return c.SensorShipping + c.SensorSlow }

// NetworkOnly counts endpoints we govern at the network layer with no host sensor
// reporting. At production scale this is the majority, and letting a network-tier fleet
// render as an instrumented one is the one lie this block exists to prevent.
func (c Coverage) NetworkOnly() int64 { return c.SensorAbsent }

// CoverageFrom decodes the single op:list{kind:'coverage'} item.
func CoverageFrom(item map[string]any) Coverage {
	return Coverage{
		Present:                true,
		ComputedAtMs:           int64OrZero(item["computed_at_ms"]),
		Endpoints:              int64OrZero(item["endpoints"]),
		SensorShipping:         int64OrZero(item["sensor_shipping"]),
		SensorSlow:             int64OrZero(item["sensor_slow"]),
		SensorStale:            int64OrZero(item["sensor_stale"]),
		SensorAbsent:           int64OrZero(item["sensor_absent"]),
		SensorUnknown:          int64OrZero(item["sensor_unknown"]),
		TierWireguard:          int64OrZero(item["tier_wireguard"]),
		TierSocks:              int64OrZero(item["tier_socks"]),
		TierResolver:           int64OrZero(item["tier_resolver"]),
		TierUnknown:            int64OrZero(item["tier_unknown"]),
		ConnOnline:             int64OrZero(item["conn_online"]),
		ConnIdle:               int64OrZero(item["conn_idle"]),
		ConnOffline:            int64OrZero(item["conn_offline"]),
		ConnUnknown:            int64OrZero(item["conn_unknown"]),
		ActNowAt:               num(item["act_now_at"]),
		ReviewAt:               num(item["review_at"]),
		Open:                   int64OrZero(item["open"]),
		ActNow:                 int64OrZero(item["act_now"]),
		Review:                 int64OrZero(item["review"]),
		Quiet:                  int64OrZero(item["handled"]),
		Unscored:               int64OrZero(item["unscored"]),
		Unacknowledged:         int64OrZero(item["unacknowledged"]),
		OldestOpenMs:           int64Ptr(item["oldest_open_ms"]),
		OldestActNowMs:         int64Ptr(item["oldest_act_now_ms"]),
		OldestUnacknowledgedMs: int64Ptr(item["oldest_unacknowledged_ms"]),
	}
}

// Action is one row of the containment trail: something we reached for, and whether it
// landed. The trail is what lets a page become a receipt, and its refusals are the
// loudest class on the plane - our own product is the failure in those.
type Action struct {
	TsMs       int64
	Actor      string
	Action     string
	Address    string
	Agent      string
	Result     string
	Detail     string
	Reversible bool
}

// Landed reports a control action that actually took effect. The plane spells success
// "ok"; every refused:*, failed:* and error result is a NOT, and the distinction is the
// difference between a receipt and an emergency.
func (a Action) Landed() bool { return strings.EqualFold(a.Result, "ok") }

// DidNotTake reports the highest-value signal we do not yet have: we
// reached for containment and it did not land.
func (a Action) DidNotTake() bool {
	r := strings.ToLower(strings.TrimSpace(a.Result))
	return r == "error" || strings.HasPrefix(r, "refused") || strings.HasPrefix(r, "failed")
}

// ActionFrom decodes one op:list{kind:'audit'} item.
func ActionFrom(item map[string]any) Action {
	return Action{
		TsMs:       int64OrZero(item["ts"]),
		Actor:      str(item["actor"]),
		Action:     str(item["action"]),
		Address:    str(item["address"]),
		Agent:      str(item["agent"]),
		Result:     str(item["result"]),
		Detail:     str(item["detail"]),
		Reversible: boolOf(item["reversible"]),
	}
}

// Suppression is one live rule holding some quiet. It is read so the quiet can name
// what is holding it: it must be impossible to be quiet without seeing that.
type Suppression struct {
	ID        string
	Name      string
	CreatedBy string
	CreatedAt int64
	ExpiresAt int64
	Revoked   bool
	Scope     string
}

// SuppressionFrom decodes one alert.suppressions row, liberally: the portal and the
// plane have spelled these keys more than one way and a rule that is live must render
// even if we read its name out of the other spelling.
func SuppressionFrom(item map[string]any) Suppression {
	return Suppression{
		ID:        first(str(item["id"]), str(item["key"])),
		Name:      first(str(item["name"]), str(item["label"])),
		CreatedBy: first(str(item["created_by"]), str(item["createdBy"]), str(item["actor"])),
		CreatedAt: firstInt(item["created_at"], item["createdAt"], item["created"]),
		ExpiresAt: firstInt(item["expires"], item["expires_at"], item["expiresAt"]),
		Revoked:   boolOf(item["revoked"]),
		Scope:     first(str(item["scope"]), str(item["match"]), str(item["customer"])),
	}
}

// --- the selector, parsed liberally ------------------------------------------------

// Selector is a parsed `whisper alerts` target. Both halves are optional: a bare
// subject means every condition on that endpoint, a bare condition means that condition
// wherever it is standing, and both together name exactly one row.
type Selector struct {
	Subject   string // an agent id, a label, a /128, a hostname or an fqdn - as typed
	Condition string // a technique or another task id - as typed, upper-cased if a technique
}

// Empty reports a selector that names nothing.
func (s Selector) Empty() bool { return s.Subject == "" && s.Condition == "" }

// String renders the selector the way it would be typed back.
func (s Selector) String() string {
	switch {
	case s.Subject != "" && s.Condition != "":
		return s.Subject + "/" + s.Condition
	case s.Subject != "":
		return s.Subject
	default:
		return s.Condition
	}
}

// ParseSelector reads a target the way a person types it, which is the whole point:
//
//	scout/T1486 an agent and a technique
//	T1486 a technique, wherever it stands
//	scout an endpoint, everything on it
//	2a04:2a01:...:1/T1486 a /128 and a technique
//	2a04:2a01:...:1/128 a /128 written with its prefix length
//	2a04:2a01:...:1/128/T1486 both, unambiguously
//	scout.t-abc.agents.whisper.online./T1486 an fqdn with a trailing dot
//
// The separator collides with CIDR notation on purpose-free grounds: a /128 is how
// every other Whisper surface writes an address, so refusing it here would make the
// alerting surface the one place the house style does not work. The split therefore
// runs from the RIGHT and skips a trailing prefix length.
//
// An empty or whitespace-only input yields an empty selector and no error; the caller
// decides whether a target was required. Anything else always parses: this function has
// no failure mode, because a target a person typed is data to match, not a syntax to
// police.
func ParseSelector(in string) Selector {
	s := strings.TrimSpace(in)
	if s == "" {
		return Selector{}
	}
	subject, condition := splitTarget(s)
	subject = strings.TrimSuffix(strings.TrimSpace(subject), ".")
	condition = strings.TrimSpace(condition)
	if condition == "" && looksLikeCondition(subject) {
		// A bare condition: "T1486", or a plumbing condition id with no endpoint.
		return Selector{Condition: normaliseCondition(subject)}
	}
	return Selector{Subject: subject, Condition: normaliseCondition(condition)}
}

// splitTarget separates the subject from the condition at the LAST slash that is not a
// prefix length. "2a04::1/128" therefore stays one subject, and "2a04::1/128/T1486"
// splits where a person means it to.
func splitTarget(s string) (subject, condition string) {
	i := strings.LastIndexByte(s, '/')
	if i < 0 {
		return s, ""
	}
	tail := s[i+1:]
	if isPrefixLen(tail) {
		return s, "" // the slash was a prefix length, not a separator
	}
	return s[:i], tail
}

// isPrefixLen reports a bare decimal that can only be an IP prefix length. Both families
// are accepted (a v4-mapped selector is not our shape, but refusing it would be a
// surprise rather than a service).
func isPrefixLen(s string) bool {
	if s == "" || len(s) > 3 {
		return false
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 0 && n <= 128
}

// looksLikeCondition reports a token that can only be a condition rather than an
// endpoint: an ATT&CK technique, or a cve id. Anything else typed on its own is read as
// an endpoint, which is the reading that matches how people talk about their fleet.
func looksLikeCondition(s string) bool {
	u := strings.ToUpper(s)
	if strings.HasPrefix(u, "CVE-") {
		return true
	}
	return IsTechnique(u)
}

// normaliseCondition upper-cases a technique so `t1486` and `T1486` are the same target,
// and leaves any other id exactly as typed (task ids are not all case-insensitive).
func normaliseCondition(s string) string {
	if s == "" {
		return ""
	}
	if u := strings.ToUpper(s); IsTechnique(u) {
		return u
	}
	return s
}

// IsTechnique reports whether a token is an ATT&CK technique id: T then four digits,
// optionally a three-digit sub-technique. It mirrors the plane's own judgement rather
// than guessing, so the CLI and the plane agree on what a technique is.
func IsTechnique(s string) bool {
	if len(s) != 5 && len(s) != 9 {
		return false
	}
	if s[0] != 'T' && s[0] != 't' {
		return false
	}
	for i := 1; i < 5; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	if len(s) == 5 {
		return true
	}
	if s[5] != '.' {
		return false
	}
	for i := 6; i < 9; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Matches reports whether a row answers to this selector. The subject half is compared
// against the agent id, the label, the address (canonicalised, so a compressed and an
// expanded /128 are one address) and the first label of the endpoint's fqdn; the
// condition half against the technique and the raw id, case-insensitively for a
// technique. A half that was not typed matches everything.
func (s Selector) Matches(r Row, e Endpoint) bool {
	if s.Condition != "" && !conditionMatches(s.Condition, r) {
		return false
	}
	if s.Subject == "" {
		return true
	}
	return subjectMatches(s.Subject, r, e)
}

func conditionMatches(want string, r Row) bool {
	return strings.EqualFold(want, r.Technique) || strings.EqualFold(want, r.ID)
}

func subjectMatches(want string, r Row, e Endpoint) bool {
	if strings.EqualFold(want, r.Agent) || strings.EqualFold(want, e.Agent) ||
		strings.EqualFold(want, e.Label) {
		return true
	}
	if SameAddress(want, r.Address) {
		return true
	}
	// An fqdn, with or without a trailing dot, and its bare first label.
	fqdn := strings.TrimSuffix(strings.ToLower(e.FQDN), ".")
	w := strings.TrimSuffix(strings.ToLower(want), ".")
	if fqdn != "" && (w == fqdn || w == firstLabel(fqdn)) {
		return true
	}
	return false
}

// SameAddress compares two textual addresses by VALUE, so 2a04:2a01:0:0::1 and
// 2a04:2a01::1 are the same endpoint, and a "/128" written on either side is ignored.
// A string that is not an address at all never equals one, and never errors.
func SameAddress(a, b string) bool {
	pa, oka := parseAddr(a)
	pb, okb := parseAddr(b)
	return oka && okb && pa == pb
}

func parseAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, false
	}
	if i := strings.LastIndexByte(s, '/'); i >= 0 && isPrefixLen(s[i+1:]) {
		s = s[:i]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func firstLabel(s string) string {
	if i := strings.IndexByte(s, '.'); i > 0 {
		return s[:i]
	}
	return s
}

// --- small decoders ---------------------------------------------------------------

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'g', -1, 64)
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return fmt.Sprint(x)
		}
		return string(b)
	}
}

func num(v any) *float64 {
	switch x := v.(type) {
	case float64:
		f := x
		return &f
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return nil
		}
		return &f
	case int64:
		f := float64(x)
		return &f
	case int:
		f := float64(x)
		return &f
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err != nil {
			return nil
		}
		return &f
	default:
		return nil
	}
}

func floatOrZero(v any) float64 {
	if f := num(v); f != nil {
		return *f
	}
	return 0
}

func int64Ptr(v any) *int64 {
	f := num(v)
	if f == nil {
		return nil
	}
	n := int64(*f)
	return &n
}

func int64OrZero(v any) int64 {
	if n := int64Ptr(v); n != nil {
		return *n
	}
	return 0
}

func firstInt(vs ...any) int64 {
	for _, v := range vs {
		if n := int64Ptr(v); n != nil && *n != 0 {
			return *n
		}
	}
	return 0
}

func boolOf(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	default:
		return false
	}
}

func first(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
