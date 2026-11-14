// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// migrateacl.go turns a migration plan into the WhaleACL document `apply` publishes.
//
// The plan already says, rule by rule, what carries exactly, what carries approximately and
// what carries as something broader (and `apply` refuses that last class until the operator
// accepts it). This file must not add a fourth outcome nobody was told about. So every
// translation below either keeps a token's meaning or NARROWS it, and every narrowing (a
// token, a rule, an alias, a test or an ssh rule that does not carry) is returned in Dropped
// and printed, because a rule that disappears without a line is a rule nobody knows they lost.
//
// Three facts about the target shape the translation:
//
//   - The document governs the whole TENANT. `*` and `autogroup:member` here select every
//     agent in the account, tagged ones and ones outside this migration included, where in
//     Tailscale `autogroup:member` is untagged user devices only. So neither is ever written
//     through: they become groups scoped to the planned nodes (group:migrated and friends).
//   - Their addresses never carry. A tailnet address is a private CGNAT address that means
//     nothing outside their coordination server, so anything naming one becomes the node's
//     minted /128, or is dropped when it belonged to no node. A non-tailnet destination was
//     reachable in their tailnet only through a subnet router or an exit node, neither of
//     which carries, so it is dropped rather than turned into direct egress.
//   - Their ACL never governed a node's own internet access (only exit-node use). Under a
//     default-deny document every agent's egress would stop, so when their file says nothing
//     about the internet one grant keeps egress exactly as it is today, and says so.
//
// The document is a pure function of (plan, addresses): the same inputs give the same
// bytes, so a re-run can be compared and a review means something.

// ACLBuild is the document and an honest account of how it was made.
type ACLBuild struct {
	// Document is the compact JSON sent to the control plane.
	Document []byte
	Grants   int
	SSHRules int
	Tests    int
	// Notes are things the document ADDS that their file did not say, and why.
	Notes []string
	// Dropped names everything that did not carry, and why, in a stable order.
	Dropped []string
}

// MaxACLBytes is the control plane's cap on a submitted document. The check is made on the
// ESCAPED form, which is what actually crosses the front door and is never shorter than
// the raw document.
const MaxACLBytes = 49_000

// ErrNothingToPublish is returned when no rule carries at all. Publishing nothing leaves the
// fleet open inside its tenancy, and publishing a bare default-deny refuses every flow; which
// of those the operator means is their decision, so neither is made for them.
var ErrNothingToPublish = errors.New("no rule in this plan carries into a WhaleACL grant")

// tagShape is the tag syntax the control plane accepts at register, after lower-casing.
var tagShape = regexp.MustCompile(`^tag:[a-z0-9]([a-z0-9-]{0,57}[a-z0-9])?$`)

// MaxNodeTags is the control plane's bound on tags per credential.
const MaxNodeTags = 16

// loginShape is the local-account syntax the ssh block accepts.
var loginShape = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// NodeTags is the tag list a node is registered with: lower-cased (the control plane
// canonicalises to lower case and the document compares exact-case, so both sides must be
// written the same way), de-duplicated and sorted, so a retried register is byte-identical.
func NodeTags(n PlanNode) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range n.Tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// ValidatePlanTags refuses, before anything is written, a plan whose tags this control plane
// cannot hold faithfully: a malformed tag (its register would be refused halfway through
// the run), too many tags on one node, or two tags that differ only in case (lower-casing
// would merge them, and every rule on either would then reach both).
func ValidatePlanTags(p *Plan) error {
	spellings := map[string]map[string]bool{}
	note := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" {
			return
		}
		l := strings.ToLower(t)
		if spellings[l] == nil {
			spellings[l] = map[string]bool{}
		}
		spellings[l][t] = true
	}
	var problems []string
	for _, n := range p.Nodes {
		tags := NodeTags(n)
		if len(tags) > MaxNodeTags {
			problems = append(problems, fmt.Sprintf("%s carries %d tags and a node can hold at most %d", n.Label, len(tags), MaxNodeTags))
		}
		for _, t := range tags {
			if !tagShape.MatchString(t) {
				problems = append(problems, fmt.Sprintf("%s carries %q, which is not a tag this control plane accepts "+
					"(tag: then 1 to 59 of a-z, 0-9 and -, not starting or ending with -)", n.Label, t))
			}
		}
		for _, t := range n.Tags {
			note(t)
		}
	}
	for _, s := range planTokens(p) {
		target, _ := SplitDst(s)
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(target)), "tag:") {
			note(target)
		}
	}
	for _, l := range sortedKeys(spellings) {
		if len(spellings[l]) > 1 {
			problems = append(problems, fmt.Sprintf("%s are different tags in their file and the same tag here "+
				"(tags are case-insensitive on this side), so every rule on either would reach both",
				strings.Join(sortedKeys(spellings[l]), " and ")))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("this plan's tags cannot be carried faithfully, and nothing has been written:\n  - %s",
			strings.Join(problems, "\n  - "))
	}
	return nil
}

// BuildMigrationACL builds the WhaleACL for a plan whose nodes have all been given their
// /128 (addrs maps a node's TailscaleID to it).
func BuildMigrationACL(p *Plan, addrs map[string]string) (*ACLBuild, error) {
	if p == nil {
		return nil, fmt.Errorf("no plan")
	}
	if missing := p.missingPolicyContext(); missing != "" {
		return nil, fmt.Errorf("this plan was written by a build that did not record the tailnet's %s, and the ACL "+
			"cannot be built faithfully without them. Re-run `whisper whale migrate plan`; the identities this plan "+
			"already applied are found again by name, not minted twice", missing)
	}
	tx, err := newACLTranslator(p, addrs)
	if err != nil {
		return nil, err
	}

	doc := aclDocument{}
	internetRule := false
	for _, r := range p.Rules {
		if r.Plane == PlaneEgress {
			internetRule = true
		}
		g, ok := tx.grant(r)
		if !ok {
			continue
		}
		doc.Grants = append(doc.Grants, g)
		if t, ok := tx.testFor(g); ok {
			doc.Tests = append(doc.Tests, t)
		}
	}
	carried := len(doc.Grants)
	for i, raw := range p.Tests {
		doc.Tests = append(doc.Tests, tx.theirTest(i, raw)...)
	}
	if len(p.SSH) > 0 {
		for _, s := range p.SSH {
			if r, ok := tx.sshRule(s); ok {
				doc.SSH = append(doc.SSH, r)
			}
		}
		if len(doc.SSH) == 0 {
			tx.drop("ssh: none of their %d ssh rule(s) carried, so no ssh block is written and each target's own "+
				"`whisper whale ssh-authz` flags decide who may log in", len(p.SSH))
		}
	}
	if carried == 0 {
		return &ACLBuild{Dropped: tx.droppedLines()}, ErrNothingToPublish
	}
	var notes []string
	if !internetRule {
		g := aclGrant{Src: []string{"*"}, Dst: []string{"autogroup:internet"}, IP: []string{"*"}}
		doc.Grants = append(doc.Grants, g)
		// Its own assertion, so the claim below is proven by the control plane at write time.
		doc.Tests = append(doc.Tests, aclTest{Src: []string{"*"}, Accept: []string{"autogroup:internet:443"}})
		notes = append(notes, "added `* -> autogroup:internet`: their policy never governed a node's own internet "+
			"access (only exit-node use), and without this grant a default-deny document would stop the egress of "+
			"every agent in the account. It keeps egress exactly as it is today")
	}
	if len(tx.hostsOut) > 0 {
		doc.Hosts = tx.hostsOut
	}
	if len(tx.groupsOut) > 0 {
		doc.Groups = map[string][]string{}
		for g, m := range tx.groupsOut {
			if len(m) > 0 {
				doc.Groups[g] = m
			}
		}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// The document is policy, not HTML: `<` and `&` stay themselves.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("serialising the WhaleACL: %w", err)
	}
	return &ACLBuild{
		Document: bytes.TrimSpace(buf.Bytes()),
		Grants:   len(doc.Grants),
		SSHRules: len(doc.SSH),
		Tests:    len(doc.Tests),
		Notes:    notes,
		Dropped:  tx.droppedLines(),
	}, nil
}

// missingPolicyContext names what an older plan file lacks, or returns "". The source
// counts and the fidelity report were always written, so they say what the tailnet HAD
// even when the plan did not record it.
func (p *Plan) missingPolicyContext() string {
	var missing []string
	if p.Source.Groups > 0 && len(p.Groups) == 0 {
		missing = append(missing, fmt.Sprintf("%d group(s)", p.Source.Groups))
	}
	if p.Source.Hosts > 0 && len(p.Hosts) == 0 {
		missing = append(missing, fmt.Sprintf("%d hosts alias(es)", p.Source.Hosts))
	}
	if len(p.Tests) == 0 {
		for _, f := range p.Fidelity {
			if f.Kind == "tests" {
				missing = append(missing, "tests block")
				break
			}
		}
	}
	return strings.Join(missing, ", ")
}

// The document, in the WhaleACL grammar (see `whisper whale acl --help`). Field order is the
// order a person reads it in; encoding/json sorts the map keys, so the bytes are stable.
type aclDocument struct {
	Groups map[string][]string `json:"groups,omitempty"`
	Hosts  map[string]string   `json:"hosts,omitempty"`
	Grants []aclGrant          `json:"grants"`
	SSH    []aclSSH            `json:"ssh,omitempty"`
	Tests  []aclTest           `json:"tests,omitempty"`
}

type aclGrant struct {
	Src []string `json:"src"`
	Dst []string `json:"dst"`
	IP  []string `json:"ip"`
}

type aclSSH struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
	Users  []string `json:"users"`
}

type aclTest struct {
	Src    []string `json:"src"`
	Accept []string `json:"accept,omitempty"`
	Deny   []string `json:"deny,omitempty"`
}

// --- the translator ------------------------------------------------------------------

type aclTranslator struct {
	p         *Plan
	addr      []netip.Addr       // by node index
	byTailnet map[netip.Addr]int // their address -> node index
	byName    map[string]int     // every name a node answers to, lower case -> node index
	aliasNode map[string]int     // their alias -> the node behind it
	hostsOut  map[string]string
	groupsOut map[string][]string
	groupSeen map[string]bool
	// The plan-scoped stand-ins for `*`, autogroup:member and autogroup:tagged.
	allGroup, memberGroup, taggedGroup string
	usedGroups                         map[string]bool // every group name taken, theirs and ours
	dropped                            map[string]struct{}
}

func newACLTranslator(p *Plan, addrs map[string]string) (*aclTranslator, error) {
	tx := &aclTranslator{
		p: p, addr: make([]netip.Addr, len(p.Nodes)),
		byTailnet: map[netip.Addr]int{}, byName: map[string]int{},
		aliasNode: map[string]int{}, hostsOut: map[string]string{},
		groupsOut: map[string][]string{}, groupSeen: map[string]bool{},
		dropped: map[string]struct{}{},
	}
	var missing []string
	for i, n := range p.Nodes {
		a, err := netip.ParseAddr(strings.TrimSpace(addrs[n.TailscaleID]))
		if err != nil || !a.Is6() || a.Is4In6() {
			missing = append(missing, n.Label)
			continue
		}
		tx.addr[i] = a
		for _, s := range n.TailnetAddrs {
			if ta, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
				tx.byTailnet[ta.Unmap()] = i
			}
		}
		for _, name := range []string{n.Label, n.Hostname, n.MagicDNSName, firstLabel(n.MagicDNSName)} {
			if k := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".")); k != "" {
				if _, taken := tx.byName[k]; !taken {
					tx.byName[k] = i
				}
			}
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("the ACL names every node by its Whisper /128, and %d node(s) have none recorded "+
			"in this plan yet (%s). Their identity step has to succeed first", len(missing), strings.Join(missing, ", "))
	}

	// Their aliases, rewritten before any rule is read so a rule naming one sees the result.
	for _, alias := range sortedKeys(p.Hosts) {
		val := strings.TrimSpace(p.Hosts[alias])
		if strings.Contains(alias, ":") {
			tx.drop("hosts alias %q: an alias may not contain \":\" here (that prefix is reserved for tag:, group: and autogroup:)", alias)
			continue
		}
		a, single, inTailnet, ok := parseAddrOrPrefix(val)
		switch {
		case !ok:
			tx.drop("hosts alias %q: %q is neither an address nor a prefix", alias, val)
		case inTailnet && single:
			if i, found := tx.byTailnet[a]; found {
				tx.aliasNode[alias] = i
				tx.hostsOut[alias] = tx.addr[i].String()
			} else {
				tx.drop("hosts alias %q: %s is a tailnet address that belongs to no node in this plan", alias, val)
			}
		case inTailnet:
			tx.drop("hosts alias %q: %s is a range inside their tailnet, which has no meaning here", alias, val)
		default:
			tx.drop("hosts alias %q: %s is outside their tailnet, reachable there only through a subnet router or an "+
				"exit node, and neither carries", alias, val)
		}
	}

	// The plan-scoped selectors, named so they cannot collide with one of theirs.
	// They are written only when a rule uses them, with their members' hosts entries.
	tx.allGroup = tx.freeGroupName("group:migrated")
	tx.memberGroup = tx.freeGroupName("group:migrated-members")
	tx.taggedGroup = tx.freeGroupName("group:migrated-tagged")
	return tx, nil
}

// freeGroupName picks a name for a plan-scoped group that NOTHING in their file uses,
// declared or not. An undeclared group (IdP or SCIM membership) is still their name: if a
// plan-scoped group took it, a rule naming theirs would be granted every planned node.
func (tx *aclTranslator) freeGroupName(base string) string {
	if tx.usedGroups == nil {
		tx.usedGroups = referencedGroupNames(tx.p)
	}
	used := tx.usedGroups
	name := base
	for n := 2; ; n++ {
		if !used[name] {
			used[name] = true
			return name
		}
		name = fmt.Sprintf("%s-%d", base, n)
	}
}

// referencedGroupNames is every group: token anywhere in the plan, declared or not.
func referencedGroupNames(p *Plan) map[string]bool {
	out := map[string]bool{}
	for _, t := range planTokens(p) {
		if target, _ := SplitDst(t); strings.HasPrefix(target, "group:") {
			out[target] = true
		}
	}
	for g := range p.Groups {
		out[g] = true
	}
	return out
}

// planTokens is every selector the plan carries: rule sources and destinations, ssh
// sources and destinations, group members, and their tests' sources and targets.
func planTokens(p *Plan) []string {
	var out []string
	for _, r := range p.Rules {
		out = append(out, r.Src...)
		out = append(out, r.Dst)
	}
	for _, s := range p.SSH {
		out = append(out, s.Src...)
		out = append(out, s.Dst...)
	}
	for _, members := range p.Groups {
		out = append(out, members...)
	}
	for _, tc := range p.Tests {
		for _, k := range []string{"src", "accept", "deny"} {
			switch v := tc[k].(type) {
			case string:
				out = append(out, v)
			case []any:
				for _, x := range v {
					if str, ok := x.(string); ok {
						out = append(out, str)
					}
				}
			}
		}
	}
	return out
}

func firstLabel(fqdn string) string {
	if i := strings.IndexByte(fqdn, '.'); i > 0 {
		return fqdn[:i]
	}
	return ""
}

// parseAddrOrPrefix reads an address or a prefix, reporting whether it is one host and
// whether it lies in their tailnet.
func parseAddrOrPrefix(v string) (addr netip.Addr, single, inTailnet, ok bool) {
	if a, err := netip.ParseAddr(v); err == nil {
		a = a.Unmap()
		return a, true, wgtun.InTailnet(a), true
	}
	pfx, err := netip.ParsePrefix(v)
	if err != nil {
		return netip.Addr{}, false, false, false
	}
	a := pfx.Addr().Unmap()
	single = pfx.Bits() == pfx.Addr().BitLen()
	inTailnet = wgtun.TailnetOverlaps(pfx)
	return a, single, inTailnet, true
}

func (tx *aclTranslator) drop(format string, args ...any) {
	tx.dropped[fmt.Sprintf(format, args...)] = struct{}{}
}

func (tx *aclTranslator) droppedLines() []string {
	out := make([]string, 0, len(tx.dropped))
	for k := range tx.dropped {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// nodeToken names one node in the document: a `hosts` entry under its label, holding its
// /128, so the document reads in the operator's own names and resolves by VALUE (the
// control plane looks a hosts name up before any node label). When their file already uses
// that name as an alias, the /128 itself is written instead.
func (tx *aclTranslator) nodeToken(i int) string {
	label := tx.p.Nodes[i].Label
	if _, clash := tx.p.Hosts[label]; clash || label == "" {
		return tx.addr[i].String()
	}
	tx.hostsOut[label] = tx.addr[i].String()
	return label
}

// groupToken returns the token for one of the plan-scoped groups, or nothing when that
// group is empty (the control plane refuses an empty group, and it would select nobody).
func (tx *aclTranslator) groupToken(name, theirs, where string) []string {
	if _, built := tx.groupsOut[name]; !built {
		var members []string
		for i, n := range tx.p.Nodes {
			tagged := len(n.Tags) > 0
			if name == tx.allGroup || (name == tx.memberGroup && !tagged) || (name == tx.taggedGroup && tagged) {
				members = append(members, tx.nodeToken(i))
			}
		}
		tx.groupsOut[name] = members
	}
	if len(tx.groupsOut[name]) == 0 {
		tx.drop("%s: %s selects no node in this plan", where, theirs)
		return nil
	}
	return []string{name}
}

// source translates one source token into tokens that select the same planned nodes or
// fewer. A source is always one of our own nodes.
func (tx *aclTranslator) source(tok, where string) []string {
	return tx.selector(tok, where, false)
}

// destination translates one destination token.
func (tx *aclTranslator) destination(tok, where string) []string {
	return tx.selector(tok, where, true)
}

func (tx *aclTranslator) selector(raw, where string, dst bool) []string {
	t := strings.TrimSpace(raw)
	lower := strings.ToLower(t)
	switch {
	case t == "":
		return nil
	case t == "*":
		// Every one of THEIR devices, which is every planned node; never every agent in the account.
		return tx.groupToken(tx.allGroup, t, where)
	case lower == "autogroup:member":
		return tx.groupToken(tx.memberGroup, t, where)
	case lower == "autogroup:tagged":
		return tx.groupToken(tx.taggedGroup, t, where)
	case dst && (lower == "autogroup:internet" || t == "0.0.0.0/0" || t == "::/0"):
		return []string{"autogroup:internet"}
	case dst && lower == "autogroup:self":
		// Theirs is "the source user's devices"; ours is the source node itself. Narrower.
		return []string{lower}
	case strings.HasPrefix(lower, "autogroup:"):
		tx.drop("%s: %s has no equivalent in this position here, so it is not carried", where, t)
		return nil
	case strings.HasPrefix(lower, "tag:"):
		if !tagShape.MatchString(lower) {
			tx.drop("%s: %s is not a tag this control plane accepts", where, t)
			return nil
		}
		return []string{lower}
	case strings.HasPrefix(t, "group:"):
		if tx.group(t) {
			return []string{t}
		}
		tx.drop("%s: %s is not carried (%s)", where, t, tx.groupWhy(t))
		return nil
	}
	if _, isAlias := tx.p.Hosts[t]; isAlias {
		if _, ok := tx.aliasNode[t]; ok {
			return []string{t}
		}
		tx.drop("%s: the alias %s was not carried (see its own line)", where, t)
		return nil
	}
	if strings.Contains(t, "@") {
		return tx.userNodes(t, where)
	}
	if a, single, inTailnet, ok := parseAddrOrPrefix(t); ok {
		switch {
		case inTailnet && single:
			if i, found := tx.byTailnet[a]; found {
				return []string{tx.nodeToken(i)}
			}
			tx.drop("%s: %s is a tailnet address that belongs to no node in this plan", where, t)
		case inTailnet:
			tx.drop("%s: %s is a range inside their tailnet, which has no meaning here", where, t)
		case dst:
			tx.drop("%s: %s is outside their tailnet, reachable there only through a subnet router or an exit node, "+
				"and neither carries", where, t)
		default:
			tx.drop("%s: %s is not one of your nodes, and a source always is", where, t)
		}
		return nil
	}
	if i, found := tx.byName[strings.ToLower(strings.TrimSuffix(t, "."))]; found {
		return []string{tx.nodeToken(i)}
	}
	tx.drop("%s: %s names no node in this plan", where, t)
	return nil
}

// userNodes is Tailscale's meaning of a user selector: that user's untagged devices.
func (tx *aclTranslator) userNodes(user, where string) []string {
	var out []string
	for i, n := range tx.p.Nodes {
		if len(n.Tags) == 0 && strings.EqualFold(strings.TrimSpace(n.Owner), user) {
			out = append(out, tx.nodeToken(i))
		}
	}
	if len(out) == 0 {
		tx.drop("%s: %s owns no untagged node in this plan", where, user)
	}
	return out
}

// group carries one of THEIR declared groups, its members translated as sources. It reports
// whether the group came out with at least one member: the control plane refuses an empty
// group, and an empty group grants nothing anyway.
func (tx *aclTranslator) group(name string) bool {
	if name == tx.allGroup || name == tx.memberGroup || name == tx.taggedGroup {
		return false // never theirs: freeGroupName picked a name their file does not use
	}
	if members, done := tx.groupsOut[name]; done {
		return len(members) > 0
	}
	if tx.groupSeen[name] {
		return false // a cycle; their own file would not have loaded either
	}
	tx.groupSeen[name] = true
	declared, ok := tx.p.Groups[name]
	if !ok {
		return false
	}
	seen := map[string]bool{}
	var members []string
	for _, m := range declared {
		for _, tok := range tx.source(m, "groups["+name+"]") {
			if !seen[tok] {
				seen[tok] = true
				members = append(members, tok)
			}
		}
	}
	tx.groupsOut[name] = members
	return len(members) > 0
}

func (tx *aclTranslator) groupWhy(name string) string {
	if _, ok := tx.p.Groups[name]; !ok {
		return "it is declared nowhere in their file, so its membership comes from an IdP or SCIM sync their API never exposes"
	}
	return "none of its members is a node in this plan"
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// grant translates one plan rule. ok is false when the rule does not carry, and the reason
// is recorded.
func (tx *aclTranslator) grant(r PlanRule) (aclGrant, bool) {
	where := fmt.Sprintf("rule %d (%s %s -> %s)", r.Index, r.From, strings.Join(r.Src, ","), r.Dst)
	if !strings.EqualFold(r.Action, "accept") || r.Dst == "" || len(r.Src) == 0 {
		tx.drop("%s: not carried, %s", where, orDefault(r.Note, "it is not an accept rule"))
		return aclGrant{}, false
	}
	ip, err := ipEntries(r.From, r.Proto, r.Ports)
	if err != nil {
		tx.drop("%s: not carried, %v", where, err)
		return aclGrant{}, false
	}
	var src []string
	for _, s := range r.Src {
		src = append(src, tx.source(s, where)...)
	}
	src = dedupe(src)
	dst := tx.destination(r.Dst, where)
	switch {
	case len(src) == 0:
		tx.drop("%s: not carried, no source survived translation", where)
		return aclGrant{}, false
	case len(dst) == 0:
		tx.drop("%s: not carried, its destination did not survive translation", where)
		return aclGrant{}, false
	}
	return aclGrant{Src: src, Dst: dst, IP: ip}, true
}

// ipEntries turns a rule's protocol and ports into the document's `ip` list. A protocol
// with no equivalent is an error, because dropping it would widen the rule.
//
// An `acls` rule with no protocol means TCP, UDP and ICMP in their grammar, not every
// protocol, so it is written as exactly those three. A grant capability is explicit: `*`
// there is every protocol, and a bare port is written as TCP and UDP.
func ipEntries(from, protoIn, portsIn string) ([]string, error) {
	proto, err := protoName(protoIn)
	if err != nil {
		return nil, err
	}
	ports := strings.TrimSpace(portsIn)
	if ports == "" {
		ports = "*"
	}
	if proto == "icmp" {
		return []string{"icmp"}, nil
	}
	if proto == "" && from == "grants" && ports == "*" {
		return []string{"*"}, nil
	}
	var pieces []string
	for _, piece := range strings.Split(ports, ",") {
		piece = strings.TrimSpace(piece)
		if piece == "*" {
			pieces = []string{"*"}
			break
		}
		if !portSpec(piece) {
			return nil, fmt.Errorf("the port constraint %q is not a port or a port range", piece)
		}
		pieces = append(pieces, piece)
	}
	if len(pieces) == 0 {
		return nil, fmt.Errorf("the port constraint %q names no port", portsIn)
	}
	protos := []string{proto}
	if proto == "" {
		protos = []string{"tcp", "udp"}
	}
	var out []string
	for _, pr := range protos {
		for _, piece := range pieces {
			out = append(out, pr+":"+piece)
		}
	}
	if proto == "" && from != "grants" {
		out = append(out, "icmp")
	}
	return out, nil
}

func portSpec(s string) bool {
	lo, hi, found := strings.Cut(s, "-")
	if !found {
		n, err := strconv.Atoi(s)
		return err == nil && n >= 0 && n <= 65535
	}
	a, err1 := strconv.Atoi(strings.TrimSpace(lo))
	b, err2 := strconv.Atoi(strings.TrimSpace(hi))
	return err1 == nil && err2 == nil && a >= 0 && b <= 65535 && a <= b
}

// protoName maps their protocol (a name or an IANA number) to the document's vocabulary.
func protoName(p string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "*":
		return "", nil
	case "tcp", "6":
		return "tcp", nil
	case "udp", "17":
		return "udp", nil
	case "icmp", "1", "ipv6-icmp", "icmpv6", "58":
		return "icmp", nil
	case "sctp", "132":
		return "sctp", nil
	}
	return "", fmt.Errorf("the protocol %q has no equivalent here, and dropping it would admit every protocol", p)
}

// sshRule translates one ssh rule. A destination is a node; a user is a POSIX login name or
// autogroup:nonroot.
func (tx *aclTranslator) sshRule(s PlanSSH) (aclSSH, bool) {
	where := fmt.Sprintf("ssh[%d]", s.Index)
	if s.Action != "accept" {
		tx.drop("%s: not carried, %s", where, orDefault(s.Note, "it is not an accept rule"))
		return aclSSH{}, false
	}
	out := aclSSH{Action: "accept"}
	for _, v := range s.Src {
		out.Src = append(out.Src, tx.source(v, where+".src")...)
	}
	for _, v := range s.Dst {
		lower := strings.ToLower(strings.TrimSpace(v))
		if v == "*" || strings.HasPrefix(lower, "autogroup:") {
			tx.drop("%s.dst: %s is not an ssh destination here (name the nodes with a tag:, a group: or a node)", where, v)
			continue
		}
		out.Dst = append(out.Dst, tx.source(v, where+".dst")...)
	}
	for _, u := range s.Users {
		u = strings.TrimSpace(u)
		if u == "autogroup:nonroot" || loginShape.MatchString(u) {
			out.Users = append(out.Users, u)
			continue
		}
		tx.drop("%s.users: %s is not a local account name here", where, u)
	}
	out.Src, out.Dst, out.Users = dedupe(out.Src), dedupe(out.Dst), dedupe(out.Users)
	if len(out.Src) == 0 || len(out.Dst) == 0 || len(out.Users) == 0 {
		tx.drop("%s: not carried, nothing survived translation on one of its sides", where)
		return aclSSH{}, false
	}
	return out, true
}

// --- the tests block -----------------------------------------------------------------

// testFor is one assertion per grant: its sources reach its destination on its first
// port. It proves each grant compiled to the nodes it names; it cannot prove the absence
// of a widening, which is what their own deny assertions (theirTest) are for. It is
// generated only when both sides resolve to a planned node, because the control plane
// refuses a test that resolves to nothing (it would always pass).
func (tx *aclTranslator) testFor(g aclGrant) (aclTest, bool) {
	if len(tx.resolve(g.Src, false)) == 0 || !tx.dstResolvable(g.Dst[0]) {
		return aclTest{}, false
	}
	proto, port := testProtoPort(g.IP[0])
	return aclTest{Src: append([]string(nil), g.Src...), Accept: []string{testTarget(proto, g.Dst[0], port)}}, true
}

// testProtoPort is the protocol and port a test asks about for one `ip` entry.
func testProtoPort(entry string) (proto, port string) {
	if entry == "*" {
		return "", "*"
	}
	if entry == "icmp" {
		return "icmp", "*"
	}
	proto, ports, _ := strings.Cut(entry, ":")
	if lo, _, found := strings.Cut(ports, "-"); found {
		return proto, lo
	}
	return proto, ports
}

func testTarget(proto, dst, port string) string {
	t := dst + ":" + port
	if proto != "" {
		t = proto + ":" + t
	}
	return t
}

// theirTest translates one assertion from their own `tests` block. Their deny assertions
// are the strongest check this document gets: the control plane runs them against what it
// compiled, before it stores a byte, so a translation that admits what they said must be
// refused is itself refused, with the pointer. An assertion that cannot be translated
// faithfully is dropped and reported, never weakened.
func (tx *aclTranslator) theirTest(i int, raw map[string]any) []aclTest {
	where := fmt.Sprintf("tests[%d]", i)
	var srcTokens []string
	switch s := raw["src"].(type) {
	case string:
		srcTokens = []string{s}
	case []any:
		for _, v := range s {
			if str, ok := v.(string); ok {
				srcTokens = append(srcTokens, str)
			}
		}
	}
	var src []string
	for _, s := range srcTokens {
		src = append(src, tx.source(s, where+".src")...)
	}
	src = dedupe(src)
	if len(src) == 0 || len(tx.resolve(src, false)) == 0 {
		tx.drop("%s: not carried, its source does not translate to a planned node", where)
		return nil
	}
	// Their assertions name a port, and a port is TCP unless the test says otherwise. Left
	// as "any protocol" it would also ask about ICMP, which a rule with no protocol admits
	// on every "port", and their own deny assertion would then fail against a faithful
	// translation (measured live on 2026-11-07: tests[2].deny[0] refused for exactly that).
	proto := "tcp"
	if v, present := raw["proto"]; present && v != nil {
		var name string
		switch x := v.(type) {
		case string:
			name = x
		case float64:
			name = strconv.FormatFloat(x, 'f', -1, 64)
		case json.Number:
			name = x.String()
		default:
			tx.drop("%s: not carried, its proto %v is neither a name nor a number", where, v)
			return nil
		}
		pn, err := protoName(name)
		if err != nil {
			tx.drop("%s: not carried, %v", where, err)
			return nil
		}
		if pn != "" {
			proto = pn
		}
	}
	out := aclTest{Src: src}
	for _, side := range []string{"accept", "deny"} {
		list, _ := raw[side].([]any)
		for j, v := range list {
			spec, _ := v.(string)
			ptr := fmt.Sprintf("%s.%s[%d]", where, side, j)
			dstTok, port := SplitDst(spec)
			if port == "" || strings.ContainsAny(port, ",-") {
				tx.drop("%s: not carried, %q does not name one port", ptr, spec)
				continue
			}
			for _, d := range tx.destination(dstTok, ptr) {
				if !tx.dstResolvable(d) {
					tx.drop("%s: not carried, %s selects no planned node", ptr, d)
					continue
				}
				tgt := testTarget(proto, d, port)
				if side == "accept" {
					out.Accept = append(out.Accept, tgt)
				} else {
					out.Deny = append(out.Deny, tgt)
				}
			}
		}
	}
	if len(out.Accept) == 0 && len(out.Deny) == 0 {
		return nil
	}
	return []aclTest{out}
}

// resolve is the local answer to "which planned nodes does this selector set name", the
// same reading the control plane gives a source over a roster of exactly these nodes. It only gates whether an assertion is generated; the control plane decides.
func (tx *aclTranslator) resolve(tokens []string, inGroup bool) map[int]bool {
	out := map[int]bool{}
	for _, t := range tokens {
		switch {
		case t == "autogroup:self":
			for i := range tx.p.Nodes {
				out[i] = true
			}
		case strings.HasPrefix(t, "tag:"):
			for i, n := range tx.p.Nodes {
				for _, nt := range NodeTags(n) {
					if nt == t {
						out[i] = true
					}
				}
			}
		case strings.HasPrefix(t, "group:"):
			if !inGroup {
				for i := range tx.resolve(tx.groupsOut[t], true) {
					out[i] = true
				}
			}
		default:
			for i := range tx.p.Nodes {
				if tx.hostsOut[t] == tx.addr[i].String() || t == tx.addr[i].String() {
					out[i] = true
				}
			}
		}
	}
	return out
}

func (tx *aclTranslator) dstResolvable(dst string) bool {
	if dst == "autogroup:internet" || dst == "autogroup:self" {
		return true
	}
	return len(tx.resolve([]string{dst}, false)) > 0
}

// SameACLDocument reports whether two WhaleACL documents say the same thing, which is how
// `apply` recognises its own document after a lost reply and how `rollback` recognises the
// one it restored. It compares MEANING, not bytes or hashes: the control plane stores a
// canonical form (object keys sorted at every level, `default` always stated, empty
// sections omitted), and reproducing its serializer byte for byte here would be a second
// implementation that eventually disagrees with the first. Arrays keep their order, because
// in this grammar order is meaning.
func SameACLDocument(a, b string) bool {
	da, okA := normalisedACL(a)
	db, okB := normalisedACL(b)
	return okA && okB && reflect.DeepEqual(da, db)
}

func normalisedACL(s string) (map[string]any, bool) {
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &m); err != nil || m == nil {
		return nil, false
	}
	for k, v := range m {
		switch x := v.(type) {
		case nil:
			delete(m, k)
		case []any:
			if len(x) == 0 {
				delete(m, k)
			}
		case map[string]any:
			if len(x) == 0 {
				delete(m, k)
			}
		}
	}
	// An absent default IS deny; the canonical form states it, the document we send does not.
	if d, ok := m["default"].(string); ok && strings.EqualFold(d, "deny") {
		delete(m, "default")
	}
	return m, true
}
