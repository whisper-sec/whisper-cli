// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/kel"
	"github.com/whisper-sec/whisper-cli/internal/trustverify"
)

// The lag window: the service records a key event before it publishes it, and heals a failed
// publish within one reconcile period, so a history may be one event ahead of DNS for that long
// plus the record's TTL and the transfer slack between the nameservers.
const (
	kelReconcilePeriod = 15 * time.Minute
	kelTransferSlack   = time.Minute
	// kelTTLCeiling bounds T, the TTL the zone signs. The zone's operator chooses it, so without a
	// ceiling a TTL of years would keep a history one event ahead acceptable for years. The
	// service publishes these records at a minute or five; a longer TTL is read as this ceiling.
	kelTTLCeiling = time.Hour
)

// kelLagWindow is one reconcile period plus T (at most kelTTLCeiling) plus the transfer slack.
func kelLagWindow(ttl time.Duration) time.Duration {
	return kelReconcilePeriod + min(ttl, kelTTLCeiling) + kelTransferSlack
}

func newIdentityVerifyCmd() *cobra.Command {
	var forTarget, resolver string
	cmd := &cobra.Command{
		Use:   "verify <file>",
		Short: "Check a saved key history against DNSSEC; no API key needed",
		Long: "Checks a key history saved by `whisper identity history --export`: every event's inclusion in\n" +
			"the transparency log, the chain of commitments and signatures, that its last event is the chain\n" +
			"head the identity publishes at _whisper-kel (DNSSEC-validated from the root), and that the keys\n" +
			"its nameservers publish are the head's. The identity's name comes from DNSSEC, never the file.\n" +
			"--for <address> binds the check to the identity you mean; without it the file's address is used\n" +
			"and named in the result.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pages, err := readBundleFile(args[0])
			if err != nil {
				return &client.ProblemError{Status: 400, Detail: err.Error()}
			}
			cx, cancel := ctx()
			defer cancel()
			rep := verifyHistory(cx, pages, forTarget, resolver)
			if g.jsonOut {
				emitJSONValue(rep)
			} else {
				renderHistoryVerdict(rep)
			}
			if !rep.Verified {
				return &client.ProblemError{Status: 1, Detail: "the key history is not verified: " + rep.Reason}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&forTarget, "for", "", "the identity the history must be of: its /128 or its name")
	cmd.Flags().StringVar(&resolver, "resolver", "", "DNS resolver to fetch records through (validation is local)")
	return cmd
}

// readBundleFile reads an exported history: one page per line as served, or a JSON array of
// pages (objects or the served strings), or a single page.
func readBundleFile(path string) ([]*kel.Page, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(b))
	var raw []string
	if strings.HasPrefix(text, "[") {
		var arr []json.RawMessage
		if err := json.Unmarshal([]byte(text), &arr); err != nil {
			return nil, fmt.Errorf("%s is not a key history: %v", path, err)
		}
		for _, m := range arr {
			var s string
			if json.Unmarshal(m, &s) == nil {
				raw = append(raw, s)
			} else {
				raw = append(raw, string(m))
			}
		}
	} else {
		for _, line := range strings.Split(text, "\n") {
			if l := strings.TrimSpace(line); l != "" {
				raw = append(raw, l)
			}
		}
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s holds no key-history page", path)
	}
	var pages []*kel.Page
	for i, r := range raw {
		p, err := kel.ParsePage(r)
		if err != nil {
			return nil, fmt.Errorf("%s page %d: %v", path, i+1, err)
		}
		pages = append(pages, p)
	}
	return pages, nil
}

// historyVerdict is the outcome of `whisper identity verify`.
type historyVerdict struct {
	Verified      bool     `json:"verified"`
	Reason        string   `json:"reason,omitempty"`
	Address       string   `json:"address"`
	AddressFrom   string   `json:"address_from"` // "caller" or "bundle"
	FQDN          string   `json:"fqdn,omitempty"`
	KeyChain      string   `json:"key_chain,omitempty"`
	Sequence      *int64   `json:"sequence,omitempty"`
	Key           string   `json:"key_digest,omitempty"`
	Head          string   `json:"head"`
	HeadPublished bool     `json:"head_published"`
	Failure       string   `json:"failure,omitempty"`
	WalkFailure   string   `json:"walk_failure,omitempty"`
	Proofs        []string `json:"proofs"`
	Signed        bool     `json:"checkpoints_signed"`
	Witnessed     bool     `json:"checkpoints_witnessed"`
	FullyProven   bool     `json:"fully_proven"`
	KeyAuthorised bool     `json:"key_authorised"`
	Breaks        []string `json:"authority_breaks"`
	Pins          []string `json:"pins"`
	PinProblems   []string `json:"pin_problems,omitempty"`
	Unreachable   []string `json:"nameservers_unreachable,omitempty"`
	LogKeySource  string   `json:"log_key_source"` // dnssec, served (by the log itself) or none
	LagUntil      string   `json:"look_again_after,omitempty"`
	// SightNotKept: the first sight of the head could not be stored, so every run is a first
	// sight and a lag never closes on this host.
	SightNotKept bool `json:"first_sight_not_kept,omitempty"`
}

// kelDNS is what the verifier reads from DNS, every answer DNSSEC-validated from the root.
type kelDNS interface {
	ProveName(ctx context.Context, addr netip.Addr) (string, error)
	ProveAddress(ctx context.Context, name string, prefer netip.Addr) (netip.Addr, error)
	ValidateKelHead(ctx context.Context, fqdn string) (*trustverify.KelHead, error)
	KelHeadFrom(ctx context.Context, fqdn, server string) (*trustverify.KelHead, error)
	Nameservers(ctx context.Context, fqdn string) ([]trustverify.Nameserver, error)
	ServedPinsFrom(ctx context.Context, fqdn string, servers []string) ([]*trustverify.ServedPins, error)
	LedgerKeys(ctx context.Context) ([]client.LedgerKey, error)
}

// validatorDNS is kelDNS over the in-process validator.
type validatorDNS struct{ v *trustverify.Validator }

func (d validatorDNS) ProveName(ctx context.Context, a netip.Addr) (string, error) {
	return d.v.ProveName(ctx, a)
}
func (d validatorDNS) ProveAddress(ctx context.Context, n string, p netip.Addr) (netip.Addr, error) {
	return provenAddressOf(ctx, d.v, n, p)
}
func (d validatorDNS) ValidateKelHead(ctx context.Context, f string) (*trustverify.KelHead, error) {
	return d.v.ValidateKelHead(ctx, f)
}
func (d validatorDNS) KelHeadFrom(ctx context.Context, f, s string) (*trustverify.KelHead, error) {
	return d.v.ValidateKelHeadFrom(ctx, f, s)
}
func (d validatorDNS) Nameservers(ctx context.Context, f string) ([]trustverify.Nameserver, error) {
	return trustverify.PublishedNameservers(ctx, d.v, f)
}
func (d validatorDNS) ServedPinsFrom(ctx context.Context, f string, s []string) ([]*trustverify.ServedPins, error) {
	return d.v.ServedPinsFrom(ctx, f, s)
}
func (d validatorDNS) LedgerKeys(ctx context.Context) ([]client.LedgerKey, error) {
	return d.v.LedgerKeys(ctx, "")
}

// verifyClock, verifyDNS and verifyServedLogKeys are seams for tests.
var (
	verifyClock = time.Now
	verifyDNS   = func(resolver string, now time.Time) kelDNS {
		return validatorDNS{trustverify.NewValidator(trustverify.NewNetResolver(resolver), nil, now)}
	}
	verifyServedLogKeys = fetchLogKeys
)

func verifyHistory(cx context.Context, pages []*kel.Page, forTarget, resolver string) *historyVerdict {
	now := verifyClock()
	rep := &historyVerdict{Address: pages[0].Address, AddressFrom: "bundle"}
	fail := func(format string, a ...any) *historyVerdict {
		rep.Verified, rep.Reason = false, fmt.Sprintf(format, a...)
		return rep
	}
	v := verifyDNS(resolver, now)
	addr, err := netip.ParseAddr(strings.TrimSpace(pages[0].Address))
	forName := ""
	if t := strings.TrimSpace(forTarget); t != "" {
		rep.AddressFrom = "caller"
		if a, aerr := netip.ParseAddr(t); aerr == nil {
			addr, err = a, nil
		} else if addr, err = v.ProveAddress(cx, t, addr); err != nil {
			return fail("%v", err)
		} else {
			forName = t
		}
	}
	if err != nil || !addr.Is6() {
		return fail("the history names no IPv6 address")
	}
	rep.Address = addr.String()
	fqdn, err := v.ProveName(cx, addr)
	if err != nil {
		return fail("the name of %s is not proven by DNSSEC: %v", addr, err)
	}
	rep.FQDN = fqdn
	if forName != "" && !strings.EqualFold(strings.TrimSuffix(forName, "."), strings.TrimSuffix(fqdn, ".")) {
		// a name that merely points at the address is not the identity: the name DNSSEC proves for
		// the address must be the one asked for
		return fail("%s is not the identity's name; %s proves %s for itself. Pass its address or that name",
			forName, addr, strings.TrimSuffix(fqdn, "."))
	}
	kh, err := v.ValidateKelHead(cx, fqdn)
	if err != nil {
		return fail("the chain head of %s is neither published nor proven absent: %v", fqdn, err)
	}
	var head *kel.Head
	if !kh.Absent {
		if head, err = kel.ParseHeadRRset(kh.Records); err != nil {
			return fail("the chain head of %s does not read: %v", fqdn, err)
		}
		rep.HeadPublished = true
	}
	window := kelLagWindow(kh.TTL)
	// The window runs from this verifier's own first sight of the head alone. The RRSIG
	// inception is no term: the zone re-signs on its own schedule, so taking the later of the
	// two could only ever lengthen the window.
	seen, kept := firstSight(fqdn, head, now)
	rep.SightNotKept = !kept
	o := kel.VerifyOptions{Head: head, NowMillis: now.UnixMilli(), HeadSeenMillis: seen.UnixMilli(),
		LagWindowMillis: window.Milliseconds()}
	o.LogKeys, rep.LogKeySource = anchoredLogKeys(cx, v)
	served, witnessed := verifyServedLogKeys(cx, now)
	if len(o.LogKeys) == 0 && served != nil {
		o.LogKeys, rep.LogKeySource = []*kel.LogKey{served}, "served"
	}
	o.Witnessed = witnessed
	res := kel.VerifyBundle(pages, kel.Subject{Address: addr.String(), FQDN: fqdn}, o)
	rep.Head = string(res.Head)
	rep.Failure = string(res.Failure)
	if res.Walk != nil {
		rep.WalkFailure = string(res.Walk.Failure)
	}
	for _, p := range res.Proofs {
		rep.Proofs = append(rep.Proofs, string(p.State))
	}
	rep.Signed, rep.Witnessed, rep.KeyAuthorised = res.CheckpointsSigned, res.CheckpointsWitnessed, res.KeyAuthorised()
	// fully proven only under a log key that does not come from the log being checked
	rep.FullyProven = res.FullyProven() && rep.LogKeySource == "dnssec"
	for _, b := range res.Breaks() {
		rep.Breaks = append(rep.Breaks, fmt.Sprintf("%d:%s at %s", b.Sequence, b.What,
			time.UnixMilli(b.EpochMillis).UTC().Format(time.RFC3339)))
	}
	var links []kel.Link
	if res.Hosted {
		rep.KeyChain = "hosted"
	} else if res.Walk != nil && res.Walk.Valid {
		rep.KeyChain = "committed"
		if res.Walk.Head.Sealed() {
			rep.KeyChain = "sealed"
		}
		s := res.Walk.Head.Sequence
		rep.Sequence, rep.Key = &s, res.Walk.Head.NewKey
		for _, p := range pages {
			for i := range p.Events {
				links = append(links, p.Events[i].Link())
			}
		}
	}
	if !res.Valid && res.Head == kel.VerdictStale {
		return fail("%s: %s%s", res.Failure, res.Reason, staleHint(res.Head, seen, now, window))
	}
	if !res.Valid {
		return fail("%s: %s", res.Failure, res.Reason)
	}
	if res.Head == kel.VerdictLagging {
		rep.LagUntil = time.UnixMilli(seen.UnixMilli() + window.Milliseconds()).UTC().Format(time.RFC3339)
	}
	// Public step 4, on the direct path: every published nameserver's own head, read beside its
	// pins, must be a state of this history, and its pins must be exactly that head's keys. On a
	// hosted identity that is the one check there is: the four records name one key.
	nss, err := v.Nameservers(cx, fqdn)
	if err != nil {
		return fail("the nameservers of %s are not proven: %v", fqdn, err)
	}
	cands := historySPKIs(pages)
	for _, ns := range nss {
		label, sh, sp, unreached, err := readNameserver(cx, v, fqdn, ns)
		rep.Unreachable = append(rep.Unreachable, unreached...)
		if err != nil {
			return fail("%v", err)
		}
		want, why := servedState(res, links, fqdn, sh, now)
		if why != "" {
			rep.PinProblems = append(rep.PinProblems, label+": "+why)
			continue
		}
		keys, problems := sp.Keys(withServedPoints(cands, sp))
		servedKeys := strings.Join(short(keys), ",")
		if servedKeys == "" {
			servedKeys = "no key in all four kinds"
		}
		rep.Pins = append(rep.Pins, label+" "+servedKeys)
		for _, pr := range problems {
			rep.PinProblems = append(rep.PinProblems, label+": "+pr)
		}
		if !acceptedSet(keys, want) {
			rep.PinProblems = append(rep.PinProblems, fmt.Sprintf("%s: serves %s, its head names %s", label,
				servedKeys, describeWant(want)))
		}
	}
	if len(rep.PinProblems) > 0 {
		return fail("the published keys are not the chain head's")
	}
	rep.Verified, rep.Reason = true, ""
	return rep
}

// readNameserver reads one nameserver's head and pins from the first of its addresses this host
// can reach. An address it cannot reach is named and skipped; an answer that does not validate
// fails the check; a nameserver none of whose addresses answers proves nothing.
func readNameserver(cx context.Context, v kelDNS, fqdn string, ns trustverify.Nameserver) (string, *trustverify.KelHead,
	*trustverify.ServedPins, []string, error) {
	var unreached []string
	for _, srv := range ns.Addrs {
		sh, err := v.KelHeadFrom(cx, fqdn, srv)
		if err == nil {
			var sp []*trustverify.ServedPins
			if sp, err = v.ServedPinsFrom(cx, fqdn, []string{srv}); err == nil && len(sp) == 1 {
				return ns.Name + " " + srv, sh, sp[0], unreached, nil
			}
		}
		if unreachable(err) {
			unreached = append(unreached, srv)
			continue
		}
		return "", nil, nil, unreached, fmt.Errorf("%s (%s) answers for %s what DNSSEC does not prove: %v", ns.Name, srv, fqdn, err)
	}
	return "", nil, nil, unreached, fmt.Errorf("no address of the nameserver %s could be reached from here", ns.Name)
}

// expected is a served key state: the sets of key digests that may be served.
type expected struct {
	hosted bool       // exactly one key, whichever
	sets   [][]string // any of these sets, exactly
}

// servedState is what a nameserver whose own head is sh may serve, given the history, or why its
// head is not a state of the history at all.
// staleHint is what a STALE verdict adds: one event ahead of a head this verifier first saw longer
// ago than the window. It cannot tell a new event from one being withheld, so it refuses; but a key
// event made just now reads the same way until DNS publishes it, so it says when that would be.
func staleHint(v kel.Verdict, seen, now time.Time, window time.Duration) string {
	if v != kel.VerdictStale {
		return ""
	}
	return fmt.Sprintf(". This verifier first saw the published head at %s, longer ago than the publish"+
		" window (%s). If the newest key event is that recent, DNS publishes it within the window: look"+
		" again after %s", seen.UTC().Format(time.RFC3339), window.Round(time.Second),
		now.Add(window).UTC().Format(time.RFC3339))
}

// Each nameserver's head is judged on its own TTL and on this verifier's first sight of that head
// state (kept per name and state, whichever server showed it first), never on the recursive head's.
func servedState(res *kel.BundleResult, links []kel.Link, fqdn string, sh *trustverify.KelHead,
	now time.Time) (expected, string) {
	window := kelLagWindow(sh.TTL)
	if res.Hosted {
		if !sh.Absent {
			return expected{}, "publishes a chain head for an identity the history says is hosted"
		}
		return expected{hosted: true}, ""
	}
	last := links[len(links)-1].Event
	if sh.Absent {
		seen := firstObservation(fqdn, nil, now)
		v := kel.CheckAbsent(links, now.UnixMilli(), seen.UnixMilli(), window.Milliseconds())
		if !v.Accepted() {
			return expected{}, "its proven absence of a chain head is not a state of this history: " + string(v) +
				staleHint(v, seen, now, window)
		}
		sets := [][]string{{last.NewKey}}
		if v == kel.VerdictLagging && len(links) > 1 {
			// one event ahead of a zone that has not published it: the pins may still be the old key's
			sets = append(sets, []string{links[len(links)-2].Event.NewKey})
		}
		return expected{sets: sets}, ""
	}
	h, err := kel.ParseHeadRRset(sh.Records)
	if err != nil {
		return expected{}, "its chain head does not read: " + err.Error()
	}
	seen := firstObservation(fqdn, h, now)
	if v := h.Check(links, now.UnixMilli(), seen.UnixMilli(), window.Milliseconds()); !v.Accepted() {
		return expected{}, "its chain head is not a state of this history: " + string(v) +
			staleHint(v, seen, now, window)
	}
	want := []string{h.Current}
	if h.Previous != "" {
		want = append(want, h.Previous)
	}
	return expected{sets: [][]string{want}}, ""
}

func acceptedSet(keys []string, want expected) bool {
	if want.hosted {
		return len(keys) == 1
	}
	for _, s := range want.sets {
		if sameSet(keys, s) {
			return true
		}
	}
	return false
}

func describeWant(want expected) string {
	if want.hosted {
		return "one key"
	}
	var parts []string
	for _, s := range want.sets {
		parts = append(parts, strings.Join(short(s), ","))
	}
	return strings.Join(parts, " or ")
}

// anchoredLogKeys are the log's checkpoint keys from DNSSEC, the anchor that does not come from
// the log being checked.
func anchoredLogKeys(cx context.Context, v kelDNS) ([]*kel.LogKey, string) {
	lks, err := v.LedgerKeys(cx)
	if err != nil {
		return nil, "none"
	}
	var out []*kel.LogKey
	for _, lk := range lks {
		if raw, err := base64.StdEncoding.DecodeString(lk.PublicKey); err == nil {
			if k, err := kel.NewLogKey(lk.Origin, raw); err == nil {
				out = append(out, k)
			}
		}
	}
	if len(out) == 0 {
		return nil, "none"
	}
	return out, "dnssec"
}

// unreachable reports a transport failure (no route, refused, timed out), never a validation one.
func unreachable(err error) bool {
	var op *net.OpError
	return err != nil && (errors.As(err, &op) || errors.Is(err, os.ErrDeadlineExceeded))
}

// provenAddressOf resolves a name to the address it proves under DNSSEC, preferring the one the
// history names.
func provenAddressOf(cx context.Context, v *trustverify.Validator, name string, prefer netip.Addr) (netip.Addr, error) {
	rrs, err := v.ValidateRRSet(cx, name, 28)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%s has no DNSSEC-proven address: %v", name, err)
	}
	var first netip.Addr
	for _, rr := range rrs {
		f := strings.Fields(rr.String())
		a, err := netip.ParseAddr(f[len(f)-1])
		if err != nil {
			continue
		}
		if a == prefer {
			return a, nil
		}
		if !first.IsValid() {
			first = a
		}
	}
	if !first.IsValid() {
		return netip.Addr{}, fmt.Errorf("%s has no DNSSEC-proven address", name)
	}
	return first, nil
}

// historySPKIs is every key the history shows, the candidates the served records are matched to.
func historySPKIs(pages []*kel.Page) [][]byte {
	var cands [][]byte
	for _, p := range pages {
		for _, e := range p.Events {
			if len(e.SPKI) > 0 {
				cands = append(cands, e.SPKI)
			}
		}
	}
	return cands
}

// withServedPoints adds the keys the OPENPGPKEY records carry to the candidates, so a key the
// history does not show (a hosted identity's) can still be checked across the four records.
func withServedPoints(cands [][]byte, sp *trustverify.ServedPins) [][]byte {
	out := append([][]byte(nil), cands...)
	for _, pt := range sp.OpenPGP {
		if len(pt) != 65 || pt[0] != 4 {
			continue
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(pt[1:33]), Y: new(big.Int).SetBytes(pt[33:])}
		if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
			out = append(out, der)
		}
	}
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func short(ds []string) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		if len(d) > 16 {
			d = d[:16]
		}
		out[i] = d
	}
	return out
}

// fetchLogKeys reads the log's checkpoint key and witness policy, keyless. Without them the
// proofs are still checked against each checkpoint's root, and the verdict says the
// checkpoints were not signature-checked.
func fetchLogKeys(cx context.Context, now time.Time) (*kel.LogKey, func(string) bool) {
	c, err := resolveClient(false, false)
	if err != nil {
		return nil, nil
	}
	var key *kel.LogKey
	if lk, err := c.FetchLedgerKey(cx); err == nil {
		if raw, err := base64.StdEncoding.DecodeString(lk.PublicKey); err == nil {
			key, _ = kel.NewLogKey(lk.Origin, raw)
		}
	}
	var witnessed func(string) bool
	if pol, err := c.FetchWitnessKeys(cx); err == nil && pol != nil {
		need := pol.Threshold
		if need < 1 {
			need = 1
		}
		witnessed = func(note string) bool {
			cp, err := client.ParseCheckpointNote(note)
			return err == nil && cp.VerifyIndependentCosignatures(pol, now.Unix()) >= need
		}
	}
	return key, witnessed
}

// observedDir is where the verifier keeps when it first saw each head; a package var for tests.
var observedDir = func() string {
	d, err := os.UserConfigDir()
	if err != nil || d == "" {
		return ""
	}
	return filepath.Join(d, "whisper", "kel-observed")
}

// firstObservation is when this verifier first saw this head (or this proven absence), kept on
// disk so the lag window can close: a check run once has no earlier sight than now, and a head
// one event behind would read as lagging every time it ran. Each head is written once and never
// moved; a store that cannot be written makes the check one-shot again, never wrong.
func firstObservation(fqdn string, head *kel.Head, now time.Time) time.Time {
	t, _ := firstSight(fqdn, head, now)
	return t
}

// firstSight is firstObservation and whether the sight is on disk, so a report can say when the
// window cannot close because the store could not be written.
func firstSight(fqdn string, head *kel.Head, now time.Time) (time.Time, bool) {
	dir := observedDir()
	if dir == "" {
		return now, false
	}
	id := strings.ToLower(strings.TrimSuffix(fqdn, ".")) + "\x00absent"
	if head != nil {
		id = strings.ToLower(strings.TrimSuffix(fqdn, ".")) + "\x00" + head.IdentityRef + "\x00" +
			strconv.FormatInt(head.Sequence, 10) + "\x00" + head.Event
	}
	sum := sha256.Sum256([]byte(id))
	path := filepath.Join(dir, hex.EncodeToString(sum[:16]))
	if b, err := os.ReadFile(path); err == nil {
		if ms, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && ms > 0 {
			return time.UnixMilli(ms), true
		}
		_ = os.Remove(path) // a record a crash tore: it proves nothing, so this sight is the first
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return now, false
	}
	// whole, then linked into place: a reader sees a complete record or none, and the first
	// writer's record is the one that stays
	record := []byte(strconv.FormatInt(now.UnixMilli(), 10))
	tmp := fmt.Sprintf("%s.tmp-%d-%d", path, os.Getpid(), now.UnixNano())
	if err := writeSynced(tmp, record, os.O_WRONLY|os.O_CREATE|os.O_TRUNC); err != nil {
		return now, false
	}
	defer os.Remove(tmp)
	err := os.Link(tmp, path)
	switch {
	case err == nil:
		syncDir(dir)
		return now, true
	case errors.Is(err, os.ErrExist):
		if b, rerr := os.ReadFile(path); rerr == nil {
			if ms, perr := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); perr == nil && ms > 0 {
				return time.UnixMilli(ms), true
			}
		}
		return now, false
	default:
		// a filesystem with no hard links: an exclusive create keeps first-writer-wins, and a torn
		// record is the case the read above already treats as no record
		if writeSynced(path, record, os.O_WRONLY|os.O_CREATE|os.O_EXCL) == nil {
			syncDir(dir)
			return now, true
		}
		return now, false
	}
}

// syncDir makes a new directory entry durable, so a first sight survives a power cut. Best effort:
// a lost entry only makes the next run a first sight again, a longer window and never a refusal.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// writeSynced writes b to path under flag, mode 0600, and syncs it before closing, so a record
// that is linked into place after a crash is whole.
func writeSynced(path string, b []byte, flag int) error {
	f, err := os.OpenFile(path, flag, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func renderHistoryVerdict(r *historyVerdict) {
	name := r.Address
	if r.FQDN != "" {
		name = r.FQDN + " (" + r.Address + ")"
	}
	fmt.Printf("identity   %s\n", name)
	if r.AddressFrom == "bundle" {
		fmt.Printf("           the address is the history's own; pass --for <address> to bind it\n")
	}
	if r.KeyChain != "" {
		line := r.KeyChain
		if r.Sequence != nil {
			line += fmt.Sprintf(", sequence %d, key %s", *r.Sequence, r.Key[:16])
		}
		fmt.Printf("chain      %s\n", line)
	}
	if r.Head != "" {
		where := "_whisper-kel, DNSSEC"
		if !r.HeadPublished {
			where = "proven absent, DNSSEC"
		}
		fmt.Printf("head       %s (%s)\n", r.Head, where)
	}
	if len(r.Proofs) > 0 {
		proven := 0
		for _, p := range r.Proofs {
			if p == string(kel.ProofProven) {
				proven++
			}
		}
		signed := "checkpoints not signature-checked"
		if r.Signed {
			signed = "under log-signed checkpoints"
			if r.LogKeySource == "served" {
				signed += " (the log key as the log serves it, not DNSSEC-anchored)"
			}
			if r.Witnessed {
				signed += ", witnessed (as the log's witness policy says)"
			}
		}
		fmt.Printf("proofs     %d of %d proven %s\n", proven, len(r.Proofs), signed)
	}
	switch {
	case len(r.Breaks) > 0:
		fmt.Printf("authority  breaks: %s\n", strings.Join(r.Breaks, "; "))
	case r.KeyChain == "committed" || r.KeyChain == "sealed":
		fmt.Printf("authority  every move authorised by the chain's own keys\n")
	}
	for _, p := range r.Pins {
		fmt.Printf("pins       %s\n", p)
	}
	// what kept the pins from matching, each in its own words (a kind the service has turned off
	// among them); without these lines a refusal named only its summary
	for _, p := range r.PinProblems {
		fmt.Printf("problem    %s\n", p)
	}
	if len(r.Unreachable) > 0 {
		fmt.Printf("           not reachable from here: %s\n", strings.Join(r.Unreachable, ", "))
	}
	if r.LagUntil != "" {
		fmt.Printf("lag        DNS is one event behind, within the publish window; look again after %s\n", r.LagUntil)
		if r.SightNotKept {
			fmt.Printf("           this host could not keep its first sight of the head, so every run starts the window again\n")
		}
	}
	switch {
	case r.Verified && r.KeyChain == "hosted":
		fmt.Fprintln(os.Stderr, "whisper: verified: a hosted identity, outside the key log, serving one key")
	case r.Verified:
		fmt.Fprintln(os.Stderr, "whisper: key history verified")
	}
}
