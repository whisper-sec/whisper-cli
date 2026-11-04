// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/kel"
	"github.com/whisper-sec/whisper-cli/internal/trustverify"
)

// The verify command's glue, against the service's own bundle vectors and a DNS that answers
// what a test says. The DNSSEC validation itself is trustverify's and tested there.

type bundleCase struct {
	Name      string    `json:"name"`
	Pages     []string  `json:"pages"`
	HeadHex   *[]string `json:"head_strings_hex"`
	NowMs     int64     `json:"now_ms"`
	UseLogKey bool      `json:"use_log_key"`
	Subject   struct {
		Address string `json:"address"`
		FQDN    string `json:"fqdn"`
	} `json:"subject"`
}

func bundleVectorCase(t *testing.T, name string) (bundleCase, *kel.LogKey) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "idkey", "testdata", "kel-bundle-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		LogKey struct {
			Name string `json:"name"`
			X509 string `json:"public_x509_b64"`
		} `json:"log_key"`
		Cases []bundleCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	der, _ := base64.StdEncoding.DecodeString(v.LogKey.X509)
	key, err := kel.LogKeyFromSPKI(v.LogKey.Name, der)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Cases {
		if c.Name == name {
			return c, key
		}
	}
	t.Fatalf("no vector %s", name)
	return bundleCase{}, nil
}

type fakeDNS struct {
	name    string
	nameErr error
	head    *trustverify.KelHead
	servers []string
	pins    []*trustverify.ServedPins
	addrOf  map[string]netip.Addr
	pinErr  map[string]error
	headOn  map[string]*trustverify.KelHead
	ledger  []client.LedgerKey
	groups  []trustverify.Nameserver
}

func (d *fakeDNS) ProveName(context.Context, netip.Addr) (string, error) { return d.name, d.nameErr }
func (d *fakeDNS) ProveAddress(_ context.Context, n string, _ netip.Addr) (netip.Addr, error) {
	if a, ok := d.addrOf[n]; ok {
		return a, nil
	}
	return netip.Addr{}, errors.New("no proven address")
}
func (d *fakeDNS) ValidateKelHead(context.Context, string) (*trustverify.KelHead, error) {
	if d.head == nil {
		return nil, errors.New("neither published nor proven absent")
	}
	return d.head, nil
}
func (d *fakeDNS) Nameservers(context.Context, string) ([]trustverify.Nameserver, error) {
	if d.groups != nil {
		return d.groups, nil
	}
	var out []trustverify.Nameserver
	for i, s := range d.servers {
		out = append(out, trustverify.Nameserver{Name: "ns" + strconv.Itoa(i+1) + ".example", Addrs: []string{s}})
	}
	return out, nil
}
func (d *fakeDNS) KelHeadFrom(_ context.Context, _ string, srv string) (*trustverify.KelHead, error) {
	if err := d.pinErr[srv]; err != nil {
		return nil, err
	}
	if h, ok := d.headOn[srv]; ok {
		return h, nil
	}
	return d.ValidateKelHead(context.Background(), "")
}
func (d *fakeDNS) LedgerKeys(context.Context) ([]client.LedgerKey, error) {
	if d.ledger == nil {
		return nil, errors.New("no DNSSEC-anchored ledger key")
	}
	return d.ledger, nil
}
func (d *fakeDNS) ServedPinsFrom(_ context.Context, _ string, servers []string) ([]*trustverify.ServedPins, error) {
	var out []*trustverify.ServedPins
	for _, srv := range servers {
		if err := d.pinErr[srv]; err != nil {
			return nil, err
		}
		for i, s := range d.servers {
			if s == srv && i < len(d.pins) {
				out = append(out, d.pins[i])
			}
		}
	}
	return out, nil
}

// pinsOf is what the four records serve for these keys.
func pinsOf(t *testing.T, spkis ...[]byte) *trustverify.ServedPins {
	t.Helper()
	p := &trustverify.ServedPins{}
	for _, der := range spkis {
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatal(err)
		}
		ec := pub.(*ecdsa.PublicKey)
		eh, err := ec.ECDH()
		if err != nil {
			t.Fatal(err)
		}
		pt := eh.Bytes() // the uncompressed point the OPENPGPKEY record carries
		d := kel.KeyDigest(der)
		var blob []byte
		for _, f := range [][]byte{[]byte("ecdsa-sha2-nistp256"), []byte("nistp256"), pt} {
			blob = binary.BigEndian.AppendUint32(blob, uint32(len(f)))
			blob = append(blob, f...)
		}
		fp := sha256.Sum256(blob)
		p.TLSA = append(p.TLSA, d)
		p.AgentKey = append(p.AgentKey, d)
		p.SSHFP = append(p.SSHFP, hex.EncodeToString(fp[:]))
		p.OpenPGP = append(p.OpenPGP, pt)
	}
	return p
}

func headRecords(t *testing.T, c bundleCase) [][][]byte {
	t.Helper()
	var rr [][]byte
	for _, h := range *c.HeadHex {
		b, _ := hex.DecodeString(h)
		rr = append(rr, b)
	}
	return [][][]byte{rr}
}

func pagesOf(t *testing.T, c bundleCase) []*kel.Page {
	t.Helper()
	var out []*kel.Page
	for _, raw := range c.Pages {
		p, err := kel.ParsePage(raw)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func lastSPKI(pages []*kel.Page) []byte {
	p := pages[len(pages)-1]
	return p.Events[len(p.Events)-1].SPKI
}

func withVerifySeams(t *testing.T, c bundleCase, key *kel.LogKey, d *fakeDNS) {
	t.Helper()
	od := observedDir
	obs := t.TempDir()
	observedDir = func() string { return obs }
	t.Cleanup(func() { observedDir = od })
	sc, sd, sk := verifyClock, verifyDNS, verifyServedLogKeys
	t.Cleanup(func() { verifyClock, verifyDNS, verifyServedLogKeys = sc, sd, sk })
	now := time.UnixMilli(c.NowMs)
	verifyClock = func() time.Time { return now }
	verifyDNS = func(string, time.Time) kelDNS { return d }
	verifyServedLogKeys = func(context.Context, time.Time) (*kel.LogKey, func(string) bool) {
		if !c.UseLogKey {
			return nil, nil
		}
		return key, func(string) bool { return false }
	}
}

func TestVerifyPassesAHistoryThatReachesThePublishedHeadAndItsPins(t *testing.T) {
	c, key := bundleVectorCase(t, "committed-two-pages-match")
	pages := pagesOf(t, c)
	d := &fakeDNS{name: c.Subject.FQDN + ".", servers: []string{"[2001:db8::53]:53", "192.0.2.53:53"},
		head: &trustverify.KelHead{Records: headRecords(t, c), TTL: 5 * time.Minute}}
	d.pins = []*trustverify.ServedPins{pinsOf(t, lastSPKI(pages)), pinsOf(t, lastSPKI(pages))}
	withVerifySeams(t, c, key, d)
	rep := verifyHistory(context.Background(), pages, c.Subject.Address, "")
	if !rep.Verified || !rep.Signed || rep.FullyProven || rep.LogKeySource != "served" {
		t.Fatalf("under a log key the log serves itself, the history is never fully proven: %+v", rep)
	}
	d.ledger = []client.LedgerKey{{Origin: key.Name, PublicKey: base64.StdEncoding.EncodeToString(key.Public)}}
	rep = verifyHistory(context.Background(), pages, c.Subject.Address, "")
	if !rep.Verified || rep.Head != "MATCH" || !rep.Signed || !rep.FullyProven || !rep.KeyAuthorised ||
		rep.LogKeySource != "dnssec" {
		t.Fatalf("a matching history under the DNSSEC-anchored log key verifies: %+v", rep)
	}
	if rep.AddressFrom != "caller" || len(rep.Pins) != 2 || rep.KeyChain != "committed" {
		t.Fatalf("%+v", rep)
	}
	// the nameservers serving another key fail it, on the one that does
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	d.pins[1] = pinsOf(t, der)
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Verified || len(rep.PinProblems) == 0 ||
		!strings.Contains(strings.Join(rep.PinProblems, ";"), "192.0.2.53:53") {
		t.Fatalf("a served key that is not the head's fails: %+v", rep)
	}
	// the old key still served beside the new one, with no overlap in the head, fails too
	var all []kel.BundleEvent
	for _, p := range pages {
		all = append(all, p.Events...)
	}
	prev := all[len(all)-2].SPKI
	d.pins[1] = pinsOf(t, lastSPKI(pages), prev)
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Verified {
		t.Fatal("two keys served against a head with no p= is a mismatch on the direct path")
	}
}

// A service that has turned OPENPGPKEY off serves it DNSSEC-absent. The check still refuses (it
// needs the key in all four kinds), and the refusal says that in its own words, on the screen.
func TestVerifyNamesAKindTheServiceTurnedOff(t *testing.T) {
	c, key := bundleVectorCase(t, "committed-two-pages-match")
	pages := pagesOf(t, c)
	d := &fakeDNS{name: c.Subject.FQDN + ".", servers: []string{"192.0.2.53:53"},
		head: &trustverify.KelHead{Records: headRecords(t, c), TTL: 5 * time.Minute}}
	off := pinsOf(t, lastSPKI(pages))
	off.OpenPGP, off.Absent = nil, []string{"OPENPGPKEY"}
	d.pins = []*trustverify.ServedPins{off}
	withVerifySeams(t, c, key, d)
	rep := verifyHistory(context.Background(), pages, c.Subject.Address, "")
	if rep.Verified || !strings.Contains(strings.Join(rep.PinProblems, ";"), "no OPENPGPKEY record is published at all") {
		t.Fatalf("a kind turned off is named as absent: %+v", rep)
	}
	out := []byte(captureVerdict(t, rep))
	if !strings.Contains(string(out), "problem    ns1.example 192.0.2.53:53: key ") ||
		!strings.Contains(string(out), "turned OPENPGPKEY off") ||
		!strings.Contains(string(out), "serves no key in all four kinds, its head names") {
		t.Fatalf("the refusal's reasons are printed, not only its summary:\n%s", out)
	}
}

func TestVerifyBindsToTheCallersSubjectNeverTheFile(t *testing.T) {
	c, key := bundleVectorCase(t, "committed-two-pages-match")
	pages := pagesOf(t, c)
	d := &fakeDNS{name: c.Subject.FQDN, head: &trustverify.KelHead{Records: headRecords(t, c)},
		addrOf: map[string]netip.Addr{"friendly.example": netip.MustParseAddr("2001:db8::b2")}}
	withVerifySeams(t, c, key, d)
	if rep := verifyHistory(context.Background(), pages, "2001:db8::b2", ""); rep.Verified || rep.Failure != "SUBJECT_MISMATCH" {
		t.Fatalf("a history of another address fails: %+v", rep)
	}
	if rep := verifyHistory(context.Background(), pages, "friendly.example", ""); rep.Verified ||
		!strings.Contains(rep.Reason, "is not the identity's name") {
		t.Fatalf("a name that only points at an address is not that identity: %+v", rep)
	}
	d.addrOf["attacker.example"] = netip.MustParseAddr(c.Subject.Address) // pointed at the victim's /128
	if rep := verifyHistory(context.Background(), pages, "attacker.example", ""); rep.Verified ||
		!strings.Contains(rep.Reason, "is not the identity's name") {
		t.Fatalf("--for a name the identity does not prove for itself is refused: %+v", rep)
	}
	d.addrOf[c.Subject.FQDN] = netip.MustParseAddr(c.Subject.Address)
	if rep := verifyHistory(context.Background(), pages, strings.ToUpper(c.Subject.FQDN)+".", ""); rep.Failure == "SUBJECT_MISMATCH" ||
		strings.Contains(rep.Reason, "is not the identity's name") {
		t.Fatalf("the identity's own name, in any case or with its dot, binds it: %+v", rep)
	}
	if rep := verifyHistory(context.Background(), pages, "unproven.example", ""); rep.Verified ||
		!strings.Contains(rep.Reason, "no proven address") {
		t.Fatalf("a name with no proven address fails: %+v", rep)
	}
	d.name = "another.agents.example."
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Verified || rep.Failure != "SUBJECT_MISMATCH" {
		t.Fatalf("the DNSSEC name decides, never the file's: %+v", rep)
	}
	d.nameErr = errors.New("PTR not signed")
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Verified || !strings.Contains(rep.Reason, "not proven") {
		t.Fatalf("an unproven name fails: %+v", rep)
	}
	d.nameErr, d.name, d.head = nil, c.Subject.FQDN, nil
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Verified || !strings.Contains(rep.Reason, "neither published") {
		t.Fatalf("a head neither published nor proven absent fails: %+v", rep)
	}
}

func TestVerifyALaggingHeadSaysWhenToLookAgain(t *testing.T) {
	c, key := bundleVectorCase(t, "committed-one-ahead-in-window")
	pages := pagesOf(t, c)
	d := &fakeDNS{name: c.Subject.FQDN, servers: []string{"ns:53"},
		head: &trustverify.KelHead{Records: headRecords(t, c), TTL: 5 * time.Minute}}
	// DNS is one edit behind the history, so it serves the previous event's key
	var evs []kel.BundleEvent
	for _, p := range pages {
		evs = append(evs, p.Events...)
	}
	d.pins = []*trustverify.ServedPins{pinsOf(t, evs[len(evs)-2].SPKI)}
	withVerifySeams(t, c, key, d)
	rep := verifyHistory(context.Background(), pages, "", "")
	if rep.Head != "LAGGING" || rep.LagUntil == "" {
		t.Fatalf("a head one behind inside the window lags: %+v", rep)
	}
}

func TestVerifyAHostedIdentityHasOneKeyAcrossItsRecords(t *testing.T) {
	c, key := bundleVectorCase(t, "hosted-against-absence")
	pages := pagesOf(t, c)
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	d1, _ := x509.MarshalPKIXPublicKey(&k1.PublicKey)
	d2, _ := x509.MarshalPKIXPublicKey(&k2.PublicKey)
	d := &fakeDNS{name: c.Subject.FQDN, servers: []string{"ns:53"}, head: &trustverify.KelHead{Absent: true},
		pins: []*trustverify.ServedPins{pinsOf(t, d1)}}
	withVerifySeams(t, c, key, d)
	if rep := verifyHistory(context.Background(), pages, "", ""); !rep.Verified || rep.KeyChain != "hosted" {
		t.Fatalf("a hosted identity whose four records name one key verifies: %+v", rep)
	}
	d.pins = []*trustverify.ServedPins{pinsOf(t, d1, d2)}
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Verified {
		t.Fatal("a hosted identity serving two keys fails")
	}
	half := pinsOf(t, d1)
	half.SSHFP = nil
	d.pins = []*trustverify.ServedPins{half}
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Verified {
		t.Fatal("a key served by some records and not others fails")
	}
	// and a hosted claim against a published head is refused by the bundle check
	cm, _ := bundleVectorCase(t, "committed-two-pages-match")
	d.head = &trustverify.KelHead{Records: headRecords(t, cm)}
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Verified || rep.Failure != "HEAD_REJECTED" {
		t.Fatalf("a hosted claim against a published head fails: %+v", rep)
	}
}

func TestVerifyReadsEveryExportForm(t *testing.T) {
	c, _ := bundleVectorCase(t, "committed-two-pages-match")
	dir := t.TempDir()
	quoted, _ := json.Marshal(c.Pages)
	objs := "[" + strings.Join(c.Pages, ",") + "]"
	for name, body := range map[string]string{
		"lines":   strings.Join(c.Pages, "\n") + "\n",
		"crlf":    strings.Join(c.Pages, "\r\n"),
		"strings": string(quoted),
		"objects": objs,
	} {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(body), 0o600)
		pages, err := readBundleFile(p)
		if err != nil || len(pages) != len(c.Pages) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, body := range map[string]string{"empty": "  \n", "junk": "[1,", "page": `{"format":"other"}`} {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(body), 0o600)
		if _, err := readBundleFile(p); err == nil {
			t.Fatalf("%s: read", name)
		}
	}
	if _, err := readBundleFile(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("a missing file is an error")
	}
}

func TestTheFirstObservationIsKeptSoTheLagWindowCloses(t *testing.T) {
	c, key := bundleVectorCase(t, "committed-one-ahead-in-window")
	pages := pagesOf(t, c)
	d := &fakeDNS{name: c.Subject.FQDN, servers: []string{"ns:53"},
		head: &trustverify.KelHead{Records: headRecords(t, c), TTL: 5 * time.Minute}}
	var evs []kel.BundleEvent
	for _, p := range pages {
		evs = append(evs, p.Events...)
	}
	d.pins = []*trustverify.ServedPins{pinsOf(t, evs[len(evs)-2].SPKI)}
	withVerifySeams(t, c, key, d)
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Head != "LAGGING" {
		t.Fatalf("first sight lags: %+v", rep)
	}
	// an hour later the same head is still one behind: the window, from the first sight, is over
	later := time.UnixMilli(c.NowMs).Add(time.Hour)
	verifyClock = func() time.Time { return later }
	rep := verifyHistory(context.Background(), pages, "", "")
	if rep.Verified || rep.Head != "STALE" {
		t.Fatalf("a lag that outlives its window is stale on a later run: %+v", rep)
	}
	// and the refusal says when a key event made just now would be published
	if !strings.Contains(rep.Reason, "first saw the published head at "+time.UnixMilli(c.NowMs).UTC().Format(time.RFC3339)) ||
		!strings.Contains(rep.Reason, "look again after "+later.Add(verifyWindowForTest(d)).UTC().Format(time.RFC3339)) {
		t.Fatalf("a stale refusal names the first sight and when to look again: %q", rep.Reason)
	}
	if rep.SightNotKept {
		t.Fatal("a stored first sight is kept")
	}
	// a store that cannot be written makes it one-shot, never wrong, and says so
	observedDir = func() string { return "" }
	rep = verifyHistory(context.Background(), pages, "", "")
	if rep.Head != "LAGGING" || !rep.SightNotKept {
		t.Fatalf("with no store, each run is a first sight, and the report says so: %+v", rep)
	}
	out := captureVerdict(t, rep)
	if !strings.Contains(out, "could not keep its first sight") {
		t.Fatalf("the screen says the window cannot close here:\n%s", out)
	}
}

// The zone's operator chooses the TTL. A signed TTL of thirty days is read as the verifier's own
// ceiling, so a history one event ahead is stale two hours after the first sight, not a month.
func TestALongSignedTTLDoesNotHoldTheLagWindowOpen(t *testing.T) {
	c, key := bundleVectorCase(t, "committed-one-ahead-in-window")
	pages := pagesOf(t, c)
	d := &fakeDNS{name: c.Subject.FQDN, servers: []string{"ns:53"},
		head: &trustverify.KelHead{Records: headRecords(t, c), TTL: 30 * 24 * time.Hour}}
	var evs []kel.BundleEvent
	for _, p := range pages {
		evs = append(evs, p.Events...)
	}
	d.pins = []*trustverify.ServedPins{pinsOf(t, evs[len(evs)-2].SPKI)}
	withVerifySeams(t, c, key, d)
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Head != "LAGGING" {
		t.Fatalf("first sight lags: %+v", rep)
	}
	verifyClock = func() time.Time { return time.UnixMilli(c.NowMs).Add(2 * time.Hour) }
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Verified || rep.Head != "STALE" {
		t.Fatalf("a thirty-day TTL is read as the one-hour ceiling: %+v", rep)
	}
	if got := kelLagWindow(30 * 24 * time.Hour); got != kelReconcilePeriod+kelTTLCeiling+kelTransferSlack {
		t.Fatalf("window %v", got)
	}
	if got := kelLagWindow(5 * time.Minute); got != kelReconcilePeriod+5*time.Minute+kelTransferSlack {
		t.Fatalf("a TTL under the ceiling is used as signed: %v", got)
	}
}

func TestVerifySkipsANameserverItCannotReachButNotOneThatLies(t *testing.T) {
	c, key := bundleVectorCase(t, "committed-two-pages-match")
	pages := pagesOf(t, c)
	d := &fakeDNS{name: c.Subject.FQDN, servers: []string{"[2001:db8::53]:53", "192.0.2.53:53"},
		head: &trustverify.KelHead{Records: headRecords(t, c)}}
	d.pins = []*trustverify.ServedPins{pinsOf(t, lastSPKI(pages)), pinsOf(t, lastSPKI(pages))}
	withVerifySeams(t, c, key, d)
	noRoute := fmt.Errorf("dnssec: fetching TLSA x: %w", &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded})
	d.groups = []trustverify.Nameserver{{Name: "ns1.example", Addrs: d.servers}}
	d.pinErr = map[string]error{"[2001:db8::53]:53": noRoute}
	rep := verifyHistory(context.Background(), pages, "", "")
	if !rep.Verified || len(rep.Unreachable) != 1 || len(rep.Pins) != 1 {
		t.Fatalf("an unreachable address is said, and the nameserver's next address read: %+v", rep)
	}
	d.pinErr["192.0.2.53:53"] = noRoute
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Verified ||
		!strings.Contains(rep.Reason, "ns1.example could be reached") {
		t.Fatalf("a nameserver none of whose addresses answers proves nothing: %+v", rep)
	}
	d.groups = nil // each address its own nameserver: the lying one is read
	d.pinErr = map[string]error{"192.0.2.53:53": errors.New("dnssec: no RRSIG over TLSA verified")}
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Verified || !strings.Contains(rep.Reason, "what DNSSEC does not prove") {
		t.Fatalf("a nameserver whose answer does not validate fails the check: %+v", rep)
	}
}

func TestEachNameserverIsJudgedByItsOwnHead(t *testing.T) {
	c, key := bundleVectorCase(t, "committed-one-ahead-in-window")
	pages := pagesOf(t, c)
	var evs []kel.BundleEvent
	for _, p := range pages {
		evs = append(evs, p.Events...)
	}
	behind := &trustverify.KelHead{Records: headRecords(t, c)}
	d := &fakeDNS{name: c.Subject.FQDN, servers: []string{"a:53", "b:53"}, head: behind,
		pins: []*trustverify.ServedPins{pinsOf(t, evs[len(evs)-2].SPKI), pinsOf(t, evs[len(evs)-1].SPKI)}}
	withVerifySeams(t, c, key, d)
	// b serves the newer key: against the head it serves (one behind) that is a mismatch
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Verified {
		t.Fatal("pins one edit ahead of the same server's head are a mismatch on the direct path")
	}
	// a nameserver whose own head is not a state of this history fails it
	cm, _ := bundleVectorCase(t, "head-names-another-chain")
	d.headOn = map[string]*trustverify.KelHead{"b:53": {Records: headRecords(t, cm)}}
	if rep := verifyHistory(context.Background(), pages, "", ""); rep.Verified ||
		!strings.Contains(strings.Join(rep.PinProblems, ";"), "not a state of this history") {
		t.Fatalf("a foreign head on one nameserver fails: %+v", rep)
	}
}

func TestATornObservationIsReplacedNotTrusted(t *testing.T) {
	od := observedDir
	dir := t.TempDir()
	observedDir = func() string { return dir }
	t.Cleanup(func() { observedDir = od })
	now := time.Unix(1761400000, 0)
	first := firstObservation("a.example.", nil, now)
	ents, _ := os.ReadDir(dir)
	if !first.Equal(now) || len(ents) != 1 {
		t.Fatalf("the first sight is kept: %v %d", first, len(ents))
	}
	if got := firstObservation("a.example", nil, now.Add(time.Hour)); !got.Equal(now) {
		t.Fatal("a later run reads the first sight, whatever the trailing dot")
	}
	_ = os.WriteFile(filepath.Join(dir, ents[0].Name()), nil, 0o600) // torn by a crash
	later := now.Add(2 * time.Hour)
	if got := firstObservation("a.example.", nil, later); !got.Equal(later) {
		t.Fatal("a torn record proves nothing: this sight is the first")
	}
	if got := firstObservation("a.example.", nil, later.Add(time.Hour)); !got.Equal(later) {
		t.Fatal("and is kept from then on")
	}
}

// verifyWindowForTest is the lag window verifyHistory builds for this fake's head.
func verifyWindowForTest(d *fakeDNS) time.Duration {
	return kelLagWindow(d.head.TTL)
}

// A nameserver whose own head reads STALE says when a key event that new would be published, as
// the recursive head's refusal does.
func TestANameserversStaleHeadSaysWhenToLookAgain(t *testing.T) {
	c, key := bundleVectorCase(t, "committed-one-ahead-in-window")
	pages := pagesOf(t, c)
	d := &fakeDNS{name: c.Subject.FQDN, servers: []string{"ns:53"},
		head: &trustverify.KelHead{Records: headRecords(t, c), TTL: 5 * time.Minute}}
	withVerifySeams(t, c, key, d)
	var links []kel.Link
	for _, p := range pages {
		for i := range p.Events {
			links = append(links, p.Events[i].Link())
		}
	}
	res := &kel.BundleResult{}
	t0 := time.UnixMilli(c.NowMs)
	if _, why := servedState(res, links, c.Subject.FQDN, d.head, t0); why != "" {
		t.Fatalf("first sight is inside the window: %s", why)
	}
	later := t0.Add(2 * time.Hour)
	_, why := servedState(res, links, c.Subject.FQDN, d.head, later)
	if !strings.Contains(why, "STALE") || !strings.Contains(why, "first saw the published head at "+t0.UTC().Format(time.RFC3339)) ||
		!strings.Contains(why, "look again after "+later.Add(kelLagWindow(5*time.Minute)).UTC().Format(time.RFC3339)) {
		t.Fatalf("a nameserver's stale head names the first sight and when to look again: %q", why)
	}
	if staleHint(kel.VerdictLagging, t0, later, time.Minute) != "" {
		t.Fatal("only STALE carries the hint")
	}
}

// captureVerdict is what renderHistoryVerdict prints for rep.
func captureVerdict(t *testing.T, rep *historyVerdict) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	renderHistoryVerdict(rep)
	os.Stdout = stdout
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}
