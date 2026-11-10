// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package resolverprofile

import (
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The macOS dns53 plan points every service at the resolver, installs the
// search domain, and on `--off` puts each service's previous DNS servers and
// search domains back exactly. These tests run the rendered
// shell for real, under /bin/sh, against a fake networksetup that keeps each
// service's settings in files, so the round trip is checked on any POSIX host
// without touching the machine's own DNS.

const fakeNetworksetup = `#!/bin/sh
d="$FAKE_NS_DIR"
key() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
known() { sed 's/^\*//' "$d/services" | grep -Fqx -- "$1"; }
cmd="$1"; shift
printf '%s' "$cmd" >> "$d/log"; for a in "$@"; do printf ' [%s]' "$a" >> "$d/log"; done; echo >> "$d/log"
case "$cmd" in
-listallnetworkservices)
	echo "An asterisk (*) denotes that a network service is disabled."
	cat "$d/services" ;;
-getsearchdomains|-getdnsservers)
	known "$1" || { echo "$1 is not a recognized network service."; exit 4; }
	if [ "$cmd" = -getdnsservers ]; then f="$d/$(key "$1").dns"; what="DNS Servers"; else f="$d/$(key "$1").search"; what="Search Domains"; fi
	if [ -s "$f" ]; then cat "$f"; else echo "There aren't any $what set on $1."; fi ;;
-setsearchdomains|-setdnsservers)
	s="$1"; shift
	known "$s" || { echo "$s is not a recognized network service."; exit 4; }
	if [ "$cmd" = -setdnsservers ]; then f="$d/$(key "$s").dns"; fail="$FAKE_NS_FAIL_DNS"; else f="$d/$(key "$s").search"; fail="$FAKE_NS_FAIL"; fi
	if [ -n "$fail" ] && [ "$s" = "$fail" ]; then echo "Error: could not change $s" >&2; exit 1; fi
	: > "$f"
	[ "$*" = "Empty" ] || for x in "$@"; do echo "$x" >> "$f"; done ;;
*) echo "unexpected: $cmd" >&2; exit 2 ;;
esac
`

type fakeMac struct {
	t       *testing.T
	dir     string
	path    string
	fail    string // refuse every search-domain change on this service
	failDNS string // refuse every DNS-server change on this service
}

// newFakeMac installs the fake networksetup with the given services (a leading
// "*" marks one disabled, as networksetup prints it) and their search lists.
func newFakeMac(t *testing.T, services []string, lists, servers map[string][]string) *fakeMac {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("runs the rendered POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "networksetup"), []byte(fakeNetworksetup), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "services"), []byte(strings.Join(services, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fakeMac{t: t, dir: dir, path: bin + string(os.PathListSeparator) + os.Getenv("PATH")}
	for s, l := range lists {
		f.set(s, ".search", l)
	}
	for s, l := range servers {
		f.set(s, ".dns", l)
	}
	orig := darwinNetState
	darwinNetState = filepath.Join(dir, "state dir", "whisper-resolver.netstate")
	if err := os.MkdirAll(filepath.Dir(darwinNetState), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { darwinNetState = orig })
	return f
}

func (f *fakeMac) keyFile(service, ext string) string {
	return filepath.Join(f.dir, hex.EncodeToString([]byte(service))+ext)
}

func (f *fakeMac) set(service, ext string, l []string) {
	content := ""
	if len(l) > 0 {
		content = strings.Join(l, "\n") + "\n"
	}
	if err := os.WriteFile(f.keyFile(service, ext), []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeMac) get(service, ext string) []string {
	b, err := os.ReadFile(f.keyFile(service, ext))
	if err != nil && !os.IsNotExist(err) {
		f.t.Fatal(err)
	}
	return strings.Fields(string(b))
}

func (f *fakeMac) list(service string) []string    { return f.get(service, ".search") }
func (f *fakeMac) servers(service string) []string { return f.get(service, ".dns") }

// expect checks every service's search domains and DNS servers.
func (f *fakeMac) expect(when string, lists, servers map[string][]string) {
	f.t.Helper()
	for _, svc := range macServiceNames() {
		if got := f.list(svc); !sameList(got, lists[svc]) {
			f.t.Fatalf("%s: %s search domains = %v, want %v", when, svc, got, lists[svc])
		}
		if got := f.servers(svc); !sameList(got, servers[svc]) {
			f.t.Fatalf("%s: %s DNS servers = %v, want %v", when, svc, got, servers[svc])
		}
	}
}

func (f *fakeMac) log() string {
	b, _ := os.ReadFile(filepath.Join(f.dir, "log"))
	return string(b)
}

func (f *fakeMac) clearLog() { _ = os.Remove(filepath.Join(f.dir, "log")) }

func (f *fakeMac) env() []string {
	env := append(os.Environ(), "PATH="+f.path, "FAKE_NS_DIR="+f.dir)
	if f.fail != "" {
		env = append(env, "FAKE_NS_FAIL="+f.fail)
	}
	if f.failDNS != "" {
		env = append(env, "FAKE_NS_FAIL_DNS="+f.failDNS)
	}
	return env
}

// run executes plan steps the way the macOS applier does: guards read against
// the state before the first step, then the steps in order, stopping at the
// first failure.
func (f *fakeMac) run(steps []Step) error {
	f.t.Helper()
	runnable := steps[:0:0]
	for _, s := range steps {
		if s.IfPresent != "" {
			if _, err := os.Stat(s.IfPresent); err != nil {
				continue
			}
		}
		if s.IfAbsent != "" {
			if _, err := os.Stat(s.IfAbsent); err == nil {
				continue
			}
		}
		runnable = append(runnable, s)
	}
	for _, s := range runnable {
		if s.Shell == "" {
			f.t.Fatalf("the macOS dns53 plan should be shell steps only, got %s", s.String())
		}
		cmd := exec.Command("sh", "-c", s.Shell)
		cmd.Env = f.env()
		if out, err := cmd.CombinedOutput(); err != nil {
			return &stepErr{step: s.Shell, out: string(out), err: err}
		}
	}
	return nil
}

// apply mirrors darwinApplier.Apply for a failed step: everything is put back,
// best effort. It returns the apply error and the rollback's own result.
func (f *fakeMac) apply(r Rendered) (applyErr, rollbackErr error) {
	if err := f.run(r.Apply); err != nil {
		return err, f.run(r.Revert)
	}
	return nil, nil
}

// script runs a whole printed block (`whisper resolver --print`) under bash,
// which adds `set -euo pipefail` on top of what the applier sees.
func (f *fakeMac) script(body string) error {
	f.t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		f.t.Skip("no bash")
	}
	cmd := exec.Command("bash", "-c", body)
	cmd.Env = f.env()
	if out, err := cmd.CombinedOutput(); err != nil {
		return &stepErr{step: "script", out: string(out), err: err}
	}
	return nil
}

type stepErr struct {
	step, out string
	err       error
}

func (e *stepErr) Error() string { return e.err.Error() + ": " + e.out + " (" + e.step + ")" }

func macDNS53(search ...string) Rendered {
	return Profile{Mode: ModeDNS53, OS: "darwin", ResolverIPs: []string{wbIP}, SearchDomains: search}.Render(Host{})
}

func sameList(a, b []string) bool { return strings.Join(a, " ") == strings.Join(b, " ") }

var macServices = []string{"Wi-Fi", "Ethernet", "*Thunderbolt Bridge", "USB 10/100/1000 LAN"}

func macServiceNames() []string {
	out := make([]string, 0, len(macServices))
	for _, s := range macServices {
		out = append(out, strings.TrimPrefix(s, "*"))
	}
	return out
}

func macPrior() map[string][]string {
	return map[string][]string{
		"Wi-Fi":              {"corp.example"},
		"Thunderbolt Bridge": {"a.example", "b.example"},
	}
}

// macPriorServers: two services carry servers an admin set by hand, two are
// automatic (no servers set).
func macPriorServers() map[string][]string {
	return map[string][]string{
		"Wi-Fi":    {"192.0.2.53", "2001:db8::53"},
		"Ethernet": {"198.51.100.1"},
	}
}

func newMac(t *testing.T) *fakeMac { return newFakeMac(t, macServices, macPrior(), macPriorServers()) }

func allOurs(v ...string) map[string][]string {
	m := map[string][]string{}
	for _, s := range macServiceNames() {
		m[s] = v
	}
	return m
}

func TestDarwinDNS53PlanInstallsTheSearchDomain(t *testing.T) {
	r := macDNS53(wbSuffix)
	if len(r.Apply) != 3 {
		t.Fatalf("want capture, dns servers, search domains; got %d steps: %v", len(r.Apply), r.Apply)
	}
	if r.Apply[0].IfAbsent != darwinNetState || !strings.Contains(r.Apply[0].Shell, "-getsearchdomains") || !strings.Contains(r.Apply[0].Shell, "-getdnsservers") {
		t.Fatalf("the first step must record the current servers and lists, and only when no record exists: %+v", r.Apply[0])
	}
	if !strings.Contains(r.Apply[1].Shell, `networksetup -setdnsservers "$s" `+wbIP+" || exit 1; done") {
		t.Fatalf("the dns servers step changed: %q", r.Apply[1].Shell)
	}
	if !strings.Contains(r.Apply[2].Shell, "networksetup -setsearchdomains") || !strings.Contains(r.Apply[2].Shell, " "+wbSuffix+"; do") {
		t.Fatalf("the search step must set our suffix per service: %q", r.Apply[2].Shell)
	}
	if len(r.Revert) != 2 {
		t.Fatalf("want the exact restore and the unrecorded fallback: %v", r.Revert)
	}
	if rs := r.Revert[0]; rs.IfPresent != darwinNetState || !strings.Contains(rs.Shell, `-setdnsservers "$s" $d`) || !strings.Contains(rs.Shell, `-setsearchdomains "$s" $q`) {
		t.Fatalf("the revert must restore the recorded servers and lists, guarded on the record: %+v", rs)
	}
	if fb := r.Revert[1]; fb.IfAbsent != darwinNetState || !strings.Contains(fb.Shell, "= "+wbIP+" ]") {
		t.Fatalf("with no record, only services still set to exactly ours may be cleared: %+v", fb)
	}
	for _, st := range r.Revert {
		if strings.Contains(st.Shell, "-setdnsservers") && st.IfPresent == "" && st.IfAbsent == "" {
			t.Fatalf("an unguarded server reset would wipe an admin's servers: %q", st.Shell)
		}
	}
	for _, s := range append(append([]Step{}, r.Apply...), r.Revert...) {
		if strings.Contains(s.Shell, "listallnetworkservices") && !strings.Contains(s.Shell, `sed 's/^\*//'`) {
			t.Fatalf("a disabled service's \"*\" marker must be stripped before networksetup sees the name: %q", s.Shell)
		}
	}
}

func TestDarwinDNS53WithoutSearchDomainStillRecordsTheServers(t *testing.T) {
	r := macDNS53()
	if len(r.Apply) != 2 || strings.Contains(r.Apply[1].Shell, "searchdomains") {
		t.Fatalf("no suffix: the record and the servers, no search step: %v", r.Apply)
	}
	if r.Revert[0].IfPresent != darwinNetState {
		t.Fatalf("the restore must ride every macOS revert: %v", r.Revert)
	}
}

func TestDarwinRevertRestoresTheRecordInEveryMode(t *testing.T) {
	for _, p := range []Profile{
		{Mode: ModeDoH, OS: "darwin", DohTemplate: "https://doh.whisper.online/dns-query"},
		{Mode: ModeDNS53, OS: "darwin"}, // no resolver address known any more
	} {
		r := p.Render(Host{})
		found := false
		for _, s := range r.Revert {
			if s.IfPresent == darwinNetState {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s revert must carry the guarded restore: %v", p.Mode, r.Revert)
		}
	}
}

func TestDarwinSearchDomainIsShellQuoted(t *testing.T) {
	r := macDNS53("odd'name.example")
	if !strings.Contains(r.Apply[2].Shell, `'odd'\''name.example'`) {
		t.Fatalf("a suffix must reach networksetup as one quoted word: %q", r.Apply[2].Shell)
	}
}

func TestDarwinRoundTripAcrossServices(t *testing.T) {
	f := newMac(t)
	r := macDNS53(wbSuffix)
	if err := f.run(r.Apply); err != nil {
		t.Fatalf("apply: %v", err)
	}
	f.expect("after apply", map[string][]string{
		"Wi-Fi":               {"corp.example", wbSuffix},
		"Ethernet":            {wbSuffix},
		"Thunderbolt Bridge":  {"a.example", "b.example", wbSuffix},
		"USB 10/100/1000 LAN": {wbSuffix},
	}, allOurs(wbIP))
	if strings.Contains(f.log(), "[*") {
		t.Fatalf("networksetup was handed a name with the disabled marker:\n%s", f.log())
	}

	if err := f.run(r.Revert); err != nil {
		t.Fatalf("revert: %v", err)
	}
	f.expect("after revert", macPrior(), macPriorServers())
	if _, err := os.Stat(darwinNetState); !os.IsNotExist(err) {
		t.Fatalf("the record must be gone after a restore: %v", err)
	}

	// A second --off is a clean no-op: it changes nothing at all.
	f.clearLog()
	if err := f.run(r.Revert); err != nil {
		t.Fatalf("second revert: %v", err)
	}
	if strings.Contains(f.log(), "-set") {
		t.Fatalf("a second --off must not change anything:\n%s", f.log())
	}
	f.expect("after a second revert", macPrior(), macPriorServers())
}

func TestDarwinEmptyPriorSettingsAreRestoredAsEmpty(t *testing.T) {
	f := newFakeMac(t, []string{"Wi-Fi"}, nil, nil)
	r := macDNS53(wbSuffix)
	if err := f.run(r.Apply); err != nil {
		t.Fatalf("apply: %v", err)
	}
	rec, err := os.ReadFile(darwinNetState)
	if err != nil || string(rec) != "Wi-Fi\tEmpty\tEmpty\n" {
		t.Fatalf("an empty setting must be recorded as Empty, got %q (%v)", rec, err)
	}
	if info, _ := os.Stat(darwinNetState); info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the record must be private to root, got %v", info.Mode())
	}
	f.clearLog()
	if err := f.run(r.Revert); err != nil {
		t.Fatalf("revert: %v", err)
	}
	for _, want := range []string{"-setsearchdomains [Wi-Fi] [Empty]", "-setdnsservers [Wi-Fi] [Empty]"} {
		if !strings.Contains(f.log(), want) {
			t.Fatalf("the restore must hand networksetup the literal Empty (%s):\n%s", want, f.log())
		}
	}
	if len(f.list("Wi-Fi")) != 0 || len(f.servers("Wi-Fi")) != 0 {
		t.Fatalf("Wi-Fi must be back to automatic: %v %v", f.list("Wi-Fi"), f.servers("Wi-Fi"))
	}
}

func TestDarwinNoSearchDomainStillRestoresTheServers(t *testing.T) {
	f := newMac(t)
	r := macDNS53()
	if err := f.run(r.Apply); err != nil {
		t.Fatalf("apply: %v", err)
	}
	f.expect("after apply", macPrior(), allOurs(wbIP))
	if err := f.run(r.Revert); err != nil {
		t.Fatalf("revert: %v", err)
	}
	f.expect("after revert", macPrior(), macPriorServers())
}

func TestDarwinReapplyKeepsTheOriginalRecord(t *testing.T) {
	f := newMac(t)
	r := macDNS53(wbSuffix)
	if err := f.run(r.Apply); err != nil {
		t.Fatalf("apply: %v", err)
	}
	first, _ := os.ReadFile(darwinNetState)
	// Applying again (or retrying after an interrupted run) must neither
	// duplicate our suffix nor overwrite the record with our own values.
	if err := f.run(r.Apply); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if again, _ := os.ReadFile(darwinNetState); string(again) != string(first) {
		t.Fatalf("the record changed on re-apply:\n%q\n%q", first, again)
	}
	if got := f.list("Wi-Fi"); !sameList(got, []string{"corp.example", wbSuffix}) {
		t.Fatalf("re-apply must not duplicate the suffix: %v", got)
	}
	if err := f.run(r.Revert); err != nil {
		t.Fatalf("revert: %v", err)
	}
	f.expect("after revert", macPrior(), macPriorServers())
}

func TestDarwinFailedSearchStepRollsBack(t *testing.T) {
	f := newMac(t)
	r := macDNS53(wbSuffix)
	f.fail = "Thunderbolt Bridge" // the third service: two are already changed when it fails
	applyErr, rollbackErr := f.apply(r)
	if applyErr == nil {
		t.Fatal("a refused setsearchdomains must fail the apply")
	}
	// The refusing service also refuses its restore, but every other service is
	// still put back, and the record stays for the next --off.
	if rollbackErr == nil {
		t.Fatal("a restore networksetup refused must be reported, not swallowed")
	}
	f.expect("after the rollback", macPrior(), macPriorServers())
	if _, err := os.Stat(darwinNetState); err != nil {
		t.Fatalf("an incomplete rollback must keep the record: %v", err)
	}
	f.fail = ""
	if err := f.run(r.Revert); err != nil {
		t.Fatalf("--off after the refusal clears: %v", err)
	}
	if _, err := os.Stat(darwinNetState); !os.IsNotExist(err) {
		t.Fatal("a completed restore leaves no record behind")
	}
}

func TestDarwinFailedServersStepRollsBackCleanly(t *testing.T) {
	f := newMac(t)
	// The servers step is refused on the second service, after the record is
	// written and the first service already points at us.
	if err := os.WriteFile(filepath.Join(f.dir, "bin", "networksetup.real"), []byte(fakeNetworksetup), 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := `#!/bin/sh
[ "$1" = -setdnsservers ] && [ "$2" = Ethernet ] && [ "$3" = ` + wbIP + ` ] && { echo refused >&2; exit 1; }
exec "$(dirname "$0")/networksetup.real" "$@"
`
	if err := os.WriteFile(filepath.Join(f.dir, "bin", "networksetup"), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	applyErr, rollbackErr := f.apply(macDNS53(wbSuffix))
	if applyErr == nil || rollbackErr != nil {
		t.Fatalf("want a failed apply and a clean rollback, got %v / %v", applyErr, rollbackErr)
	}
	f.expect("after the rollback", macPrior(), macPriorServers())
	if strings.Contains(f.log(), "-setdnsservers [USB 10/100/1000 LAN] ["+wbIP+"]") {
		t.Fatalf("the apply must stop at the refused service:\n%s", f.log())
	}
	if _, err := os.Stat(darwinNetState); !os.IsNotExist(err) {
		t.Fatal("a completed rollback leaves no record behind")
	}
}

func TestDarwinFailedRestoreKeepsTheRecord(t *testing.T) {
	f := newMac(t)
	r := macDNS53(wbSuffix)
	if err := f.run(r.Apply); err != nil {
		t.Fatalf("apply: %v", err)
	}
	f.failDNS = "Ethernet"
	if err := f.run(r.Revert); err == nil {
		t.Fatal("a refused restore must fail the revert")
	}
	if _, err := os.Stat(darwinNetState); err != nil {
		t.Fatalf("the record must survive a failed restore so the next --off can finish: %v", err)
	}
	if got := f.servers("Wi-Fi"); !sameList(got, macPriorServers()["Wi-Fi"]) {
		t.Fatalf("the other services are restored despite the refusal, got %v", got)
	}
	f.failDNS = ""
	if err := f.run(r.Revert); err != nil {
		t.Fatalf("retry: %v", err)
	}
	f.expect("after the retry", macPrior(), macPriorServers())
}

func TestDarwinRestoreSkipsAServiceSinceRemoved(t *testing.T) {
	f := newMac(t)
	r := macDNS53(wbSuffix)
	if err := f.run(r.Apply); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// The USB adapter is unplugged before --off.
	if err := os.WriteFile(filepath.Join(f.dir, "services"), []byte("Wi-Fi\nEthernet\n*Thunderbolt Bridge\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.run(r.Revert); err != nil {
		t.Fatalf("a vanished service must not block the restore: %v", err)
	}
	if got := f.servers("Ethernet"); !sameList(got, macPriorServers()["Ethernet"]) {
		t.Fatalf("Ethernet must still be restored, got %v", got)
	}
}

func TestDarwinOffWithoutARecordClearsOnlyOurServers(t *testing.T) {
	// A Mac switched before the record existed: two services point at us, one
	// carries an admin's own servers, one is automatic.
	f := newFakeMac(t, macServices, macPrior(), map[string][]string{
		"Wi-Fi":              {wbIP},
		"Ethernet":           {"198.51.100.1"},
		"Thunderbolt Bridge": {wbIP},
	})
	r := macDNS53(wbSuffix)
	if err := f.run(r.Revert); err != nil {
		t.Fatalf("revert: %v", err)
	}
	f.expect("after --off", macPrior(), map[string][]string{"Ethernet": {"198.51.100.1"}})
	f.clearLog()
	if err := f.run(r.Revert); err != nil {
		t.Fatalf("second revert: %v", err)
	}
	if strings.Contains(f.log(), "-set") {
		t.Fatalf("a second --off must change nothing:\n%s", f.log())
	}
}

func TestDarwinPrintedScriptsRoundTripUnderBash(t *testing.T) {
	f := newMac(t)
	r := macDNS53(wbSuffix)
	if err := f.script(r.ApplyScript()); err != nil {
		t.Fatalf("printed apply: %v", err)
	}
	if got := f.list("USB 10/100/1000 LAN"); !sameList(got, []string{wbSuffix}) {
		t.Fatalf("printed apply must set the suffix, got %v", got)
	}
	if err := f.script(r.RevertScript()); err != nil {
		t.Fatalf("printed revert: %v", err)
	}
	if err := f.script(r.RevertScript()); err != nil {
		t.Fatalf("printed revert, second run: %v", err)
	}
	f.expect("after the printed revert", macPrior(), macPriorServers())
}
