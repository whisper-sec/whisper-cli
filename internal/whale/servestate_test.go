// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// servestate_test.go pins the promise `funnel off` makes: an exposure is always findable,
// and a record that describes nothing is never read as an exposure that exists.

func liveState() ServeState {
	return ServeState{
		Scope: ScopeInternet, Target: "http://127.0.0.1:3000", Path: "/", Port: 443,
		Address: "2a04:2a01:1::5", FQDN: "db-01.acme.agents.whisper.online.",
		PID: os.Getpid(), Since: time.Now().Truncate(time.Second),
		IdentityHeaders: true,
	}
}

func TestServeStateRoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := liveState()
	if err := WriteServeState(dir, want); err != nil {
		t.Fatalf("WriteServeState: %v", err)
	}
	got, ok := ReadServeState(dir)
	if !ok {
		t.Fatal("a record written by this live process did not read back")
	}
	if got.Scope != want.Scope || got.Target != want.Target || got.Address != want.Address ||
		got.PID != want.PID || !got.Since.Equal(want.Since) {
		t.Errorf("round trip changed the record:\n got %+v\nwant %+v", got, want)
	}
	if got.URL() != "https://db-01.acme.agents.whisper.online./" {
		t.Errorf("URL() = %q", got.URL())
	}
}

func TestARecordIsNeverWorldReadable(t *testing.T) {
	dir := t.TempDir()
	if err := WriteServeState(dir, liveState()); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes do not apply")
	}
	fi, err := os.Stat(filepath.Join(dir, "whale", "serve.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the record is mode %v, want 0600", fi.Mode().Perm())
	}
}

// TestADeadHolderIsNotAnExposure: a stale file claiming an exposure that does not exist
// would teach an operator to ignore the file, which is how a real one gets missed.
func TestADeadHolderIsNotAnExposure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test reaps a real child process")
	}
	dir := t.TempDir()
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Skipf("could not run a throwaway process: %v", err)
	}
	dead := liveState()
	dead.PID = cmd.Process.Pid
	if err := WriteServeState(dir, dead); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadServeState(dir); ok {
		t.Fatal("a record whose holder is gone was read as a running exposure")
	}
	if raw, ok := ReadServeStateRaw(dir); !ok || raw.PID != dead.PID {
		t.Fatal("the raw read lost the record `off` needs in order to clean up")
	}
	if _, wasRunning, err := StopServeState(dir); err != nil || wasRunning {
		t.Fatalf("StopServeState on a dead holder: wasRunning=%v err=%v", wasRunning, err)
	}
	if _, ok := ReadServeStateRaw(dir); ok {
		t.Fatal("the stale record survived `off`")
	}
}

func TestOffIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		if _, running, err := StopServeState(dir); err != nil || running {
			t.Fatalf("call %d: running=%v err=%v; `off` with nothing running must simply succeed", i, running, err)
		}
	}
	if err := ClearServeState(dir); err != nil {
		t.Fatalf("ClearServeState on an empty dir: %v", err)
	}
}

// TestAnUnknownScopeIsNeverTheOpenOne: a hand-edited or corrupt file must not become a
// public funnel by accident.
func TestAnUnknownScopeIsNeverTheOpenOne(t *testing.T) {
	dir := t.TempDir()
	bad := liveState()
	bad.Scope = "everyone"
	if err := WriteServeState(dir, bad); err == nil {
		t.Fatal("a record with an unknown scope was written")
	}
	path := filepath.Join(dir, "whale", "serve.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"scope":"everyone","pid":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadServeState(dir); ok {
		t.Fatal("a record with an unknown scope was read as a running exposure")
	}
	if err := os.WriteFile(path, []byte(`not json at all`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadServeState(dir); ok {
		t.Fatal("a corrupt record was read as a running exposure")
	}
	if ScopeScopeUnknown().Valid() {
		t.Fatal("an empty scope validates")
	}
}

// ScopeScopeUnknown keeps the assertion above readable.
func ScopeScopeUnknown() ServeScope { return ServeScope("") }

func TestScopeVocabulary(t *testing.T) {
	if !ScopeFleet.Valid() || !ScopeInternet.Valid() {
		t.Fatal("a shipped scope does not validate")
	}
	if ScopeFleet.Public() {
		t.Fatal("the fleet scope reports itself as public")
	}
	if !ScopeInternet.Public() {
		t.Fatal("the internet scope does not report itself as public")
	}
	if ScopeFleet.Verb() != "serve" || ScopeInternet.Verb() != "funnel" {
		t.Fatalf("the verbs drifted: %q / %q", ScopeFleet.Verb(), ScopeInternet.Verb())
	}
}

func TestURLFallsBackToTheAddress(t *testing.T) {
	st := liveState()
	st.FQDN = ""
	if got := st.URL(); !strings.Contains(got, "[2a04:2a01:1::5]") {
		t.Errorf("URL() = %q, want the bracketed literal when there is no name", got)
	}
	st.Port = 8443
	if got := st.URL(); !strings.HasSuffix(got, ":8443/") {
		t.Errorf("URL() = %q, want a non-default port shown", got)
	}
}
