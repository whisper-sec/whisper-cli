// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// A daemon that cannot write the user's registry must still record its session.
//
// The installed connection service runs as root with an EMPTY capability bounding set, on
// purpose: a userspace egress needs none. A root process without CAP_DAC_OVERRIDE is an
// ordinary process where file permissions are concerned, so it cannot write into the
// installing user's 0700 ~/.config/whisper. Measured on a clean Ubuntu 24.04 guest, the
// write failed with EACCES on every start, and `whisper status` answered "not connected -
// run: whisper connect" about a daemon that was carrying real traffic out of the host /128.
func TestASessionIsRecordedEvenWhenTheUserRegistryIsRefused(t *testing.T) {
	// The refusal is a FILE standing where the registry directory would go, so MkdirAll
	// cannot create it. The first version of this fixture used a 0500 parent directory,
	// which is the real production cause (a root daemon without CAP_DAC_OVERRIDE meeting a
	// 0700 home) and is simply not a refusal on Windows: the DACL there ignores the Unix
	// mode, the write succeeded, the fallback never engaged, and the test failed on the one
	// platform whose file permissions work differently. A path that cannot be a directory is
	// refused identically everywhere, and it exercises the same branch.
	refused := filepath.Join(t.TempDir(), "refused")
	if err := os.MkdirAll(refused, 0o700); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(refused, "sessions"), []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	machine := filepath.Join(t.TempDir(), "run", "whisper", "sessions")

	prevUser, prevMachine := sessionsDirFn, machineSessionsDirFn
	sessionsDirFn = func() string { return filepath.Join(refused, "sessions") }
	machineSessionsDirFn = func() string { return machine }
	defer func() { sessionsDirFn, machineSessionsDirFn = prevUser, prevMachine }()

	sess := &egressSession{
		endpoint: "socks5h://127.0.0.1:34491",
		addr:     "2a04:2a01:0:beef:1111:2222:3333:4444",
		tier:     "wireguard",
		local:    stubLocalEndpoint{},
	}
	writeSessionRecord(sess)

	if sess.recordPath == "" {
		t.Fatal("the session went unrecorded, so every status surface would report the host down")
	}
	if got := filepath.Dir(sess.recordPath); got != machine {
		t.Fatalf("recorded in %q, want the host-scoped registry %q", got, machine)
	}
	if _, err := os.Stat(sess.recordPath); err != nil {
		t.Fatalf("the record it claims to have written is not there: %v", err)
	}

	// And it must be READABLE by the user who asks `whisper status` about their own machine:
	// root wrote it, a login reads it.
	fi, err := os.Stat(sess.recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o044 == 0 { // group+other read: on Windows a plain file reports 0666, so this holds there too
		t.Errorf("the host-scoped record is mode %v: unreadable by the user asking about "+
			"their own machine, which is the whole reason it exists", fi.Mode().Perm())
	}

	// Reading finds it, which is the half `whisper status` depends on.
	recs := readSessionRecords()
	if len(recs) != 1 || recs[0].Port != 34491 {
		t.Fatalf("readSessionRecords did not surface the host-scoped session: %+v", recs)
	}

	// Teardown removes the file it actually wrote, not a name it recomputed.
	clearSessionRecord(sess)
	if _, err := os.Stat(sess.recordPath); !os.IsNotExist(err) {
		t.Errorf("teardown left the record behind: %v", err)
	}
}

// The login's own registry stays first. A user's interactive `whisper connect` belongs to
// that login, and moving it host-wide would be a behaviour change nobody asked for.
func TestTheUsersOwnRegistryIsStillPreferred(t *testing.T) {
	user := filepath.Join(t.TempDir(), "user", "sessions")
	machine := filepath.Join(t.TempDir(), "run", "whisper", "sessions")

	prevUser, prevMachine := sessionsDirFn, machineSessionsDirFn
	sessionsDirFn = func() string { return user }
	machineSessionsDirFn = func() string { return machine }
	defer func() { sessionsDirFn, machineSessionsDirFn = prevUser, prevMachine }()

	sess := &egressSession{
		endpoint: "socks5h://127.0.0.1:1080",
		addr:     "2a04:2a01::a",
		local:    stubLocalEndpoint{},
	}
	writeSessionRecord(sess)
	if got := filepath.Dir(sess.recordPath); got != user {
		t.Fatalf("recorded in %q, want the login's own registry %q", got, user)
	}
	if _, err := os.Stat(machine); !os.IsNotExist(err) {
		t.Errorf("the host-scoped registry was created for a session that had no need of it")
	}
}

// Both registries are read, and a host with no machine registry at all is not an error.
func TestBothRegistriesAreRead(t *testing.T) {
	user := filepath.Join(t.TempDir(), "user", "sessions")
	machine := filepath.Join(t.TempDir(), "run", "whisper", "sessions")
	for _, d := range []string{user, machine} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(dir, addr string, port int) {
		b := []byte(`{"addr":"` + addr + `","endpoint":"socks5h://127.0.0.1:` +
			strconv.Itoa(port) + `","tier":"socks5","port":` + strconv.Itoa(port) + `,"pid":1}`)
		if err := os.WriteFile(filepath.Join(dir, flattenAddr(addr)+"-"+strconv.Itoa(port)+".json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(user, "2a04:2a01::a", 1080)
	write(machine, "2a04:2a01::b", 34491)

	prevUser, prevMachine := sessionsDirFn, machineSessionsDirFn
	sessionsDirFn = func() string { return user }
	machineSessionsDirFn = func() string { return machine }
	defer func() { sessionsDirFn, machineSessionsDirFn = prevUser, prevMachine }()

	if got := len(readSessionRecords()); got != 2 {
		t.Fatalf("read %d record(s), want both the login's and the host's", got)
	}

	machineSessionsDirFn = func() string { return "" } // a platform with nowhere host-scoped
	if got := len(readSessionRecords()); got != 1 {
		t.Fatalf("no host-scoped registry must read as no host session, got %d", got)
	}
}

// stubLocalEndpoint stands in for a running proxy/tunnel: writeSessionRecord registers only
// sessions this process OWNS, and ownership is exactly "local is not nil".
type stubLocalEndpoint struct{}

func (stubLocalEndpoint) Endpoint() string { return "" }
func (stubLocalEndpoint) Addr() string     { return "" }
func (stubLocalEndpoint) Stop()            {}
