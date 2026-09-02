// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The marker has exactly one consumer (ReadBoundFile) and now exactly one Go producer,
// so the test that matters is the round trip: what we write must be what the reader
// reads back. Before this, two shell scripts wrote the format by hand and nothing
// checked either against the parser.
func TestWriteBoundFileRoundTripsThroughTheReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "bound")
	addr := netip.MustParseAddr("2a04:2a01:400:1:a1b2:c3d4:e5f6:0718")

	if err := WriteBoundFile(path, "register", addr, "laptop.a1b2c3d4e5f60718.whisper.online.", "ag_demo"); err != nil {
		t.Fatalf("write: %v", err)
	}
	id, ok := ReadBoundFile(path)
	if !ok {
		t.Fatal("the reader rejected the marker we just wrote: a bound host would read as unbound")
	}
	if id.Addr != addr {
		t.Errorf("address round-trip: got %v want %v", id.Addr, addr)
	}
	// The writer trims the trailing dot so the reader's TrimSuffix is not load-bearing.
	if want := "laptop.a1b2c3d4e5f60718.whisper.online"; id.Name != want {
		t.Errorf("name round-trip: got %q want %q", id.Name, want)
	}
	if id.Agent != "ag_demo" {
		t.Errorf("agent round-trip: got %q want %q", id.Agent, "ag_demo")
	}
}

// The marker names which /128 a host answers as. That is a reconnaissance gift even
// though it holds no key, so it is 0600 regardless of the caller's umask.
func TestWriteBoundFileIsOwnerOnlyWhateverTheUmask(t *testing.T) {
	old := syscallUmask(0)
	defer syscallUmask(old)

	path := filepath.Join(t.TempDir(), "bound")
	if err := WriteBoundFile(path, "identity", netip.MustParseAddr("2a04:2a01::1"), "h", "ag_x"); err != nil {
		t.Fatalf("write: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("marker mode is %04o, want 0600 - a world-readable marker leaks the host's identity", perm)
	}
}

// An unbound endpoint must LOOK unbound. Writing a marker with no address would make
// ReadBoundFile return ok=false anyway, but it would also overwrite a good marker with a
// useless one, so the writer refuses outright.
func TestWriteBoundFileRefusesAnEmptyAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bound")
	if err := WriteBoundFile(path, "identity", netip.Addr{}, "h", "ag_x"); err == nil {
		t.Fatal("wrote a marker with no address; an unbound host must not look bound")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the refused write still created the file")
	}
}

// Re-binding must not leave the tail of a longer previous marker behind (a truncate bug
// here would splice two identities together and the reader takes the LAST address line).
func TestWriteBoundFileTruncatesAPreviousLongerMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bound")
	long := netip.MustParseAddr("2a04:2a01:400:1:aaaa:bbbb:cccc:dddd")
	if err := WriteBoundFile(path, "register", long, "a-very-long-previous-name.whisper.online", "ag_previous_long"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	short := netip.MustParseAddr("2a04:2a01::2")
	if err := WriteBoundFile(path, "identity", short, "s", "ag_s"); err != nil {
		t.Fatalf("second write: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(b), "ag_previous_long") {
		t.Errorf("stale content survived the re-bind:\n%s", b)
	}
	id, ok := ReadBoundFile(path)
	if !ok || id.Addr != short {
		t.Errorf("after re-bind got %v (ok=%v), want %v", id.Addr, ok, short)
	}
}
