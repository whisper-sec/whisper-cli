// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package idkey

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/kel"
)

func TestTheNextKeyIsKeptOnceAndNeverReminted(t *testing.T) {
	withTempIdentityDir(t)
	cur, err := LoadOrGenerate("2a04:2a01::a1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NextKey(cur); err == nil {
		t.Fatal("NextKey must never mint")
	}
	n1, err := EnsureNextKey(cur)
	if err != nil {
		t.Fatal(err)
	}
	n2, err := EnsureNextKey(cur)
	if err != nil || n2.Digest() != n1.Digest() {
		t.Fatal("a second EnsureNextKey must return the key already committed to, never a new one")
	}
	if got, err := NextKey(cur); err != nil || got.Digest() != n1.Digest() {
		t.Fatal("NextKey reads the stored next key")
	}
	if n1.Digest() == cur.Digest() {
		t.Fatal("the next key is a different key")
	}
	if c, _ := kel.Commit(n1.Digest()); n1.Commitment() != c {
		t.Fatal("Commitment is SHA-256 of the key digest's ASCII")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(nextPath(cur.Digest()))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("the next key is private to its owner: %v %v", fi.Mode(), err)
		}
	}
	// nothing half-written is left beside it
	ents, _ := os.ReadDir(kelDir())
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("a temporary file was left: %s", e.Name())
		}
	}
}

func TestAMoveIsFollowedFromEveryHandleAndTheLeafWaitsForServeNewAfter(t *testing.T) {
	withTempIdentityDir(t)
	cur, _ := LoadOrGenerate("2a04:2a01::a1")
	if err := Link("db-01", cur); err != nil {
		t.Fatal(err)
	}
	next, _ := EnsureNextKey(cur)
	if err := RecordMove(cur, next, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"2a04:2a01::a1", "db-01"} {
		kp, err := Load(h)
		if err != nil || kp.Digest() != next.Digest() {
			t.Fatalf("%s: the pin moved, so every handle proves the new key", h)
		}
		if kp.ServingKey().Digest() != cur.Digest() {
			t.Fatalf("%s: the old key serves until serve_new_after", h)
		}
	}
	if !Moved(cur) {
		t.Fatal("the move is recorded")
	}
	// the same move again is success; another move from the same key is refused
	if err := RecordMove(cur, next, time.Now()); err != nil {
		t.Fatalf("recording the same move twice is success: %v", err)
	}
	other, _ := GenerateKeypair()
	if err := RecordMove(cur, other, time.Now()); err == nil {
		t.Fatal("a key moves once")
	}
	// Link of the new pin under a handle that holds the old key is success, never ErrLinkedElsewhere
	if err := Link("db-01", next); err != nil {
		t.Fatalf("a handle holding a key whose moves lead to kp holds kp: %v", err)
	}
	if err := Link("db-01", other); !errors.Is(err, ErrLinkedElsewhere) {
		t.Fatal("an unrelated key is still refused")
	}
}

func TestTheLeafSwitchesOnceServeNewAfterPasses(t *testing.T) {
	withTempIdentityDir(t)
	cur, _ := LoadOrGenerate("h")
	next, _ := EnsureNextKey(cur)
	if err := RecordMove(cur, next, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	kp, _ := Load("h")
	if kp.ServingKey().Digest() != next.Digest() {
		t.Fatal("after serve_new_after the new key serves alone")
	}
	// two rotations: the walk reaches the last
	after, _ := EnsureNextKey(next)
	if err := RecordMove(next, after, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if kp, _ := Load("h"); kp.Digest() != after.Digest() {
		t.Fatal("the walk follows every recorded move")
	}
	if r := Refresh(cur); r.Digest() != after.Digest() {
		t.Fatal("Refresh of the first key reaches the pin")
	}
}

func TestTheReadOnlyReaderFollowsMovesWithoutOpeningANextKey(t *testing.T) {
	dir := withTempIdentityDir(t)
	cur, _ := LoadOrGenerate("h")
	next, _ := EnsureNextKey(cur)
	if _, err := EnsureNextKey(next); err != nil { // the key after next, which must stay unread
		t.Fatal(err)
	}
	if err := RecordMove(cur, next, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Make every next key unreadable: a reader that opened one would fail to load or fall back.
	for _, d := range []string{cur.Digest(), next.Digest()} {
		if err := os.WriteFile(filepath.Join(dir, "kel", d+".next.pem"), []byte("not a key"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kp, err := LoadFile(PathFor("h"))
	if err != nil || kp.Digest() != next.Digest() {
		t.Fatalf("the sudo reader follows the move to the stored pin: %v", err)
	}
}

func TestAMoveWhoseKeyIsMissingKeepsTheLastProvableKey(t *testing.T) {
	dir := withTempIdentityDir(t)
	cur, _ := LoadOrGenerate("h")
	next, _ := EnsureNextKey(cur)
	if err := RecordMove(cur, next, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "kel", next.Digest()+".pem")); err != nil {
		t.Fatal(err)
	}
	if kp, _ := Load("h"); kp.Digest() != cur.Digest() {
		t.Fatal("a move whose key is not stored is not followed")
	}
	if err := os.WriteFile(filepath.Join(dir, "kel", cur.Digest()+".moved"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if kp, _ := Load("h"); kp.Digest() != cur.Digest() {
		t.Fatal("an unreadable move record is not followed")
	}
}

func TestStatementsAreSignedLowSAndVerify(t *testing.T) {
	kp, _ := GenerateKeypair()
	msg := []byte("whisper-key-event/v2 test")
	for i := 0; i < 64; i++ {
		sig, err := kp.SignStatement(msg)
		if err != nil {
			t.Fatal(err)
		}
		if !kel.IsCanonicalSignature(sig) {
			t.Fatal("every signature is strict DER, low S")
		}
		if kel.VerifySignature(kp.SPKI(), msg, sig) != kel.SigValid {
			t.Fatal("the signature verifies under the key's SPKI")
		}
	}
	var nilKey *Keypair
	if _, err := nilKey.SignStatement(msg); err == nil {
		t.Fatal("no key signs nothing")
	}
}

func TestSuccessorsAreTheNextKeyAndAPendingRecovery(t *testing.T) {
	withTempIdentityDir(t)
	cur, _ := LoadOrGenerate("h")
	if len(Successors(cur)) != 0 {
		t.Fatal("no successors before any is kept")
	}
	next, _ := EnsureNextKey(cur)
	fresh, _ := GenerateKeypair()
	if err := RecordPendingRecovery(cur, fresh); err != nil {
		t.Fatal(err)
	}
	if s := Successors(cur); len(s) != 1 || s[0].Digest() != fresh.Digest() {
		t.Fatal("before a rotation of it was sent, the next key is never offered")
	}
	if err := MarkRotating(cur); err != nil {
		t.Fatal(err)
	}
	s := Successors(cur)
	if len(s) != 2 || s[0].Digest() != next.Digest() || s[1].Digest() != fresh.Digest() {
		t.Fatal("the successors are the next key, then the recovery key")
	}
	if kp, _ := Load("h"); kp.Digest() != cur.Digest() {
		t.Fatal("a pending recovery does not move the pin")
	}
	if err := RecordMove(nil, fresh, time.Now()); err == nil {
		t.Fatal("no key, no move")
	}
	if err := RecordPendingRecovery(cur, nil); err == nil {
		t.Fatal("no key, no pending recovery")
	}
	if _, err := EnsureNextKey(nil); err == nil {
		t.Fatal("no key, no next key")
	}
	if _, err := NextKey(nil); err == nil {
		t.Fatal("no key, no next key")
	}
	if MarkRotating(nil) == nil {
		t.Fatal("no key, no rotation")
	}
	if Refresh(nil) != nil {
		t.Fatal("Refresh of nothing is nothing")
	}
}

func TestADamagedStoreNeverLoopsOrMisleads(t *testing.T) {
	dir := withTempIdentityDir(t)
	a, _ := LoadOrGenerate("h")
	b, _ := EnsureNextKey(a)
	if err := RecordMove(a, b, time.Now()); err != nil {
		t.Fatal(err)
	}
	// a move back from b to a: a cycle a damaged or hostile store could hold
	if err := createOnce(movedKeyPath(dir, a.Digest()), encodeKey(a)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(movedPath(dir, b.Digest()), []byte(`{"to":"`+a.Digest()+`","serve_after_ms":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan *Keypair, 1)
	go func() { kp, _ := Load("h"); done <- kp }()
	select {
	case kp := <-done:
		if kp == nil {
			t.Fatal("the walk ends with a key")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cycle of moves must not loop forever")
	}
	// a move record naming something that is not a digest is not followed
	c, _ := GenerateKeypair()
	if err := createOnce(PathFor("c"), encodeKey(c)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(movedPath(dir, c.Digest()), []byte(`{"to":"../../etc/passwd","serve_after_ms":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if kp, _ := Load("c"); kp.Digest() != c.Digest() {
		t.Fatal("a move to a non-digest is not followed")
	}
	// a pending pointer that is not a digest, or names a key that is not stored under it, is ignored
	if err := os.WriteFile(pendingPath(c.Digest()), []byte("zz"), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(Successors(c)) != 0 {
		t.Fatal("a pending pointer that is not a digest names no successor")
	}
	if err := os.WriteFile(movedKeyPath(dir, strings.Repeat("0", 64)), encodeKey(a), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pendingPath(c.Digest()), []byte(strings.Repeat("0", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(Successors(c)) != 0 {
		t.Fatal("a stored key whose digest is not its name is no successor")
	}
	var nilKey *Keypair
	if nilKey.ServingKey() != nil {
		t.Fatal("no key serves nothing")
	}
}

func TestALinkPlantedInTheStoreIsNeverFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privilege on Windows")
	}
	dir := withTempIdentityDir(t)
	cur, _ := LoadOrGenerate("h")
	next, _ := EnsureNextKey(cur)
	if err := RecordMove(cur, next, time.Now()); err != nil {
		t.Fatal(err)
	}
	moved := movedPath(dir, cur.Digest())
	real := moved + ".real"
	if err := os.Rename(moved, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, moved); err != nil {
		t.Fatal(err)
	}
	if kp, _ := Load("h"); kp.Digest() != cur.Digest() {
		t.Fatal("a move record that is a link is not followed")
	}
	_ = os.Remove(moved)
	_ = os.Rename(real, moved)
	key := movedKeyPath(dir, next.Digest())
	_ = os.Rename(key, key+".real")
	_ = os.Symlink(key+".real", key)
	if kp, _ := Load("h"); kp.Digest() != cur.Digest() {
		t.Fatal("a moved key that is a link is not followed")
	}
}

func TestACrashsTemporariesAreSwept(t *testing.T) {
	withTempIdentityDir(t)
	cur, _ := LoadOrGenerate("h")
	stale := nextPath(cur.Digest()) + ".tmp-deadbeef"
	_ = os.MkdirAll(filepath.Dir(stale), 0o700)
	if err := os.WriteFile(stale, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	_ = os.Chtimes(stale, past, past)
	fresh := nextPath(cur.Digest()) + ".tmp-cafe"
	_ = os.WriteFile(fresh, []byte("in flight"), 0o600)
	if _, err := EnsureNextKey(cur); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Fatal("a temporary a crash left is swept")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("one another process may be writing now is left alone")
	}
	if err := writeExclusive(nextPath(cur.Digest()), []byte("x")); err == nil {
		t.Fatal("the exclusive fallback never replaces a file")
	}
}

func TestARecoveryKeyIsKeptBeforeItIsSentAndReused(t *testing.T) {
	withTempIdentityDir(t)
	cur, _ := LoadOrGenerate("2a04:2a01:9::a1")
	k1, err := RecoveryKey("2a04:2a01:9::a1", cur)
	if err != nil {
		t.Fatal(err)
	}
	if s := Successors(cur); len(s) != 1 || s[0].Digest() != k1.Digest() {
		t.Fatal("the recovery key is offered as cur's pending successor at once")
	}
	if k2, _ := RecoveryKey("2a04:2a01:9::a1", cur); k2.Digest() != k1.Digest() {
		t.Fatal("a second request reuses the kept key")
	}
	ClearRecovery("2a04:2a01:9::a1", cur)
	if len(Successors(cur)) != 0 {
		t.Fatal("a cleared recovery is no longer offered")
	}
	if k3, _ := RecoveryKey("2a04:2a01:9::a1", cur); k3.Digest() == k1.Digest() {
		t.Fatal("after it is cleared, a new request has a new key")
	}
	// on a host that holds no key for the address the pointer is the address's
	h1, err := RecoveryKey("2a04:2a01:9::b2", nil)
	if err != nil {
		t.Fatal(err)
	}
	if h2, _ := RecoveryKey("2a04:2a01:9::b2", nil); h2.Digest() != h1.Digest() {
		t.Fatal("the address's pending recovery key is reused too")
	}
	ClearRecovery("2a04:2a01:9::b2", nil)
	if h3, _ := RecoveryKey("2a04:2a01:9::b2", nil); h3.Digest() == h1.Digest() {
		t.Fatal("and cleared")
	}
}

func TestWriteExclusiveCreatesOnceAndSyncs(t *testing.T) {
	dir := withTempIdentityDir(t)
	p := filepath.Join(dir, "kel", "x")
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	if err := writeExclusive(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "one" {
		t.Fatal("the data is written")
	}
	if err := writeExclusive(p, []byte("two")); err == nil {
		t.Fatal("never twice")
	}
	if b, _ := os.ReadFile(p); string(b) != "one" {
		t.Fatal("and never replaced")
	}
	if err := writeExclusive(filepath.Join(dir, "missing", "x"), nil); err == nil {
		t.Fatal("a missing directory is an error")
	}
}

// The key `whisper connect --adopt-key` adopts on a held identity is kept as a pending recovery,
// as RecoveryKey keeps a fresh one: under its own digest, named from each handle and from the key
// this host holds for the identity, read back by a later run, and withdrawn whole.
func TestAnAdoptedKeyIsKeptAsAPendingRecovery_andFoundByEveryLaterRun(t *testing.T) {
	withTempIdentityDir(t)
	const addr, name = "2a04:2a01::a2", "db-01"
	cur, err := LoadOrGenerate(addr) // a key this host holds for the address that is not the one adopted
	if err != nil {
		t.Fatal(err)
	}
	kp, err := Mint()
	if err != nil || !kp.Unstored() {
		t.Fatal("a minted key is stored nowhere yet")
	}
	if err := KeepRecovery(cur, kp, addr, name); err != nil {
		t.Fatal(err)
	}
	if kp.Unstored() {
		t.Fatal("kept: stored")
	}
	for _, h := range []string{addr, name} {
		if rk := PendingRecovery(h); rk == nil || rk.Digest() != kp.Digest() {
			t.Fatalf("%s: a later run finds the kept recovery", h)
		}
	}
	if s := Successors(cur); len(s) != 1 || s[0].Digest() != kp.Digest() {
		t.Fatal("a connect by the key held, refused once the recovery took effect, is offered the kept key")
	}
	if got, err := Load(addr); err != nil || got.Digest() != cur.Digest() {
		t.Fatal("the handle is not moved by keeping a recovery")
	}
	if rk, err := RecoveryKey(addr, cur); err != nil || rk.Digest() != kp.Digest() {
		t.Fatal("`whisper identity recover` goes on with the kept key")
	}
	ClearRecovery(addr, cur)
	if PendingRecovery(addr) != nil || len(Successors(cur)) != 0 {
		t.Fatal("withdrawn: the pointers from the address and from the key held both go")
	}
	if PendingRecovery(name) == nil {
		t.Fatal("the pointer from another handle goes only when that handle is cleared")
	}
	ClearRecovery(name, nil)
	if PendingRecovery(name) != nil {
		t.Fatal("cleared")
	}
	if _, err := os.Stat(movedKeyPath(identityDir(), kp.Digest())); err != nil {
		t.Fatal("the key file itself stays")
	}
}

func TestKeepRecoveryRefusesToKeepAKeyNothingNames(t *testing.T) {
	withTempIdentityDir(t)
	kp, _ := Mint()
	if err := KeepRecovery(nil, kp, " ", ""); err == nil {
		t.Fatal("a recovery named by no handle and no key could never be found again")
	}
	if !kp.Unstored() {
		t.Fatal("refused: still unstored, so the caller stores it under its handle")
	}
	if err := KeepRecovery(nil, nil, "x"); err == nil {
		t.Fatal("no key")
	}
	same, _ := LoadOrGenerate("2a04:2a01::a3")
	if err := KeepRecovery(same, same, "2a04:2a01::a3"); err != nil {
		t.Fatal(err)
	}
	if len(Successors(same)) != 0 {
		t.Fatal("a key is never named as its own successor")
	}
}

func TestAPendingPointerPlantedAsALinkIsNeverFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	withTempIdentityDir(t)
	kp, _ := Mint()
	if err := KeepRecovery(nil, kp, "2a04:2a01::a4"); err != nil {
		t.Fatal(err)
	}
	ptr := recoveryPointer("2a04:2a01::a4", nil)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte(kp.Digest()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ptr); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, ptr); err != nil {
		t.Fatal(err)
	}
	if PendingRecovery("2a04:2a01::a4") != nil {
		t.Fatal("a pointer that is not a regular file is never read")
	}
}

func TestLinkStoresAMintedKey(t *testing.T) {
	withTempIdentityDir(t)
	kp, _ := Mint()
	if err := Link("db-02", kp); err != nil || kp.Unstored() {
		t.Fatalf("linked: stored: %v", err)
	}
	other, _ := Mint()
	if err := Link("db-02", other); !errors.Is(err, ErrLinkedElsewhere) || !other.Unstored() {
		t.Fatal("a refused link stores nothing")
	}
}

func TestRecoveryKeyGoesOnWithARecoveryNamedFromTheHandleOnly(t *testing.T) {
	withTempIdentityDir(t)
	const addr = "2a04:2a01::a5"
	kp, _ := Mint()
	if err := KeepRecovery(nil, kp, addr); err != nil { // kept while this host held no key for it
		t.Fatal(err)
	}
	cur, _ := LoadOrGenerate(addr) // and a key for it since
	if rk, err := RecoveryKey(addr, cur); err != nil || rk.Digest() != kp.Digest() {
		t.Fatal("the kept recovery, never a second fresh one beside it")
	}
}

func TestKeepRecoveryNeverStartsASecondRecoveryBesideAPendingOne(t *testing.T) {
	withTempIdentityDir(t)
	const addr = "2a04:2a01::a6"
	first, _ := Mint()
	if err := KeepRecovery(nil, first, addr); err != nil {
		t.Fatal(err)
	}
	second, _ := Mint()
	if err := KeepRecovery(nil, second, addr); !errors.Is(err, ErrRecoveryPending) {
		t.Fatalf("refused, naming the way out: %v", err)
	}
	if rk := PendingRecovery(addr); rk == nil || rk.Digest() != first.Digest() {
		t.Fatal("the pending one is untouched")
	}
	if err := KeepRecovery(nil, first, addr); err != nil {
		t.Fatal("keeping the same one again is no second recovery")
	}
}

func TestFinishRecoveryLeavesAPointerThatNamesAnotherKey(t *testing.T) {
	withTempIdentityDir(t)
	const addr = "2a04:2a01::a7"
	done, _ := Mint()
	other, _ := Mint()
	if err := KeepRecovery(nil, other, addr); err != nil { // written by another run since
		t.Fatal(err)
	}
	FinishRecovery(addr, nil, done)
	if rk := PendingRecovery(addr); rk == nil || rk.Digest() != other.Digest() {
		t.Fatal("only the pointers naming the finished key go")
	}
	FinishRecovery(addr, nil, other)
	if PendingRecovery(addr) != nil {
		t.Fatal("finished")
	}
}
