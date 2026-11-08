// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package idkey

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/kel"
	"github.com/whisper-sec/whisper-cli/internal/secfile"
)

// The pre-committed next key, and the moves of an identity's pin, live beside the handle files:
//
//	kel/<digest>.next.pem   the committed next key of the key whose SPKI digest is <digest>. It is
//	                        never exported to sshd, TLS or anything else, and never leaves the host;
//	                        the service only ever sees its commitment.
//	kel/<digest>.pem        a key that became an identity's pin by a rotation or a recovery
//	kel/<digest>.moved      the pin moved from the key <digest> to another: {"to","serve_after_ms"}
//
// Every file is created once and never rewritten, so a crash leaves either the old state or the
// new one. Keying them by the key rather than by the handle means every handle that reaches a
// key (its /128, a name, the connect-first default) reaches its successor too, with no fan-out.
// A reader that must never open a next key (the sudo context) follows .moved files and opens
// kel/<digest>.pem only.

func kelDir() string { return kelDirIn(identityDir()) }

func kelDirIn(dir string) string { return filepath.Join(dir, "kel") }

// Digest is the key's TLSA 3 1 1 data: lowercase hex SHA-256 of its DER SPKI.
func (k *Keypair) Digest() string { return kel.KeyDigest(k.spkiDER) }

// SPKI is the key's DER SubjectPublicKeyInfo.
func (k *Keypair) SPKI() []byte { return append([]byte(nil), k.spkiDER...) }

// Commitment is the commitment to this key: what an event that precedes it carries.
func (k *Keypair) Commitment() string {
	c, _ := kel.Commit(k.Digest())
	return c
}

// SignStatement signs a key-event statement: ECDSA P-256 over SHA-256, strict DER, low S.
func (k *Keypair) SignStatement(statement []byte) ([]byte, error) {
	if k == nil || k.Private == nil {
		return nil, errors.New("idkey: no key to sign with")
	}
	sum := sha256.Sum256(statement)
	der, err := ecdsa.SignASN1(rand.Reader, k.Private, sum[:])
	if err != nil {
		return nil, errors.New("idkey: could not sign the key event")
	}
	return kel.LowS(der)
}

// ServingKey is the key this identity's TLS leaf presents now: the pin, except inside a rotation's
// first phase, when the outgoing key keeps serving until the incoming one has had a TTL to reach
// every cache (RFC 7671 section 8.1). The pin signs every proof from the moment it moved.
func (k *Keypair) ServingKey() *Keypair {
	if k != nil && k.serving != nil && time.Now().Before(k.servingUntil) {
		return k.serving
	}
	return k
}

func nextPath(digest string) string { return filepath.Join(kelDir(), digest+".next.pem") }
func movedPath(dir, digest string) string {
	return filepath.Join(kelDirIn(dir), digest+".moved")
}
func movedKeyPath(dir, digest string) string {
	return filepath.Join(kelDirIn(dir), digest+".pem")
}

// NextKey is kp's committed next key, or an error when none is stored. It never mints.
func NextKey(kp *Keypair) (*Keypair, error) {
	if kp == nil {
		return nil, errors.New("idkey: no key")
	}
	return load(nextPath(kp.Digest()))
}

// EnsureNextKey returns kp's committed next key, minting and persisting one first when there is
// none. The key is on disk, synced, before this returns, so a commitment to it is never sent for
// a key a crash could lose.
func EnsureNextKey(kp *Keypair) (*Keypair, error) {
	if kp == nil {
		return nil, errors.New("idkey: no key")
	}
	path := nextPath(kp.Digest())
	if nk, err := load(path); err == nil {
		return nk, nil
	}
	nk, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	switch err := createOnce(path, encodeKey(nk)); {
	case err == nil:
		return nk, nil
	case errors.Is(err, os.ErrExist):
		return load(path) // another process minted it first: that one is the commitment
	default:
		return nil, err
	}
}

// DropNextKey removes kp's committed next key, for a key that was never published: a commitment
// the service never recorded protects nothing, and a private key nothing will use is not kept. No
// next key is success.
func DropNextKey(kp *Keypair) error {
	if kp == nil {
		return errors.New("idkey: no key")
	}
	if err := os.Remove(nextPath(kp.Digest())); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// move is the record of a confirmed pin move.
type move struct {
	To           string `json:"to"`
	ServeAfterMs int64  `json:"serve_after_ms"`
}

// RecordMove records that the pin moved from `from` to `to`, confirmed by the service: `to` is
// stored where every handle that reaches `from` finds it, and the leaf switches to it at
// serveAfter. Recording the same move twice is success; a different move from the same key is
// refused, because a key moves once.
func RecordMove(from, to *Keypair, serveAfter time.Time) error {
	if from == nil || to == nil {
		return errors.New("idkey: no key")
	}
	dir := identityDir()
	if err := createOnce(movedKeyPath(dir, to.Digest()), encodeKey(to)); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	b, _ := json.Marshal(move{To: to.Digest(), ServeAfterMs: serveAfter.UnixMilli()})
	err := createOnce(movedPath(dir, from.Digest()), b)
	if errors.Is(err, os.ErrExist) {
		if m, rerr := readMove(dir, from.Digest()); rerr == nil && m.To == to.Digest() {
			return nil
		}
		return fmt.Errorf("idkey: the key %s already moved to another key", from.Digest()[:16])
	}
	return err
}

// Moved reports whether the pin already moved away from kp on this host.
func Moved(kp *Keypair) bool {
	_, err := readMove(identityDir(), kp.Digest())
	return err == nil
}

// regular refuses anything but a regular file: a link planted in the store is never followed.
func regular(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New("idkey: not a regular file: " + filepath.Base(path))
	}
	return nil
}

func readMove(dir, digest string) (move, error) {
	var m move
	if err := regular(movedPath(dir, digest)); err != nil {
		return m, err
	}
	b, err := os.ReadFile(movedPath(dir, digest))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil || !kel.IsDigest(m.To) {
		return m, errors.New("idkey: an unreadable move record")
	}
	return m, nil
}

// Refresh is the key kp's identity pins now, by the moves recorded in the store kp came from:
// kp itself when none is recorded. It never opens a next key.
func Refresh(kp *Keypair) *Keypair {
	if kp == nil {
		return nil
	}
	dir := kp.dir
	if dir == "" {
		dir = identityDir()
	}
	return follow(kp, dir)
}

// maxMoves bounds the walk, so a damaged store cannot loop it.
const maxMoves = 1024

// follow walks kp's recorded moves to the key the identity pins now. It opens move records and
// moved keys only, never a next key, so the sudo context may call it.
func follow(kp *Keypair, dir string) *Keypair {
	cur := kp
	var prev *Keypair
	var until time.Time
	for i := 0; i < maxMoves; i++ {
		m, err := readMove(dir, cur.Digest())
		if err != nil {
			break
		}
		if regular(movedKeyPath(dir, m.To)) != nil {
			break
		}
		nk, err := load(movedKeyPath(dir, m.To))
		if err != nil || nk.Digest() != m.To {
			break // a move whose key is not stored here: keep the last key we can prove
		}
		nk.dir = dir
		prev, cur, until = cur, nk, time.UnixMilli(m.ServeAfterMs)
	}
	if prev != nil && time.Now().Before(until) {
		cur.serving, cur.servingUntil = prev, until
	}
	return cur
}

// encodeKey is the PEM a key is stored as.
func encodeKey(kp *Keypair) []byte {
	der, _ := x509.MarshalECPrivateKey(kp.Private)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// writeExclusive creates path, which must not exist, writes data and syncs it.
func writeExclusive(path string, data []byte) error {
	f, err := secfile.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if serr := f.Sync(); werr == nil {
		werr = serr
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
	}
	return werr
}

// sweepTemporaries removes the private temporaries a crash left beside path (older than a
// minute, so one another process is writing now is left alone).
func sweepTemporaries(path string) {
	old, _ := filepath.Glob(path + ".tmp-*")
	for _, p := range old {
		if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() && time.Since(fi.ModTime()) > time.Minute {
			_ = os.Remove(p)
		}
	}
}

// createOnce writes data to path only if path does not exist: whole and synced to a private
// temporary first, then hard-linked into place, so no reader ever sees a half-written file and an
// existing file is never replaced (os.ErrExist).
func createOnce(path string, data []byte) error {
	if err := secfile.MkdirAllFor(path); err != nil {
		return err
	}
	sweepTemporaries(path)
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	tmp := path + ".tmp-" + hex.EncodeToString(nonce[:])
	f, err := secfile.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	_, werr := f.Write(data)
	if serr := f.Sync(); werr == nil {
		werr = serr
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return err
		}
		// A filesystem without hard links (FAT, exFAT, some network shares): the file is created
		// exclusively in place instead, which still never replaces one that exists.
		if ferr := writeExclusive(path, data); ferr != nil {
			return ferr
		}
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func pendingPath(digest string) string { return filepath.Join(kelDir(), digest+".recovery") }

func recoveryPointer(handle string, cur *Keypair) string {
	if cur != nil {
		return pendingPath(cur.Digest())
	}
	return pendingPath("h-" + filepath.Base(PathFor(handle)))
}

// RecoveryKey is the key an owner's recovery of handle moves to: the one already kept for it, so a
// recovery whose answer was lost is sent again with the same key, or a fresh one, stored under its
// own digest and named as the pending successor of cur (or of the handle, on a host that holds no
// key for it) before the request leaves this host. A recovery that lands is never pinned to a key
// nobody holds.
func RecoveryKey(handle string, cur *Keypair) (*Keypair, error) {
	ptr := recoveryPointer(handle, cur)
	if rk := pointedKey(ptr); rk != nil {
		return rk, nil
	}
	if cur != nil {
		// a recovery `whisper connect --adopt-key` keeps (KeepRecovery) is named from the handle,
		// so a later recover goes on with that key rather than start a second recovery beside it
		if rk := pointedKey(recoveryPointer(handle, nil)); rk != nil {
			return rk, nil
		}
	}
	fresh, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	if err := createOnce(movedKeyPath(identityDir(), fresh.Digest()), encodeKey(fresh)); err != nil {
		return nil, err
	}
	if err := secfile.WriteFileAtomic(ptr, []byte(fresh.Digest())); err != nil {
		return nil, err
	}
	return fresh, nil
}

// pointedKey is the recovery key a pointer file names, or nil when there is none or the key it
// names is not stored under its own digest.
func pointedKey(ptr string) *Keypair {
	if regular(ptr) != nil {
		return nil
	}
	b, err := os.ReadFile(ptr)
	if err != nil || !kel.IsDigest(string(b)) {
		return nil
	}
	rk, err := load(movedKeyPath(identityDir(), string(b)))
	if err != nil || rk.Digest() != string(b) {
		return nil
	}
	return rk
}

// ClearRecovery forgets a pending recovery of handle once it took effect or was withdrawn: the
// pointer from cur and the one from the handle. The key file stays; only the pointers go.
func ClearRecovery(handle string, cur *Keypair) {
	_ = os.Remove(recoveryPointer(handle, cur))
	if cur != nil {
		_ = os.Remove(recoveryPointer(handle, nil))
	}
}

// KeepRecovery keeps kp, the key an owner's recovery moves an identity to, as RecoveryKey keeps a
// fresh one, for a key this host already has (the one `whisper connect --adopt-key` adopts): kp
// under its own digest, named as the pending successor of every handle given and of cur (the key
// this host holds for the identity, when that is another), so a later run finds it
// (PendingRecovery, RecoveryKey), a connect refused once it takes effect offers it (Successors),
// and a cancel withdraws it (ClearRecovery). All of it is synced to disk before this returns, so
// it is written before the recovery leaves this host; kp is linked under a handle only once the
// service says it took effect.
func KeepRecovery(cur, kp *Keypair, handles ...string) error {
	if kp == nil || kp.Private == nil {
		return errors.New("idkey: no key")
	}
	if err := createOnce(movedKeyPath(identityDir(), kp.Digest()), encodeKey(kp)); err != nil &&
		!errors.Is(err, os.ErrExist) {
		return err
	}
	if rk, err := load(movedKeyPath(identityDir(), kp.Digest())); err != nil || rk.Digest() != kp.Digest() {
		return errors.New("idkey: the recovery key could not be read back from the store")
	}
	var ptrs []string
	for _, h := range handles {
		if strings.TrimSpace(h) != "" {
			ptrs = append(ptrs, recoveryPointer(h, nil))
		}
	}
	if cur != nil && cur.Digest() != kp.Digest() {
		ptrs = append(ptrs, pendingPath(cur.Digest()))
	}
	for _, ptr := range ptrs {
		// never a second recovery beside one pending: a pointer that names another kept key stays
		if other := pointedKey(ptr); other != nil && other.Digest() != kp.Digest() {
			return fmt.Errorf("%w (%s); finish it, or withdraw it with `whisper identity cancel`, first",
				ErrRecoveryPending, other.Digest()[:16])
		}
	}
	named := false
	for _, ptr := range ptrs {
		if err := secfile.WriteFileAtomic(ptr, []byte(kp.Digest())); err != nil {
			return err
		}
		named = true
	}
	if !named {
		return errors.New("idkey: a recovery is kept under a handle or a key")
	}
	kp.unstored = false
	return nil
}

// ErrRecoveryPending is KeepRecovery's answer when another recovery is kept for the identity.
var ErrRecoveryPending = errors.New("idkey: another recovery of this identity is pending on this host")

// FinishRecovery forgets the pointers from the handle and from cur that name kp, once kp's
// recovery took effect: a pointer a concurrent run wrote for another key since stays.
func FinishRecovery(handle string, cur, kp *Keypair) {
	if kp == nil {
		return
	}
	paths := []string{recoveryPointer(handle, nil)}
	if cur != nil {
		paths = append(paths, recoveryPointer(handle, cur))
	}
	for _, ptr := range paths {
		if b, err := os.ReadFile(ptr); err == nil && string(b) == kp.Digest() && regular(ptr) == nil {
			_ = os.Remove(ptr)
		}
	}
}

// PendingRecovery is the recovery key kept for handle (by RecoveryKey or KeepRecovery) and not
// yet in effect or withdrawn, or nil.
func PendingRecovery(handle string) *Keypair {
	if strings.TrimSpace(handle) == "" {
		return nil
	}
	return pointedKey(recoveryPointer(handle, nil))
}

// RecordPendingRecovery names fresh as cur's pending successor (a test seam and the low-level
// half of RecoveryKey).
func RecordPendingRecovery(cur, fresh *Keypair) error {
	if cur == nil || fresh == nil {
		return errors.New("idkey: no key")
	}
	if err := createOnce(movedKeyPath(identityDir(), fresh.Digest()), encodeKey(fresh)); err != nil &&
		!errors.Is(err, os.ErrExist) {
		return err
	}
	return secfile.WriteFileAtomic(pendingPath(cur.Digest()), []byte(fresh.Digest()))
}

func rotatingPath(digest string) string { return filepath.Join(kelDir(), digest+".rotating") }

// MarkRotating records, before a rotation is sent, that this host is revealing cur's next key.
// Only then may Successors offer the next key: until its rotation the next key is never used for
// anything, because a signature by it would disclose its public half, which the commitment
// exists to keep unrevealed.
func MarkRotating(cur *Keypair) error {
	if cur == nil {
		return errors.New("idkey: no key")
	}
	nk, err := NextKey(cur)
	if err != nil {
		return err
	}
	return secfile.WriteFileAtomic(rotatingPath(cur.Digest()), []byte(nk.Digest()))
}

// Successors are the keys the service may have moved cur's identity to without this host seeing
// the answer: its committed next key once a rotation of it was sent, and a recovery key waiting
// out its window. A caller tries them only after the service refused cur, and records the move
// only on the service's answer.
func Successors(cur *Keypair) []*Keypair {
	var out []*Keypair
	if nk, err := NextKey(cur); err == nil {
		if b, rerr := os.ReadFile(rotatingPath(cur.Digest())); rerr == nil && string(b) == nk.Digest() {
			out = append(out, nk)
		}
	}
	if b, err := os.ReadFile(pendingPath(cur.Digest())); err == nil && kel.IsDigest(string(b)) {
		if rk, err := load(movedKeyPath(identityDir(), string(b))); err == nil && rk.Digest() == string(b) {
			out = append(out, rk)
		}
	}
	return out
}
