// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/egress"
	"github.com/whisper-sec/whisper-cli/internal/peerid"
	"github.com/whisper-sec/whisper-cli/internal/projcfg"
	"github.com/whisper-sec/whisper-cli/internal/secfile"
)

// session_access.go is the CLI half of who may use the forwarder this process holds.
//
// The forwarder (egress.Proxy, shared by both tiers) admits the holder's own user and refuses
// every other local user unless it presents this session's credential. This file decides the
// rule for the process (the --share mode, the host service's share list), mints the credential
// once per holder process, arms every forwarder the process brings up, and writes the
// credential to an owner-only file beside the session record so a deliberate cross-user client
// can use it. The credential is never printed, logged, put in a record, or passed on a command
// line; the only places it travels are that file and the environment of a child this process
// starts itself.

// shareUser is one entry of a host service's share list: the name it was given as, for
// messages, and the principal it resolved to at install (a uid or a SID), which is what is
// compared. A name deleted and recreated later is a different person and does not inherit it.
type shareUser = projcfg.ShareUser

// holderShare is this process's admission rule, settled before its first forwarder starts.
var holderShare = struct {
	mu       sync.Mutex
	mode     egress.ShareMode
	users    []shareUser
	explicit bool // the list came from a config or flag, not the sudo default
	secret   string
}{}

// setHolderShareMode records `--share` for this process.
func setHolderShareMode(m egress.ShareMode) {
	holderShare.mu.Lock()
	holderShare.mode = m
	holderShare.mu.Unlock()
}

// setHolderShareUsers records the share list a host service was installed with.
func setHolderShareUsers(users []shareUser) {
	holderShare.mu.Lock()
	holderShare.users = append([]shareUser(nil), users...)
	holderShare.explicit = true
	holderShare.mu.Unlock()
}

// sudoUIDFn reads the uid of the user who ran sudo. A seam for tests.
var sudoUIDFn = func() (string, uint32, bool) {
	for _, env := range []struct{ uid, name string }{{"SUDO_UID", "SUDO_USER"}, {"PKEXEC_UID", ""}} {
		v := strings.TrimSpace(os.Getenv(env.uid))
		if v == "" {
			continue
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n == 0 {
			continue
		}
		name := strings.TrimSpace(os.Getenv(env.name))
		if name == "" {
			name = "uid " + v
		}
		return name, uint32(n), true
	}
	return "", 0, false
}

// effectiveShare is the rule this process arms its forwarders with. A root holder started
// through sudo with no explicit list shares with the user who ran sudo, which is what makes
// `sudo whisper connect` serve the person who typed it. Root is never added
// by default.
func effectiveShare() (egress.ShareMode, []shareUser) {
	holderShare.mu.Lock()
	defer holderShare.mu.Unlock()
	users := holderShare.users
	if !holderShare.explicit && peerid.Privileged(peerid.Self()) {
		if name, uid, ok := sudoUIDFn(); ok {
			users = []shareUser{{Name: name, ID: string(peerid.UID(uid))}}
		}
	}
	return holderShare.mode, users
}

// holderSecret is this process's session credential, minted on first use: 32 random bytes,
// hex (no ':', '@' or '/' to break a proxy URL or the Basic split).
func holderSecret() string {
	holderShare.mu.Lock()
	defer holderShare.mu.Unlock()
	if holderShare.secret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "" // no credential at all is the strict state, never a weak one
		}
		holderShare.secret = hex.EncodeToString(b)
	}
	return holderShare.secret
}

// accessLogf receives the forwarder's rate-limited refusal lines. The daemon points it at its
// own log; an interactive holder writes to stderr unless --quiet.
var accessLogf = func(format string, a ...any) {
	if !g.quiet {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
	}
}

// accessArmable is a forwarder that takes an admission rule: *egress.Proxy and *wgtun.Tunnel.
type accessArmable interface {
	SetAccess(egress.Access)
	IdentityAvailable() bool
}

// shareHint is the one line a refused client is given: the fix, never the secret.
func shareHint() string {
	return "To use it, run as the user holding it, present its credential (the .cred file beside " +
		"its session record), or have it shared with you: `sudo whisper service install --share-user <you>`"
}

// armSessionAccess arms the forwarder behind sess with this process's rule and, when this
// process's OWN clients will need the credential to get through, records the endpoint carrying
// it in sess.clientEndpoint: a privileged holder admits only its own process (so its children
// need it), --share=credential admits nobody on identity, and a forwarder that could not name
// its own user (a sandbox denying the socket tables) admits only the credential.
func armSessionAccess(sess *egressSession) {
	if sess == nil || sess.local == nil {
		return
	}
	fw, ok := sess.local.(accessArmable)
	if !ok {
		return
	}
	mode, users := effectiveShare()
	ids := make(map[peerid.ID]bool, len(users))
	for _, u := range users {
		if id := peerid.ID(strings.TrimSpace(u.ID)); id != peerid.Unknown {
			ids[id] = true
		}
	}
	secret := holderSecret()
	fw.SetAccess(egress.Access{
		Mode:   mode,
		Secret: secret,
		Admit:  func(id peerid.ID) bool { return ids[id] },
		Hint:   shareHint(),
		Logf:   func(f string, a ...any) { accessLogf(f, a...) },
	})
	sess.share = mode
	if !fw.IdentityAvailable() && mode != egress.ShareAny {
		accessLogf("whisper: this host does not let the local forwarder see which user a client belongs to, " +
			"so it admits only clients that present the session credential; whisper's own commands do this for you")
	}
	if secret != "" && mode != egress.ShareAny &&
		(mode == egress.ShareCredential || peerid.Privileged(peerid.Self()) || !fw.IdentityAvailable()) {
		sess.clientEndpoint = withCredential(sess.endpoint, secret)
	}
}

// withCredential puts the RFC 1929 / Basic userinfo into a proxy URL. The username is fixed and
// ignored by the forwarder. The result must never be printed.
func withCredential(endpoint, secret string) string {
	i := strings.Index(endpoint, "://")
	if i < 0 || secret == "" {
		return endpoint
	}
	return endpoint[:i+3] + "whisper:" + secret + "@" + endpoint[i+3:]
}

// useEndpoint is the endpoint this process connects through and hands to its own children:
// the credential-bearing one when the forwarder needs it, otherwise the printable one.
func (s *egressSession) useEndpoint() string {
	if s.clientEndpoint != "" {
		return s.clientEndpoint
	}
	return s.endpoint
}

// sessionCred is the owner-only file beside a session record. It names the pid and port it
// belongs to, so a stale file left by a crashed holder never authenticates against whoever holds
// that port next.
type sessionCred struct {
	PID    int    `json:"pid"`
	Port   int    `json:"port"`
	Secret string `json:"secret"`
}

// credPathFor is the credential file for a record file.
func credPathFor(recordPath string) string {
	return strings.TrimSuffix(recordPath, ".json") + ".cred"
}

// writeSessionCred writes the credential beside the record this process just wrote. 0600 on
// unix and the owner-only protected DACL on Windows (secfile), whichever registry took the
// record. Best-effort: without it a cross-user client cannot authenticate, nothing else changes.
func writeSessionCred(recordPath string, port int) {
	secret := holderSecret()
	if recordPath == "" || secret == "" {
		return
	}
	b, err := json.Marshal(sessionCred{PID: os.Getpid(), Port: port, Secret: secret})
	if err != nil {
		return
	}
	_ = secfile.WriteFileAtomic(credPathFor(recordPath), append(b, '\n'))
}

// readSessionCred reads a record's credential, only when the file is trusted the way records
// are and names the record's own pid and port.
func readSessionCred(rec sessionRecord) (string, bool) {
	if rec.path == "" {
		return "", false
	}
	b, trusted := readTrustedRecord(filepath.Dir(rec.path), credPathFor(rec.path))
	if !trusted {
		return "", false
	}
	var c sessionCred
	if json.Unmarshal(b, &c) != nil || c.Secret == "" || c.PID != rec.PID || c.Port != rec.Port {
		return "", false
	}
	return c.Secret, true
}

// notSharedError stops a caller whose user the live session does not admit. Opening a fresh
// session instead would replace the holder's server-side peer and end its tunnel for everyone,
// so the caller is told whose session it is and how to be let in.
type notSharedError struct {
	addr string
	port int
}

func (e *notSharedError) Error() string {
	return fmt.Sprintf("a Whisper session for %s is live on 127.0.0.1:%d, but it is held by another user "+
		"and is not shared with you. Ask its owner to add you (`sudo whisper service install --share-user <you>`), "+
		"or run whisper as that user. A new session would replace that one's tunnel, so none was opened",
		orVal(e.addr, "this agent"), e.port)
}

// admitVerdict is what a forwarder said to a no-credential greeting.
type admitVerdict int

const (
	admitUnknown admitVerdict = iota // no answer, or not a whisper forwarder
	admitYes                         // 05 00: admitted on identity
	admitNo                          // 05 FF: this caller needs the credential
)

// forwarderAdmits greets the forwarder on port offering only "no authentication" and reads the
// method it picks. A package var so command tests can play either answer.
var forwarderAdmits = func(port int) admitVerdict {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), ensureProbeTimeout)
	if err != nil {
		return admitUnknown
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(ensureProbeTimeout))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return admitUnknown
	}
	reply := make([]byte, 2)
	if _, err := readFull(c, reply); err != nil || reply[0] != 0x05 {
		return admitUnknown
	}
	switch reply[1] {
	case 0x00:
		return admitYes
	case 0xFF:
		return admitNo
	}
	return admitUnknown
}

// reuseEndpoint decides how this caller connects through a live record's forwarder: as is when
// it admits us, with the record's credential when it does not and we may read the credential and
// the record's holder provably owns the port (never present it to a port a stranger
// holds), and otherwise not at all, which is a notSharedError.
func reuseEndpoint(rec sessionRecord) (string, error) {
	if forwarderAdmits(rec.Port) != admitNo {
		return "", nil
	}
	if secret, ok := readSessionCred(rec); ok {
		if owned, known := listenerOwnedByFn(rec.Port, rec.PID); known && owned {
			return withCredential(rec.Endpoint, secret), nil
		}
	}
	return "", &notSharedError{addr: rec.Addr, port: rec.Port}
}

// socksCredentialForPort finds the credential of the live record on port, under the same rule
// as reuseEndpoint: a trusted .cred naming the record's pid and port, and a holder that provably
// owns the listener. "" when there is none this caller may use.
func socksCredentialForPort(port int) string {
	for _, rec := range readSessionRecords() {
		if rec.Port != port {
			continue
		}
		if secret, ok := readSessionCred(rec); ok {
			if owned, known := listenerOwnedByFn(rec.Port, rec.PID); known && owned {
				return secret
			}
		}
	}
	return ""
}

// socksGreet is the client side of the SOCKS5 greeting every in-CLI dialer uses: offer
// "no authentication" and username/password, and when the forwarder picks the latter complete
// RFC 1929 with the session credential this caller may use, or fail with the fix.
func socksGreet(conn net.Conn, port int) error {
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		return err
	}
	greeting := make([]byte, 2)
	if _, err := readFull(conn, greeting); err != nil {
		return err
	}
	switch {
	case greeting[0] != 0x05 || (greeting[1] != 0x00 && greeting[1] != 0x02):
		return fmt.Errorf("the listener on 127.0.0.1:%d is not a Whisper proxy", port)
	case greeting[1] == 0x02:
		secret := socksCredentialForPort(port)
		if secret == "" {
			return fmt.Errorf("the Whisper session on 127.0.0.1:%d is held by another user and is not shared with you; "+
				"ask its owner to add you (`sudo whisper service install --share-user <you>`)", port)
		}
		return socksUserPass(conn, secret)
	}
	return nil
}

// socksUserPass runs the client side of RFC 1929 after the forwarder chose method 0x02.
func socksUserPass(c net.Conn, secret string) error {
	if len(secret) == 0 || len(secret) > 255 {
		return fmt.Errorf("the session credential is unusable")
	}
	msg := append([]byte{0x01, 7}, "whisper"...)
	msg = append(msg, byte(len(secret)))
	msg = append(msg, secret...)
	if _, err := c.Write(msg); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := readFull(c, reply); err != nil {
		return err
	}
	if reply[0] != 0x01 || reply[1] != 0x00 {
		return fmt.Errorf("the session refused its own credential; the holder may have restarted, try again")
	}
	return nil
}

// daemonSharePlan applies the config's share list to this daemon's forwarders and points the
// refusal log at the daemon's own log.
//
// A root-run SERVICE whose config predates share lists is upgraded in place, never broken: its
// list is derived from what the install already records about the account that installed it
// (legacyShareUser), adopted for this run, logged once, and published beside the session records
// so `whisper service status` shows it. Only when the install records nobody does the service
// share with nobody, and it says so with the command that fixes it.
func daemonSharePlan(cfg projcfg.Config, supervised bool, configFile string) {
	accessLogf = func(f string, a ...any) { daemonLogf(f, a...) }
	if cfg.Share != nil {
		if supervised && peerid.Privileged(peerid.Self()) {
			writeAdoptedShare(adoptedShare{Users: cfg.Share.Users, Source: shareFromConfig})
		} else {
			removeAdoptedShare()
		}
		setHolderShareUsers(cfg.Share.Users)
		if len(cfg.Share.Users) > 0 {
			names := make([]string, 0, len(cfg.Share.Users))
			for _, u := range cfg.Share.Users {
				names = append(names, orVal(strings.TrimSpace(u.Name), u.ID))
			}
			daemonLogf("whisper: the local forwarder is shared with %s; other local users need the session credential",
				strings.Join(names, ", "))
		}
		return
	}
	if !supervised || !peerid.Privileged(peerid.Self()) {
		return
	}
	if u, from, ok := legacyShareUser(configFile); ok {
		setHolderShareUsers([]shareUser{u})
		writeAdoptedShare(adoptedShare{Users: []shareUser{u}, From: from, Source: shareAdopted})
		daemonLogf("whisper: this service was installed before share lists, so its local forwarder is shared with %s, "+
			"%s. `sudo whisper service install` records that in the config; `--share-user` or `--no-share` changes it",
			orVal(u.Name, u.ID), from)
		return
	}
	writeAdoptedShare(adoptedShare{Users: []shareUser{}, Source: shareNone})
	setHolderShareUsers(nil)
	daemonLogf("whisper: this service's config has no share list and records no account that installed it, so its " +
		"local forwarder admits no login user without the session credential. Re-run `sudo whisper service install` " +
		"from the account that uses this connection (that records it), or add `--share-user <name>`")
}

// installHomeFn is the HOME the unit was installed with (baked into its environment). A seam,
// so a test names one without setting the process's HOME by hand.
var installHomeFn = func() string { return firstNonBlank(os.Getenv("HOME"), os.Getenv("USERPROFILE")) }

// pathOwnerFn names the account that owns a path; a seam for tests.
var pathOwnerFn = pathOwner

// legacyShareUser derives a pre-share-list install's user from what that install already
// stores: the owner of the config the unit runs (a project install's config is the installing
// user's own file), then the owner of the home the unit was installed with (macOS keeps the
// invoking user's HOME under sudo, and the unit bakes it in). Root, SYSTEM, the Administrators
// group and the overflow uid name nobody and are skipped. Whoever owns either of these already
// decides what this service does and as which identity, so sharing its proxy with them grants
// nothing they did not have.
func legacyShareUser(configFile string) (shareUser, string, bool) {
	home := installHomeFn()
	for _, c := range []struct{ path, what string }{
		{configFile, "the owner of its config " + configFile},
		{home, "the owner of the home it was installed with, " + home},
	} {
		if strings.TrimSpace(c.path) == "" {
			continue
		}
		id, name, ok := pathOwnerFn(c.path)
		if !ok || id == peerid.Unknown || peerid.Privileged(id) {
			continue
		}
		return shareUser{Name: name, ID: string(id)}, c.what, true
	}
	return shareUser{}, "", false
}

// adoptedShare is who a running root service shares its proxy with, and why, published for
// `whisper service status` beside the session records in the host registry. The service's own
// config may not be readable by the user asking (a host install's is root's), so the running
// daemon says it itself. It names users, never a credential.
type adoptedShare struct {
	Users  []shareUser `json:"users"`
	From   string      `json:"from,omitempty"`
	Source string      `json:"source"`
}

// Where a running service's share list came from.
const (
	shareFromConfig = "config"  // the config's own share section
	shareAdopted    = "adopted" // derived on upgrade from the installing account
	shareNone       = "none"    // a pre-share-list install that records no account
)

const adoptedShareName = "service-share.info"

func writeAdoptedShare(a adoptedShare) {
	dir := machineSessionsDirFn()
	if strings.TrimSpace(dir) == "" || os.MkdirAll(dir, 0o755) != nil || hardenSessionsDir(dir, true) != nil {
		return
	}
	if b, err := json.Marshal(a); err == nil {
		_ = writeFileAtomic(filepath.Join(dir, adoptedShareName), b, 0o644)
	}
}

func removeAdoptedShare() {
	if dir := machineSessionsDirFn(); strings.TrimSpace(dir) != "" {
		_ = os.Remove(filepath.Join(dir, adoptedShareName))
	}
}

// readAdoptedShare reads what a running pre-share-list service adopted, trusted like a record.
func readAdoptedShare() (adoptedShare, bool) {
	dir := machineSessionsDirFn()
	if strings.TrimSpace(dir) == "" {
		return adoptedShare{}, false
	}
	b, ok := readTrustedRecord(dir, filepath.Join(dir, adoptedShareName))
	if !ok {
		return adoptedShare{}, false
	}
	var a adoptedShare
	if json.Unmarshal(b, &a) != nil {
		return adoptedShare{}, false
	}
	if a.Source == "" && len(a.Users) > 0 {
		a.Source = shareAdopted
	}
	return a, a.Source != ""
}
