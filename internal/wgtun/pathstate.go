// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// pathstate.go is how the truth about a path leaves the process that knows it.
//
// The tunnel is held by a long-lived process (`whisper connect`, the ensure daemon, a spawned
// agent). `whisper whale status` and `whisper whale ping` run in a DIFFERENT process, minutes
// later, from another shell. Without something on disk, the only thing those commands can say
// about a path is what the control plane claims about it - and the control plane's claim is a
// candidacy, not an outcome. It cannot know whether the handshake landed, because the handshake
// does not touch a box. That gap is exactly how a surface ends up printing "direct" for a pair
// that has been relaying for an hour.
//
// So the process that holds the device publishes what the DEVICE says, and the surfaces read it.
//
// # It is the session registry's discipline, deliberately
//
// One small JSON record per node /128, under ~/.config/whisper/paths/, 0700 on the directory and
// 0600 on the file, naming the writing pid so a record whose holder has gone is not believed.
// That is the same shape, the same root and the same liveness rule the held-session registry
// already uses, for the same reason. It is a separate directory rather than a field on the
// session record because the two have different lifetimes: a session record is written once at
// bring-up and is immutable, while this one changes every time a path is won or lost.
//
// # No secret is ever written
//
// Overlay addresses, names, underlay endpoints, counters, timestamps. No key, public or private:
// nothing here needs one, and a file nobody needs to protect is a file nobody can leak.
//
// # A stale record is reported as stale, never as absence
//
// If the holder is alive but the record has stopped being updated, something is wrong with the
// monitor, and rendering that as "no direct paths" would turn a fault into a reassuring blank.
// Age is exposed, and the surface says how old it is.

const (
	// pathStateHeartbeat is how often the record is rewritten even when nothing has changed, so a
	// reader can tell a live monitor from a wedged one. Cheap: one small file, twice a minute.
	pathStateHeartbeat = 30 * time.Second

	// PathStateStale is when a reader should stop treating a record as current. Two heartbeats
	// plus a margin: a monitor that has missed two in a row is not merely busy.
	PathStateStale = 90 * time.Second

	// PathStateOff, given as Options.PathStateDir, publishes nothing at all. For a caller that
	// wants a tunnel to leave no trace on the filesystem.
	PathStateOff = "-"
)

// PathPunchRecord is the traversal outcome for one peer, as written to disk. It is PunchInfo
// with the times flattened, so a reader in another process needs no knowledge of this package's
// internals to render it.
type PathPunchRecord struct {
	Phase        string    `json:"phase"`
	Attempts     int       `json:"attempts,omitempty"`
	Trains       int       `json:"trains,omitempty"`
	Candidates   int       `json:"candidates,omitempty"`
	Trying       string    `json:"trying,omitempty"`
	Winner       string    `json:"winner,omitempty"`
	WinnerSource string    `json:"winner_source,omitempty"`
	Since        time.Time `json:"since,omitempty"`
	Timed        bool      `json:"timed,omitempty"`
}

// PathPeerRecord is what this node knows about the path to one peer, from the device itself.
type PathPeerRecord struct {
	Address  string          `json:"address"`
	Name     string          `json:"name,omitempty"`
	Path     string          `json:"path"`
	Endpoint string          `json:"endpoint,omitempty"`
	Promoted bool            `json:"promoted"`
	LastSeen time.Time       `json:"last_seen,omitempty"`
	Punch    PathPunchRecord `json:"punch"`
	// RouteEpoch and RoutedSince name the routed period Promoted belongs to (PeerState.RouteEpoch).
	// Promoted is the device read back, not the tunnel's decision, and a record without an
	// epoch comes from a holder that did not read it back, so a reader must not take its Promoted as a
	// path.
	RouteEpoch  uint64    `json:"route_epoch,omitempty"`
	RoutedSince time.Time `json:"routed_since,omitempty"`
}

// PathStateRecord is one node's published path table.
type PathStateRecord struct {
	Address string           `json:"address"`
	PID     int              `json:"pid"`
	Updated time.Time        `json:"updated"`
	Peers   []PathPeerRecord `json:"peers"`

	// Instance names the tunnel that wrote this record: random, and new for every tunnel, including
	// a renewal inside the same process. Two tunnels for one /128 share the file (it is keyed by
	// address), so a reader comparing two reads (`whale ping`) needs it to know both came from the
	// one tunnel it measured through, and a tunnel going away needs it to remove only its own record.
	Instance string `json:"instance,omitempty"`
	// ProxyPort is the local proxy port of the tunnel that wrote the record, so a reader that measured
	// through a proxy can tell this record is that tunnel's and not another one's for the same address.
	ProxyPort int `json:"proxy_port,omitempty"`

	// TunnelHealthy is the holder's OWN reading of whether the tunnel has handshaked recently.
	//
	// It exists because record freshness answers a different question than anyone reading it
	// assumed. A monitor that is failing to re-handshake is still a monitor that is running, so
	// it keeps republishing on every tick and the record never goes stale. On 2026-09-03 a panel
	// reported `healthy: true` for a session whose own log had reached re-handshake attempt 183
	// and which was carrying no traffic at all. Nothing lied: freshness was being read as health,
	// and those are the liveness of the PUBLISHER and the health of the TUNNEL.
	//
	// A POINTER so that absent and false stay different things. A record written by an older
	// holder has no opinion, and must fall back to the freshness heuristic rather than be read as
	// a confident "unhealthy" that nobody published.
	TunnelHealthy *bool `json:"tunnel_healthy,omitempty"`

	// Reconnects is how many times the monitor has had to re-handshake a dead tunnel. It only
	// grows, so a healthy long-lived tunnel stays at 0 and a flapping one climbs without bound.
	// Published because "healthy right now" and "has failed 183 times in two hours" are both
	// true of a flapping tunnel, and only the second one explains what the user is seeing.
	Reconnects int `json:"reconnects,omitempty"`
}

// TunnelHealth reports the holder's own reading, and whether it published one at all. Callers
// must prefer this to Stale(): freshness says the publisher is alive, not that the tunnel works.
func (r PathStateRecord) TunnelHealth() (healthy bool, published bool) {
	if r.TunnelHealthy == nil {
		return false, false
	}
	return *r.TunnelHealthy, true
}

// Age is how long ago this record was written.
func (r PathStateRecord) Age() time.Duration { return time.Since(r.Updated) }

// Stale reports whether the holder is alive but has stopped updating - a fault, and one a
// surface must say out loud rather than render as an empty peer list.
func (r PathStateRecord) Stale() bool { return r.Age() > PathStateStale }

// PeerFor returns the record for one overlay address, and whether there was one. A peer nothing
// was published about is not an error and not a direct path: it is relayed, which is what the
// box does for every /128 no direct peer holds.
func (r PathStateRecord) PeerFor(address string) (PathPeerRecord, bool) {
	want := strings.TrimSpace(strings.Trim(address, "[]"))
	for _, p := range r.Peers {
		if strings.EqualFold(p.Address, want) {
			return p, true
		}
	}
	return PathPeerRecord{}, false
}

// DefaultPathStateDir is ~/.config/whisper/paths - the same root the held-session registry and
// the serve record use. A home directory we cannot resolve falls back to a relative path rather
// than failing: publishing into the working directory is worse than nothing only if it fails,
// and it does not.
func DefaultPathStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "whisper", "paths")
	}
	return filepath.Join(home, ".config", "whisper", "paths")
}

// pathRecordPath maps a /128 to its record file. Colons are not portable in filenames on
// Windows, so they are flattened here; the address INSIDE the record stays the real literal.
func pathRecordPath(dir, address string) string {
	name := strings.ReplaceAll(strings.TrimSpace(address), ":", "_")
	if name == "" {
		name = "node"
	}
	return filepath.Join(dir, name+".json")
}

// ReadPathStates loads every published record in dir, dropping any whose holding process has
// gone. Unreadable and malformed files are skipped rather than failing the read: a surface that
// refused to say anything because one file was half-written would be worse than one that shows
// the rest. Pass "" for the default directory.
func ReadPathStates(dir string) []PathStateRecord {
	if dir == "" {
		dir = DefaultPathStateDir()
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []PathStateRecord
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			continue
		}
		var rec PathStateRecord
		if json.Unmarshal(b, &rec) != nil || rec.Address == "" {
			continue
		}
		if rec.PID > 0 && !processIsAlive(rec.PID) {
			// The holder is gone, so its claim about a live path describes nothing. Sweep it,
			// the way the session registry sweeps a record whose probe failed.
			_ = os.Remove(filepath.Join(dir, e.Name()))
			continue
		}
		out = append(out, rec)
	}
	return out
}

// ReadPathStateFor is the single-node read a surface actually wants: the record for one /128, or
// (zero, false) when nothing published one.
func ReadPathStateFor(dir, address string) (PathStateRecord, bool) {
	want := strings.TrimSpace(strings.Trim(address, "[]"))
	for _, r := range ReadPathStates(dir) {
		if strings.EqualFold(r.Address, want) {
			return r, true
		}
	}
	return PathStateRecord{}, false
}

// pathStateDir is where this tunnel publishes, or "" when publishing is off.
func (t *Tunnel) pathStateDir() string {
	if t.pathDir == PathStateOff {
		return ""
	}
	if t.pathDir == "" {
		return DefaultPathStateDir()
	}
	return t.pathDir
}

// publishPaths writes this node's path table, if it has changed or the heartbeat is due, and reports
// whether the record on disk now says what the tunnel does (true also when nothing needed writing).
//
// Called from the health monitor after each reconcile, which is deliberate: the monitor is the
// one place that has just read the device, so the record can only ever describe an observation
// rather than an intention. The refresh loop publishes too, before it takes a route away
// (publishBeforeUnroute), so the whole publish runs under pubMu: two snapshots renamed into place
// out of order would leave the older one on disk. It is best-effort throughout - a filesystem that
// will not take the write costs a diagnostic, never a path - and a write that fails is tried again on
// the next call rather than remembered as written. Nothing is published once the tunnel has begun to
// stop (retirePaths).
func (t *Tunnel) publishPaths() bool {
	dir := t.pathStateDir()
	if dir == "" {
		return true
	}
	t.pubMu.Lock()
	defer t.pubMu.Unlock()
	if t.pathsRetired {
		return true
	}
	peers := t.DirectPeers()
	healthy := t.Healthy()
	rec := PathStateRecord{
		Address:       t.cfg.Address.String(),
		PID:           os.Getpid(),
		Instance:      t.instance,
		ProxyPort:     t.proxyPort(),
		Updated:       time.Now(),
		TunnelHealthy: &healthy,
		Reconnects:    t.Reconnects(),
		Peers:         make([]PathPeerRecord, 0, len(peers)),
	}
	for _, p := range peers {
		rec.Peers = append(rec.Peers, PathPeerRecord{
			Address:     p.Address.String(),
			Name:        p.Name,
			Path:        p.Path,
			Endpoint:    p.Endpoint,
			Promoted:    p.Promoted,
			LastSeen:    p.LastSeen,
			RouteEpoch:  p.RouteEpoch,
			RoutedSince: p.RoutedSince,
			Punch: PathPunchRecord{
				Phase:        string(p.Punch.Phase),
				Attempts:     p.Punch.Attempts,
				Trains:       p.Punch.Trains,
				Candidates:   p.Punch.Candidates,
				Trying:       p.Punch.Trying,
				Winner:       p.Punch.Winner,
				WinnerSource: string(p.Punch.WinnerSource),
				Since:        p.Punch.Since,
				Timed:        p.Punch.Timed,
			},
		})
	}
	sortPathPeers(rec.Peers)

	// The fingerprint deliberately excludes Updated and the attempt counters that tick on every
	// round: a record that rewrote itself five times a minute because a counter moved would make
	// the heartbeat meaningless and put a needless write on a loop that runs forever.
	fp := pathFingerprint(rec)
	t.mu.Lock()
	unchanged := fp == t.pathFP && time.Since(t.pathAt) < pathStateHeartbeat
	t.mu.Unlock()
	if unchanged {
		return true
	}

	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return false
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	if err := writeRecordFile(pathRecordPath(dir, rec.Address), append(b, '\n')); err != nil {
		return false
	}
	t.mu.Lock()
	t.pathFP, t.pathAt = fp, rec.Updated
	t.mu.Unlock()
	return true
}

// writeRecordFile is writePathRecord, as a seam so a test can make the write fail.
var writeRecordFile = writePathRecord

// dropPaths removes this tunnel's record, for a publish that could not say what is about to change
// (publishBeforeUnroute): no record is true, a record still claiming a route is not. The fingerprint is
// forgotten, so the next publish writes the record again in full.
func (t *Tunnel) dropPaths() {
	t.pubMu.Lock()
	defer t.pubMu.Unlock()
	t.removeOwnRecord()
	// A record that cannot even be read to check whose it is goes too, here and only here: the write that
	// failed was about to take a route away, and a record still claiming it is worse than a missing one.
	if dir := t.pathStateDir(); dir != "" {
		path := pathRecordPath(dir, t.cfg.Address.String())
		if _, err := os.ReadFile(path); err != nil && !os.IsNotExist(err) {
			_ = os.Remove(path)
		}
	}
	t.mu.Lock()
	t.pathFP, t.pathAt = "", time.Time{}
	t.mu.Unlock()
}

// retirePaths ends publishing for a tunnel that is stopping, and removes its record, BEFORE the device
// closes: a closed device routes nothing, and a record that outlived it would claim a route through a
// tunnel that is gone - to a renewal in the same process, on the same local port, above all.
func (t *Tunnel) retirePaths() {
	t.pubMu.Lock()
	defer t.pubMu.Unlock()
	t.pathsRetired = true
	t.removeOwnRecord()
}

// writePathRecord publishes one record so that a reader never sees a state between two of
// them. That is not a nicety here: the whole point of this file is that the record is read
// from OTHER processes (`whisper whale status`, minutes later, from another shell), so the
// readers are concurrent and unsynchronised by design.
//
// os.WriteFile, which this used to be, opens with O_TRUNC and then writes. Between those two
// steps the file is observably empty, and during the write it is observably a prefix. A reader
// that catches either gets a JSON parse error, and the only thing making that rare is that the
// window is small. It was not rare enough: one loaded `go test ./...` found it.
//
// A rename within a directory is atomic, so the reader gets the whole old record or the whole
// new one. The temp file is a sibling for that reason - a rename across filesystems is a copy,
// which would put the window straight back.
//
// A unique temp name rather than a fixed one, because two live publishers for the same address
// is a state this package already expects (ReadPathStates sweeps records whose PID is dead, so
// it knows a stale holder can still be running). They would interleave on a shared temp name
// and rename something torn into place, which is the defect this function exists to remove.
// The cost is that a process killed between the create and the rename leaves one small file
// behind; readers never see it, because they only read *.json.
func writePathRecord(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".paths-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // a no-op once the rename below has taken it
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	// Sync before the rename: the rename orders the DIRECTORY entry, not the data behind it, so
	// without this a crash can leave the new name pointing at a file with nothing in it yet.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// clearPaths removes this node's record. Called when the monitor exits, which is when the tunnel
// is going away: a record that outlives its tunnel is a claim nothing stands behind. A reader
// would have caught it anyway through the pid, so this is tidiness rather than correctness -
// which is the right level of effort for a teardown that may not get to run at all.
//
// It removes the record only when the pid inside it is OURS. The file is keyed on the
// address alone, so two tunnels for one /128 share it, and an unconditional remove let the
// exiting one delete the survivor's row. That is what the panel then rendered as
// "tunnel": {"known": false, "healthy": false} over a tunnel that was up and carrying traffic.
// A record we cannot read, or one naming another process, is not ours to unlink; the pid sweep
// in ReadPathStates already retires it the moment its holder is gone.
func (t *Tunnel) clearPaths() {
	t.retirePaths()
}

// removeOwnRecord removes the record file when this tunnel wrote it: our pid and our instance. Called
// with pubMu held.
func (t *Tunnel) removeOwnRecord() {
	dir := t.pathStateDir()
	if dir == "" {
		return
	}
	path := pathRecordPath(dir, t.cfg.Address.String())
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var rec PathStateRecord
	if json.Unmarshal(b, &rec) != nil {
		return
	}
	if rec.PID != 0 && rec.PID != os.Getpid() {
		return
	}
	// The same pid is not enough: a renewal in this process writes the same file, and the tunnel it
	// replaced must not remove the new one's record on its way out.
	if rec.Instance != "" && rec.Instance != t.instance {
		return
	}
	_ = os.Remove(path)
}

// pathFingerprint is the part of a record that a reader would notice changing: which peers there
// are, what path each one is on, through what, and how the punch ended. Counters and timestamps
// are excluded on purpose (see publishPaths).
func pathFingerprint(rec PathStateRecord) string {
	var b strings.Builder
	for _, p := range rec.Peers {
		fmt.Fprintf(&b, "%s|%s|%s|%t|%d|%s|%s\n", // the instance is fixed for a tunnel, so not in here
			p.Address, p.Path, p.Endpoint, p.Promoted, p.RouteEpoch, p.Punch.Phase, p.Punch.Winner)
	}
	return b.String()
}

// sortPathPeers keeps the file's peer order stable, so a diff of two records shows what actually
// changed rather than the iteration order of a map.
func sortPathPeers(peers []PathPeerRecord) {
	for i := 1; i < len(peers); i++ {
		for j := i; j > 0 && peers[j].Address < peers[j-1].Address; j-- {
			peers[j], peers[j-1] = peers[j-1], peers[j]
		}
	}
}

// ProcessAlive reports whether pid names a live process, by the same rule the path record uses:
// a pid this user may not signal counts as alive, because calling a live holder dead deletes a
// true record. Exported for the session registry, which has the same question about its holders.
func ProcessAlive(pid int) bool { return processIsAlive(pid) }

// newInstanceID is a tunnel's random name for its record: 64 bits, so two tunnels never share one.
func newInstanceID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// newRouteEpochBase is where a tunnel's routed periods start counting: random, in the low 62 bits so
// the counter cannot wrap, and never zero. A reader compares a routed period between two reads, and a
// renewal in the same process writes the same record file, so a counter that started at one in every
// tunnel would let the new tunnel's first period read as the old one's.
func newRouteEpochBase() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint64(time.Now().UnixNano())>>2 | 1
	}
	return binary.BigEndian.Uint64(b[:])>>2 | 1
}

// proxyPort is the local proxy's port, or 0 when there is none (a tunnel built by a test).
func (t *Tunnel) proxyPort() int {
	if t.proxy == nil {
		return 0
	}
	ap, err := netip.ParseAddrPort(t.proxy.Addr())
	if err != nil {
		return 0
	}
	return int(ap.Port())
}
