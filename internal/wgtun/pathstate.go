// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
}

// PathStateRecord is one node's published path table.
type PathStateRecord struct {
	Address string           `json:"address"`
	PID     int              `json:"pid"`
	Updated time.Time        `json:"updated"`
	Peers   []PathPeerRecord `json:"peers"`

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

// publishPaths writes this node's path table, if it has changed or the heartbeat is due.
//
// Called from the health monitor after each reconcile, which is deliberate: the monitor is the
// one place that has just read the device, so the record can only ever describe an observation
// rather than an intention. It is best-effort throughout - a filesystem that will not take the
// write costs a diagnostic, never a path.
func (t *Tunnel) publishPaths() {
	dir := t.pathStateDir()
	if dir == "" {
		return
	}
	peers := t.DirectPeers()
	healthy := t.Healthy()
	rec := PathStateRecord{
		Address:       t.cfg.Address.String(),
		PID:           os.Getpid(),
		Updated:       time.Now(),
		TunnelHealthy: &healthy,
		Reconnects:    t.Reconnects(),
		Peers:         make([]PathPeerRecord, 0, len(peers)),
	}
	for _, p := range peers {
		rec.Peers = append(rec.Peers, PathPeerRecord{
			Address:  p.Address.String(),
			Name:     p.Name,
			Path:     p.Path,
			Endpoint: p.Endpoint,
			Promoted: p.Promoted,
			LastSeen: p.LastSeen,
			Punch: PathPunchRecord{
				Phase:        string(p.Punch.Phase),
				Attempts:     p.Punch.Attempts,
				Trains:       p.Punch.Trains,
				Candidates:   p.Punch.Candidates,
				Trying:       p.Punch.Trying,
				Winner:       p.Punch.Winner,
				WinnerSource: string(p.Punch.WinnerSource),
				Since:        p.Punch.Since,
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
	if !unchanged {
		t.pathFP, t.pathAt = fp, rec.Updated
	}
	t.mu.Unlock()
	if unchanged {
		return
	}

	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	_ = writePathRecord(pathRecordPath(dir, rec.Address), append(b, '\n'))
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
	_ = os.Remove(path)
}

// pathFingerprint is the part of a record that a reader would notice changing: which peers there
// are, what path each one is on, through what, and how the punch ended. Counters and timestamps
// are excluded on purpose (see publishPaths).
func pathFingerprint(rec PathStateRecord) string {
	var b strings.Builder
	for _, p := range rec.Peers {
		fmt.Fprintf(&b, "%s|%s|%s|%t|%s|%s\n",
			p.Address, p.Path, p.Endpoint, p.Promoted, p.Punch.Phase, p.Punch.Winner)
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
