// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package projcfg

import (
	"hash/fnv"
	"net"
	"strconv"
)

// The deterministic-port window. We hash the project's absolute path into [portBase, portBase
// +portSpan) — a high, unprivileged, IANA-ephemeral-adjacent range unlikely to clash with a
// well-known service. SAME project path ⇒ SAME base port across every run and machine layout,
// so a re-init / re-ensure binds the identical 127.0.0.1:<port> Claude Code's settings point
// at; DIFFERENT projects hash to different bases, so two projects' daemons don't collide.
const (
	portBase = 20000
	portSpan = 20000 // ⇒ ports in [20000, 40000)
)

// portProbeLimit bounds the upward free-port probe so a pathological "everything in the window
// is taken" situation fails fast with a clear error instead of scanning forever.
const portProbeLimit = 256

// BasePort returns the DETERMINISTIC base port for a project's absolute path: an FNV-1a hash
// of the path folded into [portBase, portBase+portSpan). It is pure (no I/O) and stable — the
// same path always yields the same base, on every OS and every run. The caller then probes
// upward from here for the first FREE port (ProbeFreePort) so two projects that happen to hash
// to the same base still get distinct live ports.
func BasePort(projectAbsPath string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(projectAbsPath))
	return portBase + int(h.Sum32()%uint32(portSpan))
}

// portFree reports whether 127.0.0.1:<port> can be bound right now — i.e. nothing is already
// listening there. It is the cheap, race-tolerant probe `connect --ensure` and `init` use:
// a successful Listen (immediately closed) means free; a bind failure means taken. (A taken
// port that is OUR own already-running daemon is detected separately, by an actual handshake
// probe — see the ensure path; this function only answers "is the port bindable".)
func portFree(port int) bool {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// portFreeFn is the bind-probe seam (a package var) so tests can drive the free/taken
// decision deterministically without opening real sockets.
var portFreeFn = portFree

// ProbeFreePort returns the first FREE port at or above BasePort(projectAbsPath), wrapping
// within the window if the tail is congested, and erroring only if the whole probe budget is
// exhausted. This is the "smart, collision-avoiding" port: deterministic when the base is
// free (the overwhelming common case → the same project keeps the same port), and gracefully
// stepping aside when it isn't.
//
// NOTE: a free port here is only a HINT for a FIRST init — between the probe and the daemon's
// own bind another process could grab it (TOCTOU). The daemon's bind is the real authority;
// the persisted port lets a re-ensure reuse OUR own live daemon (probed by handshake), and a
// genuine collision surfaces as a clear "port in use" error, not a silent wrong-proxy.
func ProbeFreePort(projectAbsPath string) (int, error) {
	base := BasePort(projectAbsPath)
	for i := 0; i < portProbeLimit; i++ {
		// Wrap within [portBase, portBase+portSpan) so we never wander into the privileged
		// range or past the window — the probe stays inside the deterministic band.
		port := portBase + ((base - portBase + i) % portSpan)
		if portFreeFn(port) {
			return port, nil
		}
	}
	return 0, errProbeExhausted
}

// errProbeExhausted is returned when the whole probe budget is congested — vanishingly rare,
// but a clear error beats an infinite scan.
var errProbeExhausted = &probeError{}

type probeError struct{}

func (*probeError) Error() string {
	return "could not find a free local port in the 20000-40000 range — close some listeners and retry"
}
