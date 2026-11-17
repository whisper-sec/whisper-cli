// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

// ReexecEntry is what this binary runs when it re-executes itself as one of its own helper processes, named by
// argv[1]: the enforced agent's init, or one of the containment's probes. It is nil for any other command line, which
// the command tree takes. The CLI's main dispatches on it before anything else, and the tests hold every helper this
// package starts to an entry here.
func ReexecEntry(args []string) func() {
	if len(args) < 2 {
		return nil
	}
	switch args[1] {
	case InitArg:
		return RunInit
	case ProbeArg:
		return RunProbe
	case PlaceProbeArg:
		return RunPlaceProbe
	}
	return nil
}
