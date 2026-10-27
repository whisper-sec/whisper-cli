// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"fmt"
	"net/netip"
)

// HeldError says the agent is held by another command, and by which process when that is known.
type HeldError struct {
	Addr      netip.Addr
	PID       int  // the enforced run's pid, or 0 when the holder is one or more connects
	Exclusive bool // true when an enforced run holds it
	// Unnamed is set when the refused connect named no agent: the box would have picked one, and an
	// enforced run holds Addr here, so the connect is refused until it says which agent it means.
	Unnamed bool
}

func (e *HeldError) Error() string {
	if e.Unnamed {
		return fmt.Sprintf("this connect names no agent, so the box would pick one, and an enforced run "+
			"(`whisper run --enforce`) holds %s on this host: connecting that agent here would cut the run's "+
			"tunnel. Name the agent with --agent (`whisper list` shows them)", e.Addr)
	}
	if e.Exclusive {
		who := "an enforced run (`whisper run --enforce`)"
		if e.PID > 0 {
			who = fmt.Sprintf("an enforced run (`whisper run --enforce`, pid %d)", e.PID)
		}
		return fmt.Sprintf("agent %s is held by %s on this host, and the box serves one tunnel per agent: "+
			"connecting it here would cut that run's tunnel. Stop that run first, or name another agent with --agent "+
			"(`whisper create <name>` makes one)", e.Addr, who)
	}
	return fmt.Sprintf("agent %s is being served by a running `whisper connect` on this host, and an enforced agent "+
		"needs a tunnel of its own. Stop that connect first, or name another agent with --agent "+
		"(`whisper create <name>` makes one)", e.Addr)
}
