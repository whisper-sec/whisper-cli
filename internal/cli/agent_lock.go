// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/enforce"
)

// lockAgentForConnect takes the shared per-/128 lock a `whisper connect` holds while it serves an
// agent, so it refuses up front instead of replacing the peer of an enforced run of the same
// agent at the box. A selector that is not a /128 yet returns (nil, nil): the caller locks the
// session's address once op:connect has named it. Nothing to coordinate with is not a refusal.
func lockAgentForConnect(addr string) (*enforce.AgentLock, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return nil, nil
	}
	l, err := enforce.LockShared(a)
	if err != nil {
		var held *enforce.HeldError
		if errors.As(err, &held) {
			return nil, usageErr("%s", held.Error())
		}
		// A lock directory this account cannot trust or read is not a reason to refuse a connect:
		// the box still serves one peer per /128, and an enforced run fails closed if it loses it.
		debugf("agent lock unavailable (%v); connecting without it", err)
		return nil, nil
	}
	return l, nil
}

// opConnect is the one way this CLI asks the box for a session. The enforced-run check itself lives in
// client.Agents, so the TUI and the MCP tools make it too; here its refusal becomes a usage error
// (exit 2) with the same words a connect's own lock gives.
func opConnect(cx context.Context, c *client.Client, args map[string]any) (*client.Envelope, error) {
	env, err := c.Agents(cx, "connect", args)
	var held *enforce.HeldError
	if errors.As(err, &held) {
		return nil, usageErr("%s", held.Error())
	}
	return env, err
}
