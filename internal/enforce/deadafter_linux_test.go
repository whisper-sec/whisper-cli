// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// The kill switch refuses the agent's connections once the tunnel is called dead. A session the box
// initiated re-keys only on a packet the box receives in [REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT -
// REKEY_TIMEOUT, REJECT_AFTER_TIME); an idle tunnel's 25 s keepalives can step over that window, and
// this node then re-initiates on its first keepalive past REJECT_AFTER_TIME. Until it does, a live
// tunnel reads a handshake past 180 s, and calling that dead refused a working agent.
func TestTheKillSwitchDoesNotRefuseAnIdleSessionTheBoxInitiated(t *testing.T) {
	const keepalive = 25 * time.Second
	band := device.RejectAfterTime - device.KeepaliveTimeout - device.RekeyTimeout
	if band != 165*time.Second {
		t.Fatalf("the box's re-key-on-receipt window opens at %s, not 165 s: the reasoning above is stale", band)
	}
	envelope := device.RejectAfterTime + keepalive + device.RekeyTimeout
	if deadAfter < envelope {
		t.Fatalf("deadAfter = %s refuses a live idle tunnel (its handshake can read up to %s)", deadAfter, envelope)
	}
	if deadAfter > 2*device.RejectAfterTime {
		t.Fatalf("deadAfter = %s lets a dead tunnel hang dials for longer than two session lifetimes", deadAfter)
	}
}
