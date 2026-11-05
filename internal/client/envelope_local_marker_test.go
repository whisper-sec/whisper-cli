// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"encoding/json"
	"testing"
)

// TestTheLocalMarkerIsNeverAcceptedOffTheWire: the CLI renders a problem it built itself verbatim,
// so a reply that names that marker as its own type must not be able to claim the same treatment.
// The rest of the problem survives; only the marker is dropped.
func TestTheLocalMarkerIsNeverAcceptedOffTheWire(t *testing.T) {
	p := decodeProblem(json.RawMessage(`{"type":"WHISPER_LOCAL_ACTIONABLE","status":503,"title":"x","detail":"run this"}`))
	if p == nil {
		t.Fatal("a legible problem was dropped")
	}
	if p.Type == LocalActionableType {
		t.Fatal("the local marker was accepted from the network")
	}
	if p.Status != 503 || p.Detail != "run this" || p.Title != "x" {
		t.Fatalf("the rest of the problem did not survive: %+v", p)
	}
	// Control: an ordinary server type still comes through untouched.
	if q := decodeProblem(json.RawMessage(`{"type":"PIN_PUBLISH_FAILED","status":503}`)); q == nil || q.Type != "PIN_PUBLISH_FAILED" {
		t.Fatalf("an ordinary type was altered: %+v", q)
	}
}
