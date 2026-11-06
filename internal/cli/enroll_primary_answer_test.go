// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// When the replication primary did not answer whole, a registration comes back as a retryable 503
// PRIMARY_UNREACHABLE whose message says to retry the same request unchanged (and, when the primary already holds
// the agent, names it). enroll must treat it as worth another look, as possibly having changed something, and
// must keep the server's own advice in what it shows, never a bare status.
func TestEnrollRegisterRefusalKeepsThePrimarysRetryAdvice(t *testing.T) {
	for name, msg := range map[string]string{
		"reply incomplete": "The replication primary took the request but its answer did not arrive whole, so" +
			" whether the change was applied is not known here; nothing was changed on this node. Retry the same" +
			" request unchanged shortly: an identical register or identity call is recognised and never created twice",
		"primary holds it": "An identical registration is already recorded as agent ag_agent_7, but the" +
			" replication primary did not answer, so its result (with the api_key) cannot be returned from here." +
			" Retry the same request unchanged shortly to receive it: the primary keeps it for about ten minutes." +
			" After that, use op:list to find agent ag_agent_7",
	} {
		t.Run(name, func(t *testing.T) {
			r := registerRefusal(&client.ProblemError{Status: 503, Title: "PRIMARY_UNREACHABLE", Detail: msg}, "box")
			if r.Class != refuseRetryable || !r.MaybeChanged || r.Code != "PRIMARY_UNREACHABLE" {
				t.Fatalf("want a retryable, maybe-changed PRIMARY_UNREACHABLE, got %+v", r)
			}
			if !strings.Contains(r.Reason, "Retry the same request unchanged") {
				t.Fatalf("the server's retry advice must reach the person, got %q", r.Reason)
			}
		})
	}
}

// The plain renderer too: every 503 used to read "Whisper is busy right now", which dropped the advice to retry
// unchanged. A PRIMARY_UNREACHABLE keeps its own sentence; any other 503 is still the busy line.
func TestFriendlyKeepsThePrimarysOwnSentenceAndOther503sStayBusy(t *testing.T) {
	own := "Replication primary unreachable; the zone-authoring change was NOT applied (a secondary never authors" +
		" the replicated zone), retry shortly"
	if got := friendly(&client.ProblemError{Status: 503, Title: "PRIMARY_UNREACHABLE", Detail: own}); got != own {
		t.Fatalf("PRIMARY_UNREACHABLE must keep its own sentence, got %q", got)
	}
	if got := friendly(&client.ProblemError{Status: 503, Title: "GRAPH_BUSY", Detail: "x"}); !strings.Contains(got, "busy") {
		t.Fatalf("another 503 keeps the busy line, got %q", got)
	}
}
