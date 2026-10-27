// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// The dashboard's fleet comes from a listing of the account. A listing that did not answer is
// an error the dashboard shows, never an empty fleet.
func TestLoadFleetIsAnErrorOnAListingThatDidNotAnswer(t *testing.T) {
	for _, f := range testenv.ListingFailures() {
		t.Run(f.Name, func(t *testing.T) {
			url := "http://127.0.0.1:1"
			if f.Serve != nil {
				srv := httptest.NewServer(http.HandlerFunc(f.Serve))
				t.Cleanup(srv.Close)
				url = srv.URL
			}
			c := client.New(client.Config{ControlURL: url, Timeout: 400 * time.Millisecond,
				Cred: client.Credential{Value: "whisper-0000000000000000"}})
			if msg := loadFleet(c)().(fleetMsg); msg.err == nil {
				t.Fatalf("a listing that did not answer must be an error, got a fleet of %d", len(msg.agents))
			}
		})
	}
	t.Run("empty", func(t *testing.T) {
		c, _ := deepentui_control(t, 200, deepentui_env(`"kind","item"`, ``))
		if msg := loadFleet(c)().(fleetMsg); msg.err != nil || len(msg.agents) != 0 {
			t.Fatalf("an empty account is an empty fleet, got %v %v", msg.agents, msg.err)
		}
	})
	t.Run("listed", func(t *testing.T) {
		c, _ := deepentui_control(t, 200, deepentui_env(`"kind","item"`,
			`["agent",{"agent":"scout","address":"2a04:2a01::1"}]`))
		if msg := loadFleet(c)().(fleetMsg); msg.err != nil || len(msg.agents) != 1 {
			t.Fatalf("the listed agent is the fleet, got %v %v", msg.agents, msg.err)
		}
	})
}
