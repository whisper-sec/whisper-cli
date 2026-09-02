// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// --- wiring: the anti-unreachable gate ------------------------------------------------

func TestWhaleRouteIsReachableFromTheRoot(t *testing.T) {
	route := whaleSubcommand(t, "whale", "route")
	if route.Short == "" || route.Long == "" {
		t.Fatal("`whisper whale route` ships with no help text")
	}
	for _, sub := range []string{"list", "advertise"} {
		c := whaleSubcommand(t, "whale", "route", sub)
		if c.RunE == nil {
			t.Fatalf("`whisper whale route %s` has no RunE, so it does nothing", sub)
		}
	}
}

// A Tailscale migrant types the flag name they know. The verb has to exist for them to
// land anywhere but "unknown command".
func TestWhaleRouteAdvertiseTakesArguments(t *testing.T) {
	c := whaleSubcommand(t, "whale", "route", "advertise")
	if err := c.Args(c, nil); err == nil {
		t.Fatal("advertise with no prefix must be a usage error, not a silent success")
	}
	if err := c.Args(c, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("advertise with one prefix: %v", err)
	}
}

// --- route list ------------------------------------------------------------------------

func TestRouteListDisconnectedRoutesNothing(t *testing.T) {
	v := buildWhaleRouteView(nil)
	if v.Connected {
		t.Fatal("connected with no sessions")
	}
	if len(v.Captured) != 0 {
		t.Fatalf("captured = %v with nothing connected", v.Captured)
	}
	if !strings.Contains(strings.Join(v.Notes, " "), "whisper connect") {
		t.Fatalf("notes = %v, want the remedy named", v.Notes)
	}
}

func TestRouteListConnectedShowsBothDefaultsAndNoAdvertisement(t *testing.T) {
	v := buildWhaleRouteView([]statusSession{{Address: "2a04:2a01:1::a", Tier: "wireguard", Port: 1080}})
	if !v.Connected || v.Tier != "wireguard" {
		t.Fatalf("view = %+v, want a connected wireguard node", v)
	}
	if len(v.Captured) != 2 || v.Captured[0] != "::/0" || v.Captured[1] != "0.0.0.0/0" {
		t.Fatalf("captured = %v, want both default routes", v.Captured)
	}
	if len(v.Advertised) != 0 {
		t.Fatalf("advertised = %v; nothing can be advertised in this build", v.Advertised)
	}
	if v.Support.Supported {
		t.Fatal("support reports advertising is possible; it is not")
	}
}

// The JSON shape must never carry a nil where a list belongs: a consumer reading null as
// "unknown" and [] as "none" is reading two different things.
func TestRouteListEmitsEmptyListsNotNull(t *testing.T) {
	v := buildWhaleRouteView(nil)
	if v.Captured == nil || v.Advertised == nil {
		t.Fatal("captured/advertised are nil; they must serialise as [] not null")
	}
}

// --- the refusal ---------------------------------------------------------------------

func TestAdvertiseRefusalNamesThePrefixAndBothBlockers(t *testing.T) {
	routes, err := whale.ParseRoutes([]string{"192.168.10.0/24"})
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	msg := whaleAdvertiseRefusal(routes, whale.SupportForRoutes("wireguard"))
	for _, want := range []string{"192.168.10.0/24", "direct node-to-node path", "kernel tier", "NO_PROXY"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refusal is missing %q:\n%s", want, msg)
		}
	}
}

// Private space is refused permanently, not "for now", and the sentence has to say which.
// Getting this wrong sends someone away expecting a release that is never coming.
func TestAdvertiseRefusalDistinguishesPrivateSpace(t *testing.T) {
	priv, _ := whale.ParseRoutes([]string{"10.0.0.0/8"})
	glob, _ := whale.ParseRoutes([]string{"2001:db8:1::/48"})
	sup := whale.SupportForRoutes("kernel")
	if !strings.Contains(whaleAdvertiseRefusal(priv, sup), "permanently") {
		t.Fatal("a private prefix must be told its constraint is permanent")
	}
	if strings.Contains(whaleAdvertiseRefusal(glob, sup), "permanently") {
		t.Fatal("a globally unique prefix must not be told its constraint is permanent")
	}
}

func TestAdvertiseRefusalHandlesSeveralPrefixes(t *testing.T) {
	routes, err := whale.ParseRoutes([]string{"192.168.1.0/24,192.168.2.0/24"})
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	msg := whaleAdvertiseRefusal(routes, whale.SupportForRoutes(""))
	if !strings.Contains(msg, "192.168.1.0/24, 192.168.2.0/24") || !strings.Contains(msg, "are valid") {
		t.Fatalf("refusal reads wrong for a list:\n%s", msg)
	}
}
