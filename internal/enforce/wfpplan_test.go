// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import "testing"

func TestAgentPlanPermitsOnlyTheProxy(t *testing.T) {
	plan, err := AgentPlan(41234)
	if err != nil {
		t.Fatal(err)
	}
	var permits []FilterSpec
	blocked := map[Layer]bool{}
	for _, f := range plan {
		if f.Who != WhoAgent {
			t.Fatalf("%q matches %v: every per-run filter must match the agent's logon SID only", f.Name, f.Who)
		}
		if f.Permit {
			permits = append(permits, f)
			continue
		}
		if f.Proto != 0 || f.RemotePort != 0 || f.RemoteV4Loopback || f.HasICMPType {
			t.Fatalf("block %q carries a condition, so something it does not name would pass: %+v", f.Name, f)
		}
		blocked[f.Layer] = true
	}
	if len(permits) != 1 {
		t.Fatalf("want exactly one permit (the proxy), got %d: %+v", len(permits), permits)
	}
	p := permits[0]
	if p.Layer != LayerConnectV4 || p.Proto != 6 || !p.RemoteV4Loopback || p.RemotePort != 41234 {
		t.Fatalf("the permit must be TCP to 127.0.0.1:41234 at connect v4, got %+v", p)
	}
	for _, l := range []Layer{LayerConnectV4, LayerConnectV6, LayerRecvAcceptV4, LayerRecvAcceptV6} {
		if !blocked[l] {
			t.Fatalf("no block at %v: that family or direction would be open", l)
		}
	}
	for _, f := range plan {
		if !f.Permit && f.Weight >= p.Weight {
			t.Fatalf("block %q (weight %d) would outrank the permit (weight %d)", f.Name, f.Weight, p.Weight)
		}
	}
}

func TestAgentPlanRefusesAZeroPort(t *testing.T) {
	if _, err := AgentPlan(0); err == nil {
		t.Fatal("a plan with no proxy port must be refused, not built with a permit on port 0")
	}
}

func TestHostICMPPlanIsEchoRequestFromSystemOnly(t *testing.T) {
	plan := HostICMPPlan()
	if len(plan) != 2 {
		t.Fatalf("want one filter per family, got %d", len(plan))
	}
	want := map[Layer][2]uint8{LayerConnectV4: {1, 8}, LayerConnectV6: {58, 128}}
	for _, f := range plan {
		w, ok := want[f.Layer]
		if !ok || f.Permit || f.Who != WhoSystem || f.Proto != w[0] || !f.HasICMPType || f.ICMPType != w[1] {
			t.Fatalf("host ICMP filter must refuse only echo requests sent as SYSTEM, got %+v", f)
		}
		delete(want, f.Layer)
	}
}

func TestRunTagRoundTrips(t *testing.T) {
	tag := RunTag{PID: 4242, Created: 133456789012345678}
	got, ok := ParseRunTag(tag.String())
	if !ok || got != tag {
		t.Fatalf("round trip: %v %v", got, ok)
	}
}

func TestParseRunTagRejectsForeignDescriptions(t *testing.T) {
	for _, d := range []string{
		"", "WireGuard filter", "whisper-enforce ", "whisper-enforce pid=0 created=1",
		"whisper-enforce pid=12", "whisper-enforce pid=x created=1", "whisper-enforce pid=1 created=1 extra=2",
		"whisper-enforce pid=99999999999 created=1",
	} {
		if _, ok := ParseRunTag(d); ok {
			t.Fatalf("%q must not parse as one of our run tags", d)
		}
	}
}
