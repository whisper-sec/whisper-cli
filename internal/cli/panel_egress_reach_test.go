// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// panel_egress_reach_test.go is, asserted.
//
// WHAT WENT WRONG. `whisper panel status --json` reported egress.proxy_apps in-force, with the
// agent's own /128 as the observed source, beside a healthy tunnel. Measured on that same host
// at that same moment, through the same local proxy:
//
//	rdap.whisper.online/egress-ip (ours)        200, and the source it saw was that /128
//	news.ycombinator.com (on the allow list)    200
//	api.openai.com (on the allow list)          421 - reached
//	raw.githubusercontent.com (on the list)     301 - reached
//	www.google.com (NOT on the list)            refused, SOCKS reply 5
//	example.com (NOT on the list)               refused, SOCKS reply 5
//
// The tenant policy was `default block` with three allowed names. Nothing was broken: the
// tunnel was up, the identity was right, the policy was doing what it was told. The defect was
// that the ONE destination the panel probed was ours, so it could not tell "this egress carries
// traffic" from "this egress carries traffic to Whisper and nothing else", and it drew a
// confident green over a machine that could barely reach the internet.
//
// The tests below pin the distinction and, just as importantly, its limits: a probe that failed
// with no control behind it is not evidence of a block, and a timeout is not a refusal.

// panelReachAddr stands in for the agent /128 in the measurement above. A fabricated address in
// the same range, because a fixture never needs to name a real agent on a real machine.
const panelReachAddr = "2a04:2a01:9::b3cd"

// --- 1. the verdict, every branch --------------------------------------------------------------

func TestPanelEgressVerdict(t *testing.T) {
	cases := []struct {
		name     string
		observed string
		direct   string
		reach    panelReach
		want     string
		must     []string
		mustNot  []string
	}{
		{
			name:     "carrying, and it reaches the wider internet",
			observed: panelReachAddr,
			reach:    panelReach{Host: "example.com", Tried: true, ProxiedOK: true, DirectOK: true},
			want:     panelInForce,
			must:     []string{panelReachAddr, "example.com"},
		},
		{
			name:     "carrying, but the outside destination was refused while the control answered",
			observed: panelReachAddr,
			reach:    panelReach{Host: "example.com", Tried: true, DirectOK: true},
			want:     panelPolicyLimited,
			// It must say the tunnel is fine, name what was refused, and send the person to the
			// place that actually decides it.
			must: []string{"tunnel is up", "example.com", "whisper policy", panelReachAddr},
			// And it must NOT read as a broken connection: `whisper connect` is the remedy for a
			// dead tunnel, and offering it here sends somebody to reconnect a working one.
			mustNot: []string{"whisper connect"},
		},
		{
			name:     "carrying, and the outside destination timed out: not a refusal, so not a finding",
			observed: panelReachAddr,
			reach:    panelReach{Host: "example.com", Tried: true, DirectOK: true, ProxiedTimedOut: true},
			want:     panelUnknown,
			must:     []string{"timed out", "not known"},
		},
		{
			name:     "carrying, and the destination answered neither way: about the destination, not the egress",
			observed: panelReachAddr,
			reach:    panelReach{Host: "example.com", Tried: true},
			want:     panelUnknown,
			must:     []string{"not known", "example.com"},
		},
		{
			name:     "carrying, and nothing was measured: an unasked question is not a green tick",
			observed: panelReachAddr,
			reach:    panelReach{},
			want:     panelUnknown,
			must:     []string{"not checked"},
		},
		{
			name:     "leaking: the source was this machine's own address, whatever the reach probe says",
			observed: "203.0.113.9",
			direct:   "203.0.113.9",
			reach:    panelReach{Host: "example.com", Tried: true, ProxiedOK: true, DirectOK: true},
			want:     panelNotInForce,
			must:     []string{"this machine's own address"},
		},
		{
			name:     "a third address: still not in force, and the reach probe does not soften it",
			observed: "2a04:2a01:9::dead",
			direct:   "203.0.113.9",
			reach:    panelReach{Host: "example.com", Tried: true, ProxiedOK: true, DirectOK: true},
			want:     panelNotInForce,
			must:     []string{"not this agent's address"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := panelProxyAppsVerdict(panelReachAddr, tc.observed, tc.direct, tc.reach)
			if got.State != tc.want {
				t.Fatalf("state = %q, want %q (detail: %s)", got.State, tc.want, got.Detail)
			}
			if got.Observed != tc.observed {
				t.Fatalf("the observed address must survive every branch, got %q", got.Observed)
			}
			for _, want := range tc.must {
				if !strings.Contains(got.Detail, want) {
					t.Fatalf("the detail must contain %q, got %q", want, got.Detail)
				}
			}
			for _, never := range tc.mustNot {
				if strings.Contains(got.Detail, never) {
					t.Fatalf("the detail must NOT contain %q, got %q", never, got.Detail)
				}
			}
			if got.Detail == "" {
				t.Fatal("every state says why; a bare word is not an answer")
			}
		})
	}
}

// TestPanelEgressInForceOnlyWhenSomethingOutsideAnswered is the spanning assertion, and it is
// the one that would have caught the original defect. Whatever the other fields say, a green
// tick is reachable ONLY from a proxied request to a destination that is not ours coming back.
func TestPanelEgressInForceOnlyWhenSomethingOutsideAnswered(t *testing.T) {
	for _, tried := range []bool{false, true} {
		for _, proxiedOK := range []bool{false, true} {
			for _, directOK := range []bool{false, true} {
				for _, timedOut := range []bool{false, true} {
					r := panelReach{Host: "example.com", Tried: tried,
						ProxiedOK: proxiedOK, DirectOK: directOK, ProxiedTimedOut: timedOut}
					got := panelEgressCarrying(panelReachAddr, r)
					wantGreen := tried && proxiedOK
					if (got.State == panelInForce) != wantGreen {
						t.Fatalf("%+v gave state %q; in-force must mean, and only mean, that a "+
							"destination outside Whisper answered through the egress", r, got.State)
					}
				}
			}
		}
	}
}

// --- 2. the wiring: the panel document, produced by the real command ---------------------------

// panelEchoProxy stands in for the live local egress proxy. Anything routed through it is
// answered with the keyless echo body, so the panel learns the address traffic left from exactly
// the way it does in production (an http:// echo target sent via a proxy arrives as an
// absolute-URI request, which is what makes this a real proxy round trip and not a stub).
func panelEchoProxy(t *testing.T, ip string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ip":"`+ip+`"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// panelEgressDoc runs the REAL command against a live-looking session whose proxy answers the
// echo with addr, with reach as the scripted second observation. It returns the
// egress.proxy_apps block the command produced, and the sessions the reachability leg was asked
// about - which is how a test proves the leg is wired in at all rather than dead code.
//
// The stub is installed AFTER panelIsolation on purpose: isolation resets this seam, so a stub
// placed before it would be quietly thrown away.
func panelEgressDoc(t *testing.T, addr string, reach panelReach) (map[string]any, *[]statusSession) {
	t.Helper()
	dir := panelIsolation(t)
	asked := panelStubReach(t, reach)
	panelStubSensor(t, "running", "")
	stubProbe(t, true, nil)
	proxy := panelEchoProxy(t, addr)
	writeSessionRecord(ownedSession(addr, proxy.URL, "socks5"))

	// The echo target is a name that does not resolve, so the DIRECT leg cannot answer and the
	// only address in the document is the one that came back THROUGH the proxy.
	doc, raw := panelStatusJSON(t, dir, "--echo-url", "http://echo-target.invalid/egress-ip")
	t.Logf("panel document: %s", raw)
	return panelSub(t, doc, "egress", "proxy_apps"), asked
}

// TestPanelStatus_APolicyBlockedEgressIsNotDrawnAsWorking is the defect itself, end to end
// through `whisper panel status --json`: the echo comes back as the agent's own /128 and the
// outside destination is refused while the control answers.
func TestPanelStatus_APolicyBlockedEgressIsNotDrawnAsWorking(t *testing.T) {
	apps, asked := panelEgressDoc(t, panelReachAddr,
		panelReach{Host: "example.com", Tried: true, DirectOK: true})

	if apps["state"] == panelInForce {
		t.Fatal("an egress that reaches Whisper and nothing else was drawn as in force")
	}
	if apps["state"] != panelPolicyLimited {
		t.Fatalf("state = %v, want %q", apps["state"], panelPolicyLimited)
	}
	if apps["observed"] != panelReachAddr {
		t.Fatalf("the observed address must still be reported, got %v", apps["observed"])
	}
	detail, _ := apps["detail"].(string)
	if !strings.Contains(detail, "whisper policy") {
		t.Fatalf("the detail must send the person to the policy, got %q", detail)
	}
	if strings.Contains(detail, "whisper connect") {
		t.Fatalf("the detail blames the connection for a policy decision, got %q", detail)
	}
	// The leg must actually have been consulted about THIS session. Without this, deleting the
	// call and hard-coding the answer would still pass everything above.
	if len(*asked) != 1 || (*asked)[0].Address != panelReachAddr {
		t.Fatalf("the reachability leg was not asked about the live session: %+v", *asked)
	}
}

// TestPanelStatus_AnEgressThatReachesTheInternetIsInForce is the control. Without it an
// implementation that answered "policy-limited" to everything would pass the test above.
func TestPanelStatus_AnEgressThatReachesTheInternetIsInForce(t *testing.T) {
	apps, _ := panelEgressDoc(t, panelReachAddr,
		panelReach{Host: "example.com", Tried: true, ProxiedOK: true, DirectOK: true})

	if apps["state"] != panelInForce {
		t.Fatalf("state = %v, want %q (detail: %v)", apps["state"], panelInForce, apps["detail"])
	}
	if detail, _ := apps["detail"].(string); !strings.Contains(detail, "example.com") {
		t.Fatalf("the in-force detail must name what it reached, got %q", detail)
	}
}

// TestPanelStatus_AFailedEchoIsUnknownEvenWhenTheOutsideProbeWasRefused. The address leg is what
// establishes there is anything to say at all. If the echo through the proxy failed, we do not
// know where traffic is leaving from, and a refused reachability probe must not be promoted into
// a finding about a policy on a session we could not read.
func TestPanelStatus_AFailedEchoIsUnknownEvenWhenTheOutsideProbeWasRefused(t *testing.T) {
	dir := panelIsolation(t)
	panelStubReach(t, panelReach{Host: "example.com", Tried: true, DirectOK: true})
	panelStubSensor(t, "running", "")
	stubProbe(t, true, nil)
	// A session whose local proxy the registry probe accepts but which nothing is really
	// serving: the echo through it cannot complete.
	writeSessionRecord(ownedSession(panelReachAddr, "socks5h://127.0.0.1:41080", "socks5"))

	doc, raw := panelStatusJSON(t, dir)

	apps := panelSub(t, doc, "egress", "proxy_apps")
	if apps["state"] != panelUnknown {
		t.Fatalf("a failed echo must stay %q, got %v (%s)", panelUnknown, apps["state"], raw)
	}
}

// --- 3. the cache, which is the only reason this is cheap enough to run on a poll --------------

// TestPanelReachCacheIsReusedOnlyForTheSameSessionAndDestination. A remembered answer is a claim
// about a moment, a session and a host. Reusing one across any of those is how a cache turns
// into a lie.
func TestPanelReachCacheIsReusedOnlyForTheSameSessionAndDestination(t *testing.T) {
	panelIsolation(t)
	sess := statusSession{Endpoint: "socks5h://127.0.0.1:41080", Address: panelReachAddr, Port: 41080}
	stored := panelReach{Host: client.ReachURLHost(), Tried: true, ProxiedOK: true, DirectOK: true}
	writePanelReachCache(sess, stored)

	got, ok := readPanelReachCache(sess)
	if !ok || got != stored {
		t.Fatalf("a fresh record for this session must be reused, got %+v ok=%v", got, ok)
	}

	other := statusSession{Endpoint: "socks5h://127.0.0.1:9999", Address: panelReachAddr, Port: 9999}
	if _, ok := readPanelReachCache(other); ok {
		t.Fatal("a record taken against another session must not be reused")
	}
	otherAddr := statusSession{Endpoint: sess.Endpoint, Address: "2a04:2a01:9::abcd", Port: 41080}
	if _, ok := readPanelReachCache(otherAddr); ok {
		t.Fatal("a record taken against another agent must not be reused")
	}

	// A repointed destination is a different question, so the old answer must not answer it.
	t.Setenv(client.ReachURLEnv, "https://elsewhere.invalid/")
	if _, ok := readPanelReachCache(sess); ok {
		t.Fatal("a record about another destination must not be reused")
	}
}

// TestPanelReachCacheExpires: a verdict older than the TTL is not this minute's answer, and a
// panel that showed one would be reporting a policy that may have changed since.
func TestPanelReachCacheExpires(t *testing.T) {
	panelIsolation(t)
	sess := statusSession{Endpoint: "socks5h://127.0.0.1:41080", Address: panelReachAddr, Port: 41080}

	stale := panelReachRecord{
		panelReach: panelReach{Host: client.ReachURLHost(), Tried: true, ProxiedOK: true},
		CheckedAt:  time.Now().UTC().Add(-2 * panelReachTTL).Format(time.RFC3339),
		Endpoint:   sess.Endpoint,
		Address:    sess.Address,
	}
	raw, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(strings.TrimSuffix(panelReachCachePath(), "/egress-reach.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(panelReachCachePath(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readPanelReachCache(sess); ok {
		t.Fatal("a record older than the TTL must be measured again, not shown")
	}

	// The control: the same record, taken now, IS reused. Without it the assertion above would
	// be satisfied by a cache that never returns anything.
	writePanelReachCache(sess, panelReach{Host: client.ReachURLHost(), Tried: true, ProxiedOK: true})
	if _, ok := readPanelReachCache(sess); !ok {
		t.Fatal("a record taken now must be reusable, or the cache is doing nothing at all")
	}
}

// TestPanelReachFromKeepsTheDestinationAndDropsTheError bridges the client's pair of
// observations to the record this document carries. The errors are deliberately NOT carried: a
// transport failure through a SOCKS proxy names the local proxy's port, and nothing here may.
func TestPanelReachFromKeepsTheDestinationAndDropsTheError(t *testing.T) {
	got := panelReachFrom(client.OutsideReach{
		Host: "example.com", Tried: true,
		Proxied: os.ErrDeadlineExceeded, Direct: nil, ProxiedTimedOut: true,
	})
	want := panelReach{Host: "example.com", Tried: true, ProxiedOK: false, DirectOK: true, ProxiedTimedOut: true}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// Nothing measured means nothing claimed, in both directions.
	if got := panelReachFrom(client.OutsideReach{Host: "example.com"}); got.ProxiedOK || got.DirectOK || got.Tried {
		t.Fatalf("an unmeasured pair must claim nothing, got %+v", got)
	}
}
