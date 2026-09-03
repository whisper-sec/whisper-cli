// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/observed"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// panel_view.go is the document behind `whisper panel status`: one JSON read of this host,
// assembled from the primitives the rest of the CLI already uses, for the resident panel to
// render.
//
// The panel is a different kind of consumer from every other surface here. Nobody types it. It
// polls, it is glanced at, and whatever it shows is what the person believes about their machine
// until they look again. That raises the cost of one particular mistake to the point where it
// governs the whole file: a leg we could not READ must never be rendered as a leg we read and
// found NEGATIVE. "Stopped" is an answer. "Not connected" is an answer. A probe that timed out is
// not either of them, and a panel that draws a grey dot for both teaches the person to distrust
// the green one.
//
// So every leg here has three outcomes, not two, and the third one is written down:
//
// - the state lands on "unknown" (or the field is simply absent), and
// - the reason lands in `errors`, one line, so the panel can say WHY rather than shrug.
//
// The same rule governs rtt_ms, which is `omitempty` and only ever present when something
// measured it. A zero that renders as "0.0 ms" is a measurement nobody made.
//
// Nothing here is a second source of truth. The connection and tier come from the session
// registry through liveStatusSessions, the fleet from buildWhaleStatus, the sensor from the
// hostSensorStatus seam, verify from the keyless verify-identity endpoint, and the egress proof
// from the same keyless echo `whisper ip` uses. If one of those changes its mind, the panel
// changes with it.

// panelSchema is the document version the app checks before reading anything else. Bump it only
// for a change a reader coded against schema 1 could not survive.
const panelSchema = 1

// The three-valued vocabulary every readable leg uses. "unknown" is a first-class answer here,
// never a synonym for the negative one.
const (
	panelInForce    = "in-force"
	panelNotInForce = "not-in-force"
	panelUnknown    = "unknown"
)

// panelPolicyLimited is the fourth word, and this is the reason it exists.
//
// A tenant whose policy is `default block` with a short allow list has a tunnel that is up,
// bound to the right identity, and carrying traffic - to the handful of names the policy allows
// and to nothing else. Calling that "in force" is a confident green over a machine that can
// barely reach the internet. Calling it "not in force" blames the tunnel for doing exactly what
// it was told. It is neither, so it has its own word, and the sentence beside it points at
// `whisper policy` rather than at the connection.
const panelPolicyLimited = "policy-limited"

// The identity verdict, matching `whisper verify`: verified means the server ran the full chain
// and DANE anchored it; unverified means it ran and did not; unknown means it did not run.
const (
	panelVerified   = "verified"
	panelUnverified = "unverified"
)

// The connection words, kept byte-identical to `whisper status` so the two surfaces can never
// disagree about the same host in the same second.
const (
	panelConnected    = "connected"
	panelNotConnected = "not connected"
)

// panelView is the whole document, and the exact shape the panel is coded against. No key value
// appears anywhere in it, at any depth: `key` carries presence and provenance and nothing else.
type panelView struct {
	Schema      int             `json:"schema"`
	GeneratedAt string          `json:"generated_at"`
	CLIVersion  string          `json:"cli_version"`
	Key         panelKey        `json:"key"`
	Identity    panelIdentity   `json:"identity"`
	Connection  panelConnection `json:"connection"`
	Egress      panelEgress     `json:"egress"`
	Sensor      panelSensor     `json:"sensor"`
	Observed    panelObserved   `json:"observed"`
	Whalenet    panelWhalenet   `json:"whalenet"`
	// Errors is one line per leg that could not be read. It is never null: an empty array is
	// the statement "everything below was actually read", which is a different claim from
	// "there is no errors field here" and the panel is entitled to make it.
	Errors []string `json:"errors"`
}

// panelKey is the key ladder's verdict with the key itself removed. Presence and source are the
// only two facts a panel needs, and they are the only two it can safely be told.
type panelKey struct {
	Present bool   `json:"present"`
	Source  string `json:"source"`
}

// panelIdentity is who this host is on the Whisper network, and how well that stood up to being
// checked. Address is the pinned or live /128; the name, fqdn and tenant come from whatever
// actually named THIS node (the fleet listing, or the keyless verify verdict).
type panelIdentity struct {
	Address string      `json:"address"`
	Name    string      `json:"name"`
	FQDN    string      `json:"fqdn"`
	Tenant  string      `json:"tenant"`
	Verify  panelVerify `json:"verify"`
}

// panelVerify is the keyless identity check. DaneOK is the load-bearing field (a DNSSEC-anchored
// TLSA is the trust anchor for an agent, not a public CA), and it is only meaningful when State
// is verified or unverified: on unknown, nothing checked it and the boolean means nothing.
type panelVerify struct {
	State     string `json:"state"`
	DaneOK    bool   `json:"dane_ok"`
	Detail    string `json:"detail"`
	CheckedAt string `json:"checked_at"`
}

// panelConnection is the live local egress, read from the session registry rather than assumed.
type panelConnection struct {
	State     string      `json:"state"`
	Tier      string      `json:"tier"`
	TierLabel string      `json:"tier_label"`
	Endpoint  string      `json:"endpoint"`
	Port      int         `json:"port"`
	Tunnel    panelTunnel `json:"tunnel"`
}

// panelTunnel is what the process HOLDING the tunnel published about it, which is the only
// honest source: a WireGuard handshake never touches a box and never touches this process, so a
// panel that inferred health from its own reachability would be inventing it. Known:false means
// nothing published a record, and it is deliberately NOT the same as Healthy:false.
type panelTunnel struct {
	Known   bool `json:"known"`
	Healthy bool `json:"healthy"`
	// Reconnects is how many times the holder has had to re-handshake a dead tunnel. Surfaced
	// because a FLAPPING tunnel is healthy at most instants and useless across all of them: the
	// handshake completes, goes idle, completes again, and no data ever crosses. "healthy: true"
	// with a reconnect count in the hundreds is the shape of that, and without the count the
	// reader has no way to tell it from a tunnel that has simply been up all day.
	Reconnects int `json:"reconnects,omitempty"`
}

// panelEgress is the defect this whole command exists to make visible.
//
// `whisper connect` prints a socks5h://127.0.0.1:PORT string. Terminal tools that honour
// ALL_PROXY pick it up and leave from the agent's /128. Safari, Chrome, Mail and every other
// GUI app do not read ALL_PROXY, never saw that string, and keep leaving from the machine's own
// address. The product read as though egress was in force; for the browser it never was. Two
// fields, separately answered, because they genuinely have two different answers.
type panelEgress struct {
	ProxyApps  panelProxyApps  `json:"proxy_apps"`
	SystemApps panelSystemApps `json:"system_apps"`
	// Direct is the address the world sees when this host does NOT go through Whisper. It is
	// what makes the two states above legible: without it, "not in force" is a word, and with
	// it the person can see the address they are actually leaking.
	Direct string `json:"direct"`
}

// panelProxyApps is the ALL_PROXY half, proven with TWO observations through the same proxy: the
// keyless Whisper echo, which says WHICH ADDRESS traffic leaves from, and a cheap HEAD to a
// destination that is not ours, which says WHETHER IT GETS ANYWHERE. State is one of in-force,
// policy-limited, not-in-force or unknown - see panelEgressCarrying for why the third answer had
// to exist.
type panelProxyApps struct {
	State    string `json:"state"`
	Observed string `json:"observed"`
	Detail   string `json:"detail"`
}

// panelSystemApps is the GUI half, plus the machine-readable system-proxy state behind it.
//
// CanEnable and CannotEnableReason are the fix, and they exist because a button is a
// promise. The panel drew "Route Safari and system apps through Whisper" whenever a connection
// was up, and pressing it on an egress that carries IPv6 but not IPv4 took the whole machine off
// the internet. A surface that offers an action it has not checked is offering a coin flip, so
// the same pre-flight the CLI refuses on decides whether the button is drawn at all - and when it
// is not, the reason is drawn in its place, because a control that silently vanishes teaches
// people the app is broken.
//
// PreflightCheckedAt and PreflightAgeSeconds keep the verdict honest under polling. It is cached
// for a minute so a panel that refreshes every few seconds does not make three HTTP requests a
// second, and a cached answer states its age rather than passing for this instant's reading.
type panelSystemApps struct {
	State              string           `json:"state"`
	Detail             string           `json:"detail"`
	SystemProxy        systemProxyState `json:"system_proxy"`
	CanEnable          bool             `json:"can_enable"`
	CannotEnableReason string           `json:"cannot_enable_reason"`
	PreflightCheckedAt string           `json:"preflight_checked_at"`
	// PreflightAgeSeconds is 0 for a verdict measured during THIS read, and the age in seconds
	// for a reused one. It is not omitempty: a reader is entitled to see the zero and know the
	// answer is fresh, rather than have to infer freshness from a missing key.
	PreflightAgeSeconds int `json:"preflight_age_seconds"`
}

// systemProxyState is the OS network-settings SOCKS proxy as we found it. It lives here rather
// than in either platform file because both sides of the build tag return it and the sentence
// built from it must be identical on every platform.
//
// PointsAtWhisper is the field that keeps this honest. A system proxy can be enabled, pointed at
// 127.0.0.1, and aimed at a port nothing is serving any more - a connection that ended hours ago
// leaves exactly that behind. That configuration is not egress; it is broken networking wearing
// the clothes of a working setup, and it reads here as not-in-force with the reason said out loud.
type systemProxyState struct {
	Supported       bool   `json:"supported"`
	Enabled         bool   `json:"enabled"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Service         string `json:"service"`
	PointsAtWhisper bool   `json:"points_at_whisper"`
}

// panelSensor is the host sensor, as the four states the sensor seam models: running, stopped,
// not-installed, unknown. The panel never collapses them to two.
type panelSensor struct {
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// panelObserved is what the host sensor has actually counted, per minute, from the rollup it
// publishes. It is the one part of this document that is a MEASUREMENT of the product
// working rather than a report of its configuration, which is exactly why it is worth drawing.
//
// State is deliberately three-valued and never two. "live" means a rollup was read and is
// recent. "stale" means one was read and is too old to present as current - a sensor that
// stopped an hour ago must not be able to show an hour-old graph as though it were now.
// "unavailable" means none was found, which on a host with no sensor installed is the correct
// and unalarming answer. A zero is never used to mean any of the three.
type panelObserved struct {
	State  string `json:"state"`
	Detail string `json:"detail"`
	// UpdatedAt and AgeSeconds let the panel make its own judgement rather than trusting ours.
	UpdatedAt  string `json:"updated_at,omitempty"`
	AgeSeconds int    `json:"age_seconds,omitempty"`
	// Since is when the counter started. The series is trimmed to it, so it is here as
	// provenance rather than as something the panel has to do arithmetic with.
	Since string `json:"since,omitempty"`
	// BucketSeconds is the width of one entry in every series.
	BucketSeconds int `json:"bucket_seconds,omitempty"`
	// Series are oldest-first and equal-length; the last entry is the bucket containing
	// UpdatedAt. Keyed by event kind: exec, file, conn, dns.
	Series map[string][]uint64 `json:"series,omitempty"`
	Totals map[string]uint64   `json:"totals,omitempty"`
}

// panelWhalenet is the fleet and the path to each member.
type panelWhalenet struct {
	Peers    []panelPeer `json:"peers"`
	PathNote string      `json:"path_note"`
	// Notes is the fleet leg's own honest channel, carried through from buildWhaleStatus: it is
	// where "could not reach the control plane" lands, so an empty peer list is never mistaken
	// for an empty fleet. A note that means the listing FAILED is also copied into the
	// document's `errors`, so a panel that renders only the error banner still shows it.
	Notes []string `json:"notes"`
}

// panelPeer is one fleet member. RTTMs is omitempty and set ONLY by an actual measurement, which
// is why --probe exists: without it there is no rtt_ms key at all, rather than a zero that reads
// as an instant round trip.
type panelPeer struct {
	Name    string  `json:"name"`
	Address string  `json:"address"`
	FQDN    string  `json:"fqdn"`
	Tenant  string  `json:"tenant"`
	Path    string  `json:"path"`
	RTTMs   float64 `json:"rtt_ms,omitempty"`
	Why     string  `json:"why"`
	Self    bool    `json:"self"`
	State   string  `json:"state"`
}

// readSystemProxyState is the platform system-proxy reader, behind a package var so the
// sentence-building below can be driven through every branch from a test on any OS. The darwin
// implementation shells out to networksetup; everywhere else it answers "not supported here".
var readSystemProxyState = readSystemProxy

// panelErrors collects the one-line reasons from the legs, which run concurrently.
type panelErrors struct {
	mu   sync.Mutex
	list []string
}

func (p *panelErrors) add(format string, a ...any) {
	line := strings.TrimSpace(fmt.Sprintf(format, a...))
	if line == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.list = append(p.list, line)
}

func (p *panelErrors) drain() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.list == nil {
		return []string{}
	}
	return p.list
}

// buildPanelView assembles the document. Every leg is fail-open and none of them can make this
// function return an error: a panel that shows nothing because one HTTP call timed out is worse
// than a panel that shows the eight things it did read and names the ninth in `errors`.
//
// The four remote-ish legs run concurrently because this is polled, and the whole thing is
// bounded by the caller's context.
func buildPanelView(cx context.Context, agentFile string, probe bool) panelView {
	errs := &panelErrors{}
	view := panelView{
		Schema:      panelSchema,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		CLIVersion:  Version,
	}

	cred, _ := client.ResolveCredential(client.KeyLadderOptions{
		FlagKey: g.key, FlagBearer: g.bearer, KeyFile: g.keyFile, AllowEnv: true, AllowFile: true,
	})
	view.Key = panelKey{Present: !cred.IsZero(), Source: string(cred.Source)}

	// The live session is the most authoritative statement this host can make about itself: it
	// is the one that was verified against the echo when it came up, and its liveness is
	// re-confirmed by a real SOCKS5 handshake on every read.
	live := liveStatusSessions()
	var sess *statusSession
	if len(live) > 0 {
		sess = &live[0]
	}
	view.Connection = buildPanelConnection(sess)

	addr := ""
	if sess != nil {
		addr = sess.Address
	}
	if addr == "" {
		addr = client.ReadAgentFile(agentFile)
	}
	view.Identity.Address = addr

	// resolveClient never prompts and never hard-fails on a missing key: verify and the egress
	// echo are both keyless, so a signed-out host still gets the honest half of the answer.
	c, cerr := resolveClient(false, false)
	if cerr != nil || c == nil {
		errs.add("could not build a client for the keyless checks: %s", friendly(cerr))
	}

	var (
		wg     sync.WaitGroup
		whale  whaleStatusView
		vfy    panelVerify
		vfqdn  string
		vten   string
		prox   panelProxyApps
		direct string
		sysapp panelSystemApps
	)

	wg.Add(6)
	go func() {
		defer wg.Done()
		whale = buildWhaleStatus(cx, agentFile, true, probe)
	}()
	go func() {
		defer wg.Done()
		vfy, vfqdn, vten = panelVerifyLeg(cx, c, addr, errs)
	}()
	go func() {
		defer wg.Done()
		prox, direct = panelEgressLeg(cx, c, sess, errs)
	}()
	go func() {
		defer wg.Done()
		view.Sensor = panelSensorLeg(errs)
	}()
	go func() {
		defer wg.Done()
		// A local file read, so it does not need the concurrency; it sits here so that it
		// cannot ever become the one leg that runs in front of the others and delays them.
		view.Observed = panelObservedLeg()
	}()
	go func() {
		defer wg.Done()
		// The system-apps leg reads a local setting AND, when something is connected, runs the
		// pre-flight behind the enable button. That is network work on a polled surface, so it
		// belongs here with the other concurrent legs rather than in front of them.
		sysapp = panelSystemAppsLeg(cx, live, addr, errs)
	}()
	wg.Wait()

	view.Identity.Verify = vfy
	view.Identity.Name = whale.Self.Name
	view.Identity.Tenant = firstNonBlank(whale.Self.Tenant, vten)
	view.Identity.FQDN = firstNonBlank(panelSelfFQDN(whale), vfqdn)
	if view.Identity.Name == "" {
		view.Identity.Name = panelFirstLabel(view.Identity.FQDN)
	}

	view.Whalenet = panelWhalenetFrom(whale)
	// A fleet that came back empty WITH a note behind it is a failed read, not an empty fleet.
	// That distinction is already made by buildWhaleStatus; copying it into `errors` is what
	// stops a panel which renders only the error banner from showing the failure as "0 peers".
	if whale.Self.KeyPresent && len(whale.Peers) == 0 && len(whale.Notes) > 0 {
		for _, n := range whale.Notes {
			errs.add("%s", n)
		}
	}

	view.Egress = panelEgress{ProxyApps: prox, SystemApps: sysapp, Direct: direct}
	view.Errors = errs.drain()
	return view
}

// buildPanelConnection turns the live session (or its absence) into the connection block. The
// tier is normalised through canonTier and labelled through connectTierLabel, so the panel and
// `whisper connect` describe the same transport in the same words.
func buildPanelConnection(sess *statusSession) panelConnection {
	if sess == nil {
		return panelConnection{State: panelNotConnected}
	}
	tier := canonTier(sess.Tier)
	return panelConnection{
		State:     panelConnected,
		Tier:      tier,
		TierLabel: connectTierLabel(tier),
		Endpoint:  sess.Endpoint,
		Port:      sess.Port,
		Tunnel:    panelTunnelFor(sess.Address),
	}
}

// panelTunnelFor reads the record the tunnel-holding process publishes for this /128. The panel
// runs in a different process, minutes later, and a WireGuard handshake never touches it, so
// this on-disk record is the only thing here that knows. Nothing published means Known:false -
// the absence of a report, which is not the report of an unhealthy tunnel.
func panelTunnelFor(addr string) panelTunnel {
	if strings.TrimSpace(addr) == "" {
		return panelTunnel{}
	}
	rec, ok := wgtun.ReadPathStateFor("", addr)
	if !ok {
		return panelTunnel{}
	}
	// PREFER the holder's own reading. Record freshness answers a different question: a monitor
	// failing to re-handshake is still a monitor that is RUNNING, so it republishes on every tick
	// and the record never goes stale. That is how a panel came to report healthy for a session
	// whose own log had reached re-handshake attempt 183 while carrying no traffic. Freshness is
	// the liveness of the publisher; only the holder knows the tunnel.
	if healthy, published := rec.TunnelHealth(); published {
		// A stale record still overrides: a holder that has stopped updating is a wedged monitor,
		// and its last opinion is no more current than the record carrying it.
		return panelTunnel{Known: true, Healthy: healthy && !rec.Stale(), Reconnects: rec.Reconnects}
	}
	// An older holder published no opinion, so fall back to the freshness heuristic rather than
	// reporting a confident "unhealthy" that nobody actually published.
	return panelTunnel{Known: true, Healthy: !rec.Stale(), Reconnects: rec.Reconnects}
}

// panelVerifyLeg runs the keyless identity check and returns the verdict plus the fqdn and
// tenant it named, which is often the only place a signed-out host can learn them.
func panelVerifyLeg(cx context.Context, c *client.Client, addr string, errs *panelErrors) (panelVerify, string, string) {
	if strings.TrimSpace(addr) == "" {
		// Not a failed read: there is genuinely nothing to verify yet. It gets a reason, and it
		// stays out of `errors`, because a fresh install is not a fault.
		return panelVerify{State: panelUnknown,
			Detail: "no agent is selected on this host yet, so there is nothing to verify - run: whisper connect"}, "", ""
	}
	if c == nil {
		errs.add("could not verify %s: no client", addr)
		return panelVerify{State: panelUnknown, Detail: "no client to check the identity with"}, "", ""
	}
	v, _, status, err := c.VerifyIdentity(cx, addr)
	checked := time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		errs.add("could not verify %s: %s", addr, friendly(err))
		return panelVerify{State: panelUnknown, Detail: friendly(err), CheckedAt: checked}, "", ""
	}
	if status == 400 {
		// A 400 is the server rejecting the INPUT, not a verdict about the agent. Reading
		// it as "unverified" would be the panel converting our own bad request into an accusation
		// about the user's identity.
		errs.add("verify rejected %s as an address it could not read", addr)
		return panelVerify{State: panelUnknown,
			Detail: "the verify endpoint could not read " + addr + " as an address", CheckedAt: checked}, "", ""
	}
	out := panelVerify{CheckedAt: checked}
	fqdn, tenant := "", ""
	if v != nil {
		out.DaneOK = v.DaneOK
		out.Detail = v.Detail
		fqdn, tenant = trimDot(v.FQDN), v.Tenant
	}
	if status == 200 && v != nil && v.IsWhisperAgent && v.DaneOK {
		out.State = panelVerified
		if out.Detail == "" {
			out.Detail = fqdn + " verified: reverse DNS, forward confirm and the DANE-EE pin all agreed"
		}
		return out, fqdn, tenant
	}
	out.State = panelUnverified
	if out.Detail == "" {
		out.Detail = notVerifiedReason(v, addr)
	}
	return out, fqdn, tenant
}

// panelEgressLeg proves - or fails to prove - that traffic actually leaves from the agent's
// /128, using the same keyless echo `whisper ip` uses. It deliberately does NOT go through
// connectAndVerify: that would MINT a session, and a panel that polls every few seconds must
// never create the thing it is reporting on.
func panelEgressLeg(cx context.Context, c *client.Client, sess *statusSession, errs *panelErrors) (panelProxyApps, string) {
	if c == nil {
		errs.add("could not read the egress: no client")
		return panelProxyApps{State: panelUnknown, Detail: "no client to check the egress with"}, ""
	}

	// The observations are independent, and this is a polled surface, so they run together
	// rather than one after the other.
	var (
		wg       sync.WaitGroup
		direct   string
		observed string
		obsErr   error
		reach    panelReach
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		d, err := c.DirectEgressIP(cx)
		if err != nil {
			errs.add("could not read this machine's own address: %s", friendly(err))
			return
		}
		direct = d
	}()
	if sess != nil {
		wg.Add(2)
		go func() {
			defer wg.Done()
			observed, obsErr = c.ObservedEgressIP(cx, sess.Endpoint)
		}()
		go func() {
			defer wg.Done()
			reach = panelReachLeg(cx, *sess)
		}()
	}
	wg.Wait()

	if sess == nil {
		// A definite negative, reached without a failed read: there is no local proxy, so nothing
		// can be going through one.
		return panelProxyApps{State: panelNotInForce,
			Detail: "no Whisper connection is up on this host, so nothing is leaving through the Whisper egress - run: whisper connect"}, direct
	}
	if obsErr != nil {
		// Before calling a failed read an unknown, ask the one thing this process can answer on
		// its own. The panel runs in a different process from the tunnel and a WireGuard
		// handshake never touches it, but the holder publishes a path record, and a record that
		// has gone stale is that holder saying the tunnel stopped carrying.
		if apps, ok := panelEgressStalledByTunnel(panelTunnelFor(sess.Address), obsErr); ok {
			errs.add("%s", apps.Detail)
			return apps, direct
		}
		errs.add("could not read the egress through the local proxy: %s", friendly(obsErr))
		return panelProxyApps{State: panelUnknown, Detail: friendly(obsErr)}, direct
	}
	out := panelProxyAppsVerdict(sess.Address, observed, direct, reach)
	if out.State == panelUnknown {
		// The address leg was read; the reachability leg was not. That is a failed read and it
		// belongs in `errors`, so a panel which renders only the banner still says so.
		errs.add("%s", out.Detail)
	}
	return out, direct
}

// panelProxyAppsVerdict is the whole decision, pure, so every branch can be driven from a test
// without a proxy, a tunnel, a policy or a network.
func panelProxyAppsVerdict(sessAddr, observed, direct string, reach panelReach) panelProxyApps {
	switch {
	case inWhisperRange(observed) && sameIP(observed, sessAddr):
		return panelEgressCarrying(observed, reach)
	case direct != "" && sameIP(observed, direct):
		return panelProxyApps{State: panelNotInForce, Observed: observed,
			Detail: "traffic through the local proxy still came out of this machine's own address (" +
				observed + "), so the egress is not carrying it"}
	default:
		return panelProxyApps{State: panelNotInForce, Observed: observed,
			Detail: "traffic through the local proxy left from " + observed +
				", which is not this agent's address (" + sessAddr + ")"}
	}
}

// panelEgressCarrying answers the question the Whisper echo alone never could, and this is the
// whole reason it exists.
//
// By the time we are here one thing is settled: traffic through the local proxy left from this
// agent's own /128. The tunnel is up and it is carrying. What that does NOT establish is where
// it can carry anything TO, because the only destination that was asked is ours - the probe sat
// inside the same failure domain it was certifying. On a `default block` tenant the panel drew a
// confident green over a machine that could reach Whisper and nothing else.
//
// The second observation settles it, and its control is what makes it evidence rather than
// inference: the SAME destination, at the SAME moment, through the proxy and straight from this
// machine.
//
//   - it answered through the proxy: the egress reaches the wider internet. in-force.
//   - it was REFUSED through the proxy and answered directly: something on the egress path
//     turned that traffic away while this machine could make the identical request. On this
//     product that is the tenant policy, so the sentence names `whisper policy` and says in as
//     many words that the tunnel is not the problem - because it is not.
//   - it TIMED OUT through the proxy: a refusal is a decision taken by something and can be
//     named; a timeout is the absence of one. Not knowing is an answer here, and it is the
//     honest one.
//   - it failed BOTH ways, or nothing was measured: that is about the destination or this
//     machine's own network, and it is not grounds to say anything about the egress. Also
//     unknown - never a green, because we did not check what a green would be claiming.
func panelEgressCarrying(observed string, reach panelReach) panelProxyApps {
	out := panelProxyApps{Observed: observed}
	leaves := "traffic through the local proxy left from " + observed + ", your own Whisper address"
	switch {
	case !reach.Tried:
		out.State = panelUnknown
		out.Detail = leaves + ", but whether it reaches anything beyond Whisper was not checked, " +
			"so nothing here says it does"
	case reach.ProxiedOK:
		out.State = panelInForce
		out.Detail = "tools that honour ALL_PROXY leave from " + observed + ", your own Whisper address, " +
			"and traffic through it reached " + reach.Host
	case reach.ProxiedTimedOut && reach.DirectOK:
		out.State = panelUnknown
		out.Detail = leaves + ", but a request to " + reach.Host + " through the egress timed out while the " +
			"identical one straight from this machine answered. A timeout is not a refusal, so what the " +
			"egress will and will not carry is not known from here - see what your policy allows with: whisper policy"
	case reach.DirectOK:
		out.State = panelPolicyLimited
		out.Detail = "the tunnel is up and carrying: " + leaves + ". What it is not carrying is the rest of " +
			"the internet - " + reach.Host + " was refused through the egress at the same moment the identical " +
			"request straight from this machine succeeded. That is your policy, not a broken connection: " +
			"see what is allowed with `whisper policy`"
	default:
		out.State = panelUnknown
		out.Detail = leaves + ", but whether it reaches the rest of the internet is not known: " + reach.Host +
			" answered neither through the egress nor straight from this machine, which is that destination " +
			"or this machine's own network and not something to pin on the egress"
	}
	return out
}

// panelEgressStalledByTunnel is the pure half of that decision, so it can be tested without a
// live tunnel, a real proxy or a home directory.
//
// Two facts have to line up before it will speak: the echo through the local proxy FAILED, and
// the tunnel-holding process's own published record has gone stale. Either alone proves
// nothing - a stale record beside a working echo is a wedged publisher, not a dead tunnel, and
// a failed echo beside a fresh record is about the far end. Together they are a definite
// negative reached from evidence, and they name the layer that is actually broken.
//
// It matters because the alternative was to hand the user a sentence about their session token
// while the network dropped UDP to the WireGuard endpoint: the wrong cause, and a remedy that
// could not have worked. A socks5 session publishes no path record at all, so
// Known is false there and this stays silent rather than guessing about a tunnel that does not
// exist.
func panelEgressStalledByTunnel(tun panelTunnel, obsErr error) (panelProxyApps, bool) {
	if obsErr == nil || !tun.Known || tun.Healthy {
		return panelProxyApps{}, false
	}
	return panelProxyApps{State: panelNotInForce,
		Detail: "the Whisper tunnel has stopped carrying traffic, so tools pointed at the local proxy are " +
			"not getting through. That is the tunnel itself and not your session: check that UDP to the " +
			"Whisper endpoint is not blocked on this network, then run: whisper connect"}, true
}

// --- the second observation ------------------------------------------------------------

// panelReach is what the outside-destination probe established, reduced to the facts the verdict
// needs and nothing else.
//
// Booleans rather than the errors themselves, and that is deliberate twice over. A transport
// failure through a SOCKS proxy spells out the local proxy's host and port, and nothing in this
// document may carry that. And this record is cached on disk between polls, where an error value
// could not survive anyway.
type panelReach struct {
	// Host is the destination that was tried, so the sentence can name it. Never the proxy.
	Host string `json:"host,omitempty"`
	// Tried is false when nothing was measured. It is NOT a failed measurement, and it is never
	// evidence of a block.
	Tried bool `json:"tried"`
	// ProxiedOK and DirectOK are the observation and its control, taken at the same moment.
	ProxiedOK bool `json:"proxied_ok"`
	DirectOK  bool `json:"direct_ok"`
	// ProxiedTimedOut separates a refusal from a black hole. Something refused is a decision
	// that can be named; something that never answered is not.
	ProxiedTimedOut bool `json:"proxied_timed_out,omitempty"`
}

// panelReachFrom reduces the client's pair of observations to the record above.
func panelReachFrom(r client.OutsideReach) panelReach {
	return panelReach{
		Host:            r.Host,
		Tried:           r.Tried,
		ProxiedOK:       r.Tried && r.Proxied == nil,
		DirectOK:        r.Tried && r.Direct == nil,
		ProxiedTimedOut: r.ProxiedTimedOut,
	}
}

// panelReachLeg takes the second observation. A package var so every branch of the verdict can
// be driven from a test with no proxy, no policy and no network.
var panelReachLeg = panelReachCached

// panelReachTTL is how long one pair of observations may be reused.
//
// The panel refreshes every 15 seconds while somebody has it open and every 2 minutes while
// nobody does, and two real HTTPS requests to a stranger's host on every one of those polls is
// not a thing to do to somebody's laptop, or to the far end. A minute is short enough that a
// policy change is reflected within a minute and long enough that an open panel costs two
// requests a minute instead of eight. The same TTL the system-proxy pre-flight settled on, for
// the same reason.
const panelReachTTL = 60 * time.Second

// panelReachCached is the live leg: a record no older than the TTL and measured against THIS
// session, or a fresh pair of probes.
func panelReachCached(cx context.Context, sess statusSession) panelReach {
	if r, ok := readPanelReachCache(sess); ok {
		return r
	}
	r := panelReachFrom(client.ReachOutside(cx, sess.Endpoint))
	writePanelReachCache(sess, r)
	return r
}

// panelReachRecord is the cached pair plus the provenance that decides whether it may be reused:
// when it was taken, and which session it was taken against. A new connect invalidates it by
// simply not matching.
type panelReachRecord struct {
	panelReach
	CheckedAt string `json:"checked_at"`
	Endpoint  string `json:"endpoint"`
	Address   string `json:"address"`
}

// panelReachCachePath is where that record lives. On disk because `whisper panel status` is a
// fresh process on every poll, so an in-process cache would never once be read.
func panelReachCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "whisper", "egress-reach.json")
	}
	return filepath.Join(home, ".config", "whisper", "egress-reach.json")
}

// readPanelReachCache returns a usable cached record, or ok=false. A record for another session,
// an unreadable file, an unparseable timestamp or an age past the TTL all mean "measure again";
// none of them is fatal, because a miss costs two requests and never a wrong answer.
func readPanelReachCache(sess statusSession) (panelReach, bool) {
	raw, err := os.ReadFile(panelReachCachePath())
	if err != nil {
		return panelReach{}, false
	}
	var rec panelReachRecord
	if json.Unmarshal(raw, &rec) != nil {
		return panelReach{}, false
	}
	if rec.Endpoint != sess.Endpoint || !strings.EqualFold(rec.Address, sess.Address) {
		return panelReach{}, false
	}
	// The destination is part of the answer: an operator who repoints it must not be shown a
	// verdict about the host it used to probe, and a record taken when there was no usable
	// destination at all must not survive one being configured.
	if rec.Host != client.ReachURLHost() {
		return panelReach{}, false
	}
	at, perr := time.Parse(time.RFC3339, rec.CheckedAt)
	if perr != nil {
		return panelReach{}, false
	}
	if age := time.Since(at); age < 0 || age > panelReachTTL {
		return panelReach{}, false
	}
	return rec.panelReach, true
}

// writePanelReachCache stores the record (0600, in a 0700 directory). Best-effort: losing it
// costs two requests, never a wrong verdict, so a write failure is silent.
func writePanelReachCache(sess statusSession, r panelReach) {
	raw, err := json.Marshal(panelReachRecord{
		panelReach: r,
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),
		Endpoint:   sess.Endpoint,
		Address:    sess.Address,
	})
	if err != nil {
		return
	}
	path := panelReachCachePath()
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	_ = os.WriteFile(path, raw, 0o600)
}

// panelSystemAppsLeg answers the half of the egress story `whisper connect` never could: what
// Safari, Chrome, Mail and every other app that reads the system network settings are doing, and
// whether switching them over is safe to offer at all.
// It judges the system proxy against the ports the live sessions are actually serving.
func panelSystemAppsLeg(cx context.Context, live []statusSession, sessionAddr string, errs *panelErrors) panelSystemApps {
	sp, err := readSystemProxyState(sysProxyLivePorts(live))
	if err != nil {
		errs.add("could not read the system network settings: %s", friendly(err))
		return panelSystemApps{State: panelUnknown,
			Detail:      "could not read this Mac's network settings, so what Safari and other system apps are doing is not known: " + friendly(err),
			SystemProxy: sp,
			CannotEnableReason: "Whisper will not change network settings it could not read first, " +
				"because it could not promise to put them back: " + friendly(err)}
	}
	return panelSystemAppsFrom(sp, sessionAddr, panelSystemProxyEnableVerdict(cx, sp, live))
}

// panelSystemProxyEnableVerdict decides whether the enable button is worth offering, and says why
// when it is not. The two cheap negatives are answered here without touching the network; the
// expensive one is the real pre-flight, cached so a polled panel stays cheap.
func panelSystemProxyEnableVerdict(cx context.Context, sp systemProxyState, live []statusSession) sysProxyVerdict {
	switch {
	case !sp.Supported:
		return sysProxyVerdict{Reason: "Whisper cannot change this platform's system network settings, " +
			"so there is nothing to switch on here. Point your apps at the connection string " +
			"`whisper connect` prints instead."}
	case len(live) == 0:
		return sysProxyVerdict{Reason: "nothing is connected on this host, so there is no Whisper egress " +
			"to send Safari and other system apps through. Run: whisper connect"}
	}
	return sysProxyPreflightCached(cx, live[0])
}

// panelSystemAppsFrom writes the sentence a person can act on, and carries the enable verdict
// alongside it. It is pure and platform-neutral on purpose: the wording is the product here, and
// it must not differ by OS.
func panelSystemAppsFrom(sp systemProxyState, sessionAddr string, v sysProxyVerdict) panelSystemApps {
	out := panelSystemApps{
		SystemProxy:         sp,
		CanEnable:           v.CanEnable,
		CannotEnableReason:  v.Reason,
		PreflightCheckedAt:  v.CheckedAt,
		PreflightAgeSeconds: v.AgeSecs,
	}
	switch {
	case !sp.Supported:
		// Not a failure and not a negative: this build cannot read or set the system proxy on
		// this platform, so it does not know what the GUI apps are doing, and it says that.
		out.State = panelUnknown
		out.Detail = "Whisper cannot read this platform's system network settings yet, so whether apps " +
			"like Safari and Chrome use the Whisper egress here is not something this build can tell you"
	case sp.Enabled && sp.PointsAtWhisper:
		out.State = panelInForce
		out.Detail = "Safari and other system apps leave from " +
			orVal(sessionAddr, "your Whisper address") + " through the local Whisper proxy."
	case sp.Enabled:
		// The one that matters. An enabled proxy aimed at a port nothing is serving is the
		// wrong answer wearing the clothes of a working one, and the panel names it as such.
		out.State = panelNotInForce
		out.Detail = fmt.Sprintf("the system proxy on %s is switched on and points at %s, but no live Whisper "+
			"session is serving that port - Safari and other system apps are NOT using the Whisper egress. "+
			"Point it at the running session with: whisper panel system-proxy on",
			orVal(sp.Service, "this Mac"), panelHostPort(sp.Host, sp.Port))
	default:
		out.State = panelNotInForce
		out.Detail = "Safari, Chrome and other apps that use the system network settings are NOT using the " +
			"Whisper egress - they leave from this machine's own address."
	}
	// The advice is decided by the pre-flight, never bolted onto the state sentence.
	// Telling somebody to run `system-proxy on` a line above a paragraph explaining that
	// `system-proxy on` would take their machine off the internet is a document arguing
	// with itself, and it is what the panel showed the first time this shipped.
	if out.State == panelNotInForce && !out.CanEnable {
		// Nothing appended: cannot_enable_reason already carries the whole story,
		// including what to do instead.
		return out
	}
	if out.State == panelNotInForce && out.CanEnable {
		out.Detail += " Turn it on with: whisper panel system-proxy on"
	}
	return out
}

// panelCheckedAgo appends the age of a reused pre-flight verdict, and nothing at all for a fresh
// one. A verdict from fifty seconds ago is still worth printing; printing it as though it were
// this second's measurement is not.
func panelCheckedAgo(ageSecs int) string {
	if ageSecs <= 0 {
		return ""
	}
	return fmt.Sprintf(" (checked %ds ago)", ageSecs)
}

// panelHostPort renders the system proxy's target for the sentence above, without pretending to
// know a port that was never set.
func panelHostPort(host string, port int) string {
	h := orVal(strings.TrimSpace(host), "an unset address")
	if port <= 0 {
		return h
	}
	return fmt.Sprintf("%s:%d", h, port)
}

// systemProxyPointsAtWhisper is the whole honesty test for the system proxy, and it is written
// here rather than in the darwin file so it is one rule and so it is reachable from a test on
// any OS.
//
// True demands BOTH halves: a loopback address (anything else is somebody else's proxy) AND a
// port a Whisper session is serving RIGHT NOW. The second half is the one that catches the
// failure people actually hit: a session ends, the OS setting stays behind, and every GUI app on
// the machine quietly stops reaching the internet while the settings pane still reads "on".
func systemProxyPointsAtWhisper(host string, port int, livePorts []int) bool {
	if port <= 0 {
		return false
	}
	h := strings.Trim(strings.TrimSpace(host), "[]")
	if !strings.EqualFold(h, "localhost") {
		a, err := netip.ParseAddr(h)
		if err != nil || !a.IsLoopback() {
			return false
		}
	}
	for _, p := range livePorts {
		if p == port {
			return true
		}
	}
	return false
}

// panelSensorLeg reads the host sensor through the hostSensorStatus seam.
//
// The seam hands back an `any`, and this file must keep it that way: the endpoint half of this
// CLI is not part of the source we publish, so naming its type here would break the published
// client. Round-tripping the value through JSON reads the state the seam already models without
// importing it, and it asserts the wire shape the panel is coded against rather than a Go type.
func panelSensorLeg(errs *panelErrors) panelSensor {
	if hostSensorStatus == nil {
		// A build with no endpoint half has no sensor to report four states about. That is not a
		// failed read, so it carries a reason and stays out of `errors`.
		return panelSensor{State: panelUnknown,
			Detail: "this build carries no host sensor, so there is nothing here to report on"}
	}
	value, _ := hostSensorStatus()
	raw, err := json.Marshal(value)
	if err != nil {
		errs.add("could not read the host sensor: %s", friendly(err))
		return panelSensor{State: panelUnknown, Detail: friendly(err)}
	}
	var s panelSensor
	if err := json.Unmarshal(raw, &s); err != nil || strings.TrimSpace(s.State) == "" {
		errs.add("the host sensor reported a state this build could not read")
		return panelSensor{State: panelUnknown, Detail: "the sensor seam returned a state that could not be read"}
	}
	if s.State == panelUnknown {
		// The seam could not reach the service manager. That is a failed read, and it must reach
		// `errors` rather than sitting in a field the panel might render as a grey dot next to
		// the grey dot it draws for "stopped".
		errs.add("could not read the host sensor: %s", orVal(s.Detail, "no reason given"))
	}
	return s
}

// panelWhalenetFrom flattens the whale view into the panel's shape, adding the tenant each peer
// belongs to. RTTMs is carried straight through, which is what keeps rtt_ms absent unless a
// probe actually measured it.
func panelWhalenetFrom(w whaleStatusView) panelWhalenet {
	out := panelWhalenet{Peers: make([]panelPeer, 0, len(w.Peers)), PathNote: w.PathNote, Notes: []string{}}
	out.Notes = append(out.Notes, w.Notes...)
	for _, p := range w.Peers {
		out.Peers = append(out.Peers, panelPeer{
			Name:    p.Name,
			Address: p.Address,
			FQDN:    trimDot(p.FQDN),
			Tenant:  tenantOfFQDN(p.FQDN),
			Path:    p.Path,
			RTTMs:   p.RTTMs,
			Why:     p.Why,
			Self:    p.Self,
			State:   p.State,
		})
	}
	return out
}

// panelSelfFQDN finds the fleet entry that IS this node, which is where the fqdn comes from when
// a key is in effect.
func panelSelfFQDN(w whaleStatusView) string {
	for _, p := range w.Peers {
		if p.Self {
			return trimDot(p.FQDN)
		}
	}
	return ""
}

// panelFirstLabel is the last-resort name: the first label of the fqdn. Used only when the fleet
// listing did not name this node, so a keyless panel still has something to render.
func panelFirstLabel(fqdn string) string {
	s := trimDot(strings.TrimSpace(fqdn))
	if i := strings.IndexByte(s, '.'); i > 0 {
		return s[:i]
	}
	return s
}

// observedStaleAfter is how old a published rollup may be and still be presented as current.
//
// The sensor republishes every 30s and the panel polls at worst every 120s, so anything past
// five minutes means the writer stopped rather than that the reader was early. Presenting that
// as a live graph would be the panel telling a person their sensor is working because it used
// to be.
const observedStaleAfter = 5 * time.Minute

// observedCandidates lists where the panel looks for the sensor's published rollup,
// best first. It is EMPTY unless a build supplies the endpoint half, and a reader that
// finds no candidates is the same reader that finds no file: the panel loses one graph
// and keeps everything around it.
//
// It is also the seam a test points somewhere it controls. Without that, `go test` on a
// machine with a sensor installed would read that machine's live rollup and pass or fail
// on whatever the host happened to be doing at the time.
var observedCandidates = func() []string { return nil }

// panelObservedLeg reads the sensor's published rollup.
//
// It is a local file read of a couple of kilobytes, so unlike the other legs it costs nothing
// and cannot hang. Every failure here is soft: the panel loses one graph and keeps the eight
// things around it.
func panelObservedLeg() panelObserved {
	var lastErr string
	for _, path := range observedCandidates() {
		body, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				lastErr = friendly(err)
			}
			continue
		}
		var snap observed.Snapshot
		if err := json.Unmarshal(body, &snap); err != nil {
			lastErr = "the published rollup could not be read"
			continue
		}
		updated, terr := time.Parse(time.RFC3339, snap.UpdatedAt)
		if terr != nil {
			lastErr = "the published rollup carried no readable timestamp"
			continue
		}
		age := time.Since(updated)
		if age < 0 {
			// A rollup stamped in the future is a clock disagreement, not a measurement.
			// Treat it as current rather than reporting a negative age.
			age = 0
		}
		out := panelObserved{
			UpdatedAt:     snap.UpdatedAt,
			AgeSeconds:    int(age.Seconds()),
			Since:         snap.Since,
			BucketSeconds: snap.BucketSeconds,
			Series:        trimToUptime(snap, updated),
			Totals: map[string]uint64{
				"exec": snap.Totals.Exec,
				"file": snap.Totals.File,
				"conn": snap.Totals.Conn,
				"dns":  snap.Totals.DNS,
			},
		}
		if age > observedStaleAfter {
			out.State = "stale"
			out.Detail = "the sensor last published " + humanizeAge(age) + " ago, so this is not current activity"
			return out
		}
		out.State = "live"
		return out
	}
	return panelObserved{State: "unavailable", Detail: orVal(lastErr,
		"no host sensor on this machine is publishing activity counts")}
}

// humanizeAge renders a duration the way a sentence would say it.
func humanizeAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
}

// trimToUptime drops the buckets from before the counter existed.
//
// The ring starts empty, so a sensor that has been up for six minutes reports
// fifty-four zeroes in front of its six real numbers. Drawn, those are a flat
// line for most of an hour, which says "the sensor was watching and nothing
// happened". It was not watching. A minute nobody counted is not a minute that
// counted nothing, and this is the difference between the two.
//
// Unparseable or absent provenance means no trim: showing the whole ring is worse
// than showing it, but inventing a start time to trim against is worse than both.
func trimToUptime(snap observed.Snapshot, updated time.Time) map[string][]uint64 {
	if snap.Series == nil || snap.BucketSeconds <= 0 {
		return snap.Series
	}
	started, err := time.Parse(time.RFC3339, snap.Since)
	if err != nil {
		return snap.Series
	}
	up := updated.Sub(started)
	if up < 0 {
		return snap.Series
	}
	// The bucket holding `since` is partly covered, and it is a real measurement
	// for the part that was watched, so it is kept.
	covered := int(up.Seconds())/snap.BucketSeconds + 1
	out := make(map[string][]uint64, len(snap.Series))
	for k, v := range snap.Series {
		if covered >= len(v) {
			out[k] = v
			continue
		}
		if covered <= 0 {
			out[k] = []uint64{}
			continue
		}
		out[k] = v[len(v)-covered:]
	}
	return out
}
