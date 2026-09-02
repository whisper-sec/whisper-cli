// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/egress"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// connect_core.go is the ONE shared connect implementation that
// `whisper connect`, the guided front door, `whisper ip`, and `whisper run` all call.
// It takes the op:connect envelope, brings up the PURE-GO local forward proxy, folds
// the egress verify in, and yields a bearer-free local endpoint plus the verified
// /128 - so every surface behaves identically and NONE of them ever sees the bearer.
//
// THE bearer-hygiene contract: the et_ bearer and the upstream proxy URL are pulled
// from the envelope as INTERNAL values here and handed ONLY to egress.StartLocalProxy
// (where they stay in process memory). They are never returned, never printed, never
// persisted to argv/history/child-env. The only value any caller surfaces is the
// local socks5h://127.0.0.1:<port>.

// isWireGuardTier reports whether the requested tier string selects the Tier-1 WireGuard path
// Liberal-accept (Postel): trimmed + case-insensitive, with "wg" as a friendly alias.
func isWireGuardTier(tier string) bool {
	t := strings.ToLower(strings.TrimSpace(tier))
	return t == "wireguard" || t == "wg"
}

// --- AUTO tier negotiation: the no-flag default -----------------------------------------
//
// `whisper connect` without an explicit --tier negotiates the BEST tier the platform and
// network can give (the core robustness requirement): try Tier-1 (a routed /128 over
// userspace WireGuard) first under a short bound, and on ANY failure downgrade
// automatically to Tier-1.5 (the SOCKS5 egress, which needs nothing but outbound :443).
// The Tier-1 failure is typed and logged at debug, never surfaced as an error - only BOTH
// tiers failing produces one, and then exactly one clear, helpful line (Postel: maximum
// reliability, minimum resistance). An explicit --tier forces that exact tier, no downgrade.

// Canonical tier tokens (the values op:connect understands).
const (
	tierWireGuard = "wireguard"
	tierSocks5    = "socks5"
)

// tier1AttemptTimeout bounds the WHOLE Tier-1 attempt in auto mode (op:connect + tunnel
// bring-up + the through-tunnel verify echo), so a blocked-UDP / no-handshake environment
// downgrades to Tier-1.5 in seconds - never a long hang. An EXPLICIT --tier wireguard is
// NOT bounded by this: the user asked for that tier, so it keeps the full per-call timeout.
// A package var so a test can shrink it (never grown at runtime).
var tier1AttemptTimeout = 10 * time.Second

// isAutoTier reports whether the requested tier selects AUTO negotiation: the empty
// default (no --tier at all) and the explicit "auto" spelling (Postel: accept both).
func isAutoTier(tier string) bool {
	t := strings.ToLower(strings.TrimSpace(tier))
	return t == "" || t == "auto"
}

// autoTierFailure types one failed tier attempt during AUTO negotiation: which tier
// failed, and why. Internal: auto mode logs it at debug and downgrades; only a
// both-tiers failure ever reaches the user (as ONE combined error, see bothTiersFailed).
type autoTierFailure struct {
	tier string
	err  error
}

func (f *autoTierFailure) Error() string { return f.tier + ": " + friendlyAttemptErr(f.err) }
func (f *autoTierFailure) Unwrap() error { return f.err }

// friendlyAttemptErr renders one attempt failure as a plain human phrase - the bounded
// attempt's context deadline/cancel maps to "timed out"/"cancelled", never Go's opaque
// "context deadline exceeded".
func friendlyAttemptErr(err error) string {
	switch {
	case err == nil:
		return "failed"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	return friendly(err)
}

// debugf prints an internal diagnostic to stderr when WHISPER_DEBUG is set (any non-empty
// value). The auto-tier downgrade is a FEATURE, not an error: by default it is silent and
// the landed-tier success line is the only user surface; set WHISPER_DEBUG=1 to see why
// Tier-1 was passed over.
func debugf(format string, args ...any) {
	if os.Getenv("WHISPER_DEBUG") == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "whisper[debug]: "+format+"\n", args...)
}

// connectTierAttempt runs ONE complete connect for an EXPLICIT tier: per-tier key prep
// (the WG + identity keypairs for the routed tier), op:connect, local bring-up, and
// the egress verify. base is NEVER mutated - each attempt works on its own copy, so a
// failed Tier-1 attempt's public_key/identity_public_key/tier args can never bleed into
// the Tier-1.5 retry. It is the one connect body BOTH the forced --tier path and each
// auto-negotiation leg run, so the two modes can never drift apart.
func connectTierAttempt(cx context.Context, c *client.Client, base map[string]any, tier, sel string, port int) (*egressSession, error) {
	args := make(map[string]any, len(base)+3)
	for k, v := range base {
		args[k] = v
	}
	args["tier"] = tier
	wgKey, err := prepareWireGuard(tier, args)
	if err != nil {
		return nil, err
	}
	idKey, err := prepareIdentityKey(tier, args, sel)
	if err != nil {
		return nil, err
	}
	keys := &connectKeys{wg: wgKey, identity: idKey}
	env, err := c.Agents(cx, "connect", args)
	if err != nil {
		return nil, err
	}
	// Check ONLY for a control-plane error here - never the shared --json envelope dump:
	// the raw op:connect result carries the et_ bearer / minted WG private key, so dumping
	// it would LEAK a credential. connect's own sanitized render runs after bring-up.
	if perr := envelopeError(env); perr != nil {
		// SELF-HEAL the one refusal a client can honestly answer for itself.
		//
		// We stopped resending identity_public_key on a reconnect to an address we
		// already hold a key for, and PROVED possession with a signature instead. It is the
		// right shape, and it rests on an assumption nothing checks: that the pin is already
		// published on the box this connect lands on. When that is false the server answers
		// "no identity key is pinned for this address to verify against" and Tier 1 fails for
		// that agent FOREVER, because every retry makes the same unprovable claim. Measured on
		// a live host: a `--tier wireguard` that had worked an hour earlier failed on every
		// subsequent attempt, and `whisper connect` silently downgraded to Tier 1.5 with the
		// reason only visible under WHISPER_DEBUG.
		//
		// So: if the server says it has nothing to verify against, say who we are instead of
		// insisting it already knows. Exactly once, and only for that reason. This gives away
		// nothing the server was enforcing: whether a birth-pin is acceptable for an address is
		// the SERVER's decision and it is unchanged - we are answering the question it asked.
		if idKey != nil && serverHoldsNoPin(perr) && retryAsBirthPin(args, idKey) {
			debugf("tier %s: the box holds no pin for this address, re-sending the key as a first enrolment", tier)
			env, err = c.Agents(cx, "connect", args)
			if err != nil {
				return nil, err
			}
			if perr2 := envelopeError(env); perr2 != nil {
				return nil, perr2
			}
		} else {
			return nil, perr
		}
	}
	// A pinned port binds a REAL socket, so it goes through connectAndVerifyOnPort
	// directly; the free-port path rides the connectAndVerify var (the test stub seam).
	if port > 0 {
		return connectAndVerifyOnPort(cx, c, env.Result, displayName(env.Result), keys, port)
	}
	return connectAndVerify(cx, c, env.Result, displayName(env.Result), keys)
}

// negotiateConnect is the AUTO orchestration: try Tier-1 (WireGuard) first under
// tier1AttemptTimeout; on ANY failure - typed, logged at debug, never surfaced - fall
// back to Tier-1.5 (SOCKS5) on the parent's full deadline. The session it returns is
// marked negotiated so the success line names the tier it landed on. Only both tiers
// failing returns an error, and then exactly one helpful one.
func negotiateConnect(parent context.Context, c *client.Client, base map[string]any, sel string, port int) (*egressSession, error) {
	wgCtx, cancel := context.WithTimeout(parent, tier1AttemptTimeout)
	sess, wgErr := connectTierAttempt(wgCtx, c, base, tierWireGuard, sel, port)
	// Cancelling the attempt ctx is safe on success: the running proxy/tunnel is
	// Background-rooted and ends ONLY on Stop() (see egress.StartLocalProxy / wgtun.Start).
	cancel()
	if wgErr == nil {
		sess.negotiated = true
		return sess, nil
	}
	wgFail := &autoTierFailure{tier: tierWireGuard, err: wgErr}
	debugf("auto tier: %s - downgrading to %s", wgFail, tierSocks5)
	sess, sErr := connectTierAttempt(parent, c, base, tierSocks5, sel, port)
	if sErr == nil {
		sess.negotiated = true
		return sess, nil
	}
	s5Fail := &autoTierFailure{tier: tierSocks5, err: sErr}
	debugf("auto tier: %s - no tier left", s5Fail)
	return nil, bothTiersFailed(wgFail, s5Fail)
}

// bothTiersFailed collapses the two attempt failures into exactly ONE clear, helpful
// error - never two stacked errors, never an opaque one. When both tiers failed for the
// SAME reason (a rejected key, a stale agent, a dead network) the cause is
// tier-independent, so it surfaces AS ITSELF - preserving the original status/detail a
// user or script can act on. Only genuinely different causes get the combined diagnosis.
func bothTiersFailed(wg, s5 *autoTierFailure) error {
	if wg.err != nil && s5.err != nil && wg.err.Error() == s5.err.Error() {
		return s5.err
	}
	return &client.ProblemError{Status: 502, Detail: fmt.Sprintf(
		"couldn't connect on any tier (wireguard: %s; socks5: %s) - check your network and API key, then try `whisper connect` again",
		friendlyAttemptErr(wg.err), friendlyAttemptErr(s5.err))}
}

// landedTierNote is the short, honest label for the tier AUTO negotiation landed on -
// rendered in the one-line success message so the user always knows what they got.
func landedTierNote(tier string) string {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "wireguard", "wg":
		return "Tier-1 wireguard (routed /128)"
	case "anyip":
		return "Tier-1.5 anyip egress"
	default:
		return "Tier-1.5 socks5 egress"
	}
}

// prepareWireGuard is the command-layer pre-step for --tier wireguard: it mints a local
// Curve25519 keypair, injects ONLY the public half into the op:connect args (so the server
// registers us as a peer without ever seeing the private key), and returns the keypair to
// thread into connectAndVerify. For any other tier it is a no-op (nil keypair, args untouched).
//
// This is the best-practice WG flow: the private key never leaves the host (a key-hygiene
// requirement), and the agent's reverse-DNS identity is bound to a key only we hold. It is
// a package var so a command test can stub it to a deterministic keypair without real crypto.
var prepareWireGuard = func(tier string, args map[string]any) (*wgtun.Keypair, error) {
	if !isWireGuardTier(tier) {
		return nil, nil
	}
	kp, err := wgtun.GenerateKeypair()
	if err != nil {
		return nil, &client.ProblemError{Status: 500, Detail: "couldn't prepare a WireGuard key - please try again"}
	}
	// The server reads `public_key` (alias publicKey) and binds a peer to our /128. We send
	// ONLY the public half; the private key stays in kp (in-memory) for the device bring-up.
	args["public_key"] = kp.PublicKeyBase64
	// tell the control plane where this node can be dialed on the underlay, and
	// pin the port we will actually listen on. Both or neither - a declared ip:port that the
	// device does not bind is a lie, and a peer would send handshakes into a void. Declaring
	// nothing is the ordinary case (no private address, or no port reservable) and simply
	// means every east-west packet keeps being relayed, exactly as before direct paths.
	if eps, port := declaredEndpoints(); port > 0 {
		args["endpoints"] = eps
		wgListenPort = port
	} else {
		wgListenPort = 0
	}
	// Normalise the tier the server sees to the canonical token (so "wg" still selects WG).
	args["tier"] = "wireguard"
	return &kp, nil
}

// wgListenPort is the UDP port prepareWireGuard reserved and declared, read by
// bringUpWireGuard when it builds the device. It is package state rather than a threaded
// argument because prepareWireGuard is a package var a test stubs, and the two halves have to
// agree on ONE number: the port we told the control plane about must be the port we bind, or
// the declaration is worthless. A connect that declared nothing leaves it 0, which means "let
// the kernel choose", which is what it did before the port was declared.
var wgListenPort int

// prepareIdentityKey is the command-layer pre-step, run ALONGSIDE prepareWireGuard: for the
// routed (WireGuard) tier ONLY, it loads-or-mints a LOCAL EC P-256 identity keypair and injects ONLY
// its public SPKI into the op:connect args as identity_public_key - so the server pins the agent's
// OWN key, verbatim; the server pins SHA-256 of exactly this SPKI and never derives or serves a
// Whisper-minted key for a held /128. Default-ON for the
// routed tier: this is the tier the trust-boundary claim ("we can never speak as your agent") is
// about. For any other tier it is a no-op (nil keypair, args untouched) - a hosted identity's
// credential stays Whisper-derived (the server rejects the arg there anyway).
//
// handle is the persistence key (an already-resolved agent id/address, or "" for a connect-first
// flow - see idkey.PathFor) so a RECONNECT for the same agent reuses the SAME key rather than
// rotating on every call (the server's idempotent re-pin then costs zero zone writes). It is a
// package var so a command test can stub it to a deterministic keypair without real crypto.
var prepareIdentityKey = func(tier string, args map[string]any, handle string) (*idkey.Keypair, error) {
	if !isWireGuardTier(tier) {
		return nil, nil
	}
	// RECONNECT to a known /128 whose key we already hold: PROVE possession
	// instead of resending the key. Two things change for the better at once. The server can
	// refuse an enrolment that carries no proof (which is what makes a stolen API key unable to
	// mint a peer for somebody else's node), and the connect stops carrying
	// identity_public_key, which the zone-write classifier reads as re-authoring and forwards
	// to the primary - resent on every reconnect, that lands every Tier-1 tunnel in the fleet
	// on one box. The pin is already published; there is nothing to re-pin.
	//
	// Strictly narrower than the path below: it needs an address-shaped selector AND a key
	// already persisted for it. A first connect, a connect-first flow, or an agent-id selector
	// all fall through to the unchanged birth-pin behaviour.
	if addr, aerr := netip.ParseAddr(strings.TrimSpace(handle)); aerr == nil {
		if kp, lerr := idkey.Load(handle); lerr == nil {
			wgPub, _ := args["public_key"].(string)
			window := idkey.EnrolmentWindow(time.Now())
			if sig, serr := kp.SignEnrolment(addr, wgPub, window); serr == nil {
				args["identity_signature"] = sig
				args["identity_signature_window"] = window
				return kp, nil
			}
		}
	}
	kp, err := idkey.LoadOrGenerate(handle)
	if err != nil {
		return nil, &client.ProblemError{Status: 500, Detail: "couldn't prepare an identity key - please try again"}
	}
	// The server hashes EXACTLY this base64 DER, verbatim - never a private key, never re-encoded.
	args["identity_public_key"] = kp.MarshalSPKIBase64()
	return kp, nil
}

// serverHoldsNoPin reports whether a control-plane refusal is the one specific "I have
// nothing to verify your signature against" answer. It is matched on the server's own
// sentence, narrowly, because a broad match here
// would turn every enrolment refusal into a re-pin attempt and that is precisely the
// thing this narrow match exists to prevent.
func serverHoldsNoPin(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()),
		"no identity key is pinned for this address to verify against")
}

// retryAsBirthPin rewrites a proof-of-possession connect into a first-enrolment one: the
// signature comes out, the public key goes in. It reports false when the args were not a
// proof-of-possession connect in the first place, so the caller never retries a request it
// did not change.
func retryAsBirthPin(args map[string]any, kp *idkey.Keypair) bool {
	if _, signed := args["identity_signature"]; !signed {
		return false
	}
	delete(args, "identity_signature")
	delete(args, "identity_signature_window")
	args["identity_public_key"] = kp.MarshalSPKIBase64()
	return true
}

// connectKeys bundles the (at most two) LOCAL keypairs a routed connect may carry: the WireGuard
// tunnel key and, by default for that same tier, the agent-held identity key. Both private
// halves live ONLY in this process; only their public halves are ever sent to op:connect. Either
// field may be nil (a non-WireGuard tier carries neither).
type connectKeys struct {
	wg       *wgtun.Keypair
	identity *idkey.Keypair
}

// localEndpoint is the shared surface BOTH egress tiers expose: the bearer/key-free local
// SOCKS5/HTTP endpoint a caller hands to tools, and a Stop() that tears it down. The Tier-1.5
// egress (*egress.Proxy) and the Tier-1 WireGuard tunnel (*wgtun.Tunnel) both satisfy it, so
// every command (connect/run/ip/guided) treats the two tiers identically - only the bring-up
// differs. A tier-1 *wgtun.Tunnel additionally exposes Healthy() (asserted via a type switch
// where status needs it); the common path never has to care which tier it holds.
type localEndpoint interface {
	Endpoint() string
	Addr() string
	Stop()
}

// egressSession is a live local egress: the bearer-free local endpoint a caller hands
// to tools, the verified /128, the agent's display name, the tier, and the local proxy/tunnel.
type egressSession struct {
	endpoint   string        // socks5h://127.0.0.1:<port> - THE connection string (bearer/key-free)
	addr       string        // the agent's verified /128 (== the egress source)
	name       string        // the agent's human name (for the success line)
	tier       string        // "socks5" | "anyip" | "wireguard" - the active egress tier
	verified   bool          // true when the egress source IP == the agent /128
	negotiated bool          // true when AUTO tier negotiation picked this tier (the success line then names it)
	local      localEndpoint // the running proxy (Tier-1.5) or WG tunnel (Tier-1); nil in stubs
}

// tunnelHealthy reports the WireGuard tunnel's live handshake health when this session is the
// Tier-1 WG tier (ok=true); for the egress tiers there is no tunnel to probe (ok=false). It is
// the seam status/render use to show tunnel state without the common path knowing the tier.
func (s *egressSession) tunnelHealthy() (healthy bool, ok bool) {
	if s == nil {
		return false, false
	}
	if t, isWG := s.local.(*wgtun.Tunnel); isWG {
		return t.Healthy(), true
	}
	return false, false
}

// Stop tears down the local proxy/tunnel. Safe on a nil session / nil local.
func (s *egressSession) Stop() {
	if s != nil && s.local != nil {
		s.local.Stop()
	}
}

// connectEnvelope is the load-bearing slice of the op:connect result we consume. The
// secret-carrying fields (http_proxy / connection_string for the egress tier; the WG keys)
// stay INTERNAL - extracted for the bring-up, NEVER surfaced.
type connectEnvelope struct {
	tier    string // "socks5" | "anyip" | "wireguard" (echoed by the server; default socks5)
	address string // the agent's /128
	fqdn    string // canonical FQDN (display)

	// --- Tier-1.5 egress (socks5/anyip) fields ---
	upstreamHostPort string // the egress host:port (e.g. egress.whisper.online:443)
	bearer           string // the et_ token (in-memory only from here on)
	tlsToProxy       bool   // true ⇒ the egress terminates TLS (the https:// proxy form)

	// --- Tier-1 WireGuard fields ---
	wgServerPubKey string // the server's WireGuard public key, base64
	wgEndpoint     string // the server UDP endpoint, host:port
	wgDNS          string // the in-tunnel resolver (DNS64/NAT64)
	wgQuick        string // the full wg-quick config blob (parsed as a fallback)
	wgPrivKeyB64   string // server-minted private key, base64 - present ONLY on the zero-key path
}

// isWireGuard reports whether the server selected the Tier-1 WireGuard tier for this result.
func (e connectEnvelope) isWireGuard() bool {
	return strings.EqualFold(strings.TrimSpace(e.tier), "wireguard")
}

// parseConnectEnvelope distils the op:connect result into the internal connect inputs. For
// the egress tiers it reads the proxy/socks fields ONLY to derive the upstream host + bearer;
// for the WireGuard tier it reads the WG config fields. A result with no usable transport for
// its tier is a clean error (never a silent half-connect).
func parseConnectEnvelope(res *client.Result) (connectEnvelope, error) {
	recs := res.Records()
	if len(recs) == 0 {
		return connectEnvelope{}, &client.ProblemError{Status: 502, Detail: "the control plane returned no egress"}
	}
	rec := recs[0]
	var out connectEnvelope
	out.tier = field(rec, "tier")
	out.address = field(rec, "address", "addr128")
	out.fqdn = field(rec, "fqdn")

	// --- Tier-1 WireGuard: the server echoes tier:wireguard + the wg-quick config fields. ---
	if out.isWireGuard() {
		out.wgServerPubKey = field(rec, "server_public_key")
		out.wgEndpoint = field(rec, "endpoint")
		out.wgDNS = field(rec, "dns")
		out.wgQuick = field(rec, "wireguard_config")
		out.wgPrivKeyB64 = field(rec, "client_private_key") // empty when WE supplied the public key
		if out.wgServerPubKey == "" && out.wgQuick == "" {
			return connectEnvelope{}, &client.ProblemError{Status: 502,
				Detail: "the control plane returned a WireGuard tier without a usable config"}
		}
		if out.wgEndpoint == "" {
			// Endpoint may still be inside the wg-quick blob; FromWgQuick recovers it. Only a
			// total absence (no field AND no blob) is fatal - caught above.
			_ = out.wgEndpoint
		}
		return out, nil
	}

	// --- Tier-1.5 egress (socks5/anyip): the bearer-carrying proxy form. ---
	// Prefer the TLS-to-proxy form (http_proxy = https://w:<token>@<tls-endpoint>): the
	// egress terminates TLS, so our local proxy wraps the upstream leg in TLS too. Fall
	// back to socks5_endpoint / connection_string for the host (still TLS on :443 - the
	// port multiplexes TLS, the proven live transport).
	httpProxy := field(rec, "http_proxy")
	host, bearer, isTLS := extractUpstream(httpProxy)
	if host != "" && !strings.Contains(host, ":") {
		// http_proxy carried a bare hostname with no explicit port (seen on the live
		// control plane). This tier always multiplexes TLS on :443 - the same port
		// socks5_endpoint/connection_string already carry - so default it rather than
		// handing bringUpEgress an undialable "host" with no port (Postel: liberal in
		// what we accept, never a silent half-connect).
		host += ":443"
	}
	if host == "" {
		// http_proxy absent/odd: derive the host from socks5_endpoint (the bare host:port)
		// and the bearer from connection_string (socks5h://w:<token>@<host>).
		host = strings.TrimSpace(field(rec, "socks5_endpoint"))
		if _, b, _ := extractUpstream(field(rec, "connection_string")); b != "" {
			bearer = b
		}
		isTLS = true // the egress multiplexes TLS on :443 (the proven HTTPS-CONNECT form)
	}
	if host == "" || bearer == "" {
		return connectEnvelope{}, &client.ProblemError{Status: 502,
			Detail: "the control plane returned an egress without a usable endpoint"}
	}
	out.upstreamHostPort = host
	out.bearer = bearer
	out.tlsToProxy = isTLS
	return out, nil
}

// extractUpstream parses a proxy URL of the form
// scheme://w:<bearer>@<host:port> into (host:port, bearer, isTLS). Liberal-accept:
// any scheme; missing userinfo ⇒ empty bearer; isTLS true only for https://. It never
// logs the input (it carries a secret).
func extractUpstream(proxyURL string) (host, bearer string, isTLS bool) {
	s := strings.TrimSpace(proxyURL)
	if s == "" {
		return "", "", false
	}
	if i := strings.Index(s, "://"); i >= 0 {
		isTLS = strings.EqualFold(s[:i], "https")
		s = s[i+3:]
	}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		userinfo := s[:at]
		s = s[at+1:]
		// userinfo is user:bearer - the bearer is everything after the first ':'.
		if c := strings.Index(userinfo, ":"); c >= 0 {
			bearer = userinfo[c+1:]
		} else {
			bearer = userinfo
		}
	}
	// Drop any trailing path.
	if sl := strings.IndexByte(s, '/'); sl >= 0 {
		s = s[:sl]
	}
	host = s
	return host, bearer, isTLS
}

// bringUpEgress starts the local proxy/tunnel for the parsed envelope and returns a
// live session (endpoint + local holder) - WITHOUT verifying yet. The caller folds verify
// in via verifyEgress. For the egress tier the bearer is handed to StartLocalProxy and never
// kept; for the WireGuard tier keys carries OUR private keys (in-memory only) - handed to the
// userspace device and never surfaced. keys is nil for the egress tiers.
//
// port pins the LOCAL loopback port (0 ⇒ a free one). Every interactive caller passes 0
// (zero-config); `whisper init`/`connect --ensure` pass the project's DETERMINISTIC port so
// the daemon always binds the same 127.0.0.1:<port> Claude Code's settings point at.
func bringUpEgress(ctx context.Context, ce connectEnvelope, keys *connectKeys, port int) (*egressSession, error) {
	if ce.isWireGuard() {
		return bringUpWireGuard(ce, keys, port)
	}
	proxy, err := egress.StartLocalProxy(ctx, ce.upstreamHostPort, ce.bearer, egress.Options{Port: port})
	if err != nil {
		return nil, &client.ProblemError{Status: 502,
			Detail: cleanProxyError(err)}
	}
	return &egressSession{
		endpoint: proxy.Endpoint(),
		addr:     ce.address,
		tier:     firstNonBlank(ce.tier, "socks5"),
		local:    proxy,
	}, nil
}

// cleanProxyError maps a local-proxy bring-up error to a plain remediation. A pinned-port
// collision (egress reports the port is in use) is surfaced verbatim - it is already a
// clear, secret-free, actionable line ("local port N is already in use…"); everything else
// collapses to the generic retry line (never a stack trace).
func cleanProxyError(err error) string {
	if err != nil && strings.Contains(err.Error(), "already in use") {
		return strings.TrimPrefix(err.Error(), "egress: ")
	}
	return "couldn't start the local connection - please try again"
}

// identityTLSPort is the standard HTTPS port the in-tunnel identity listener binds to on the
// agent's OWN /128 - the same port `whisper verify --trustless` / `openssl s_client` dial.
const identityTLSPort = 443

// identityDocBase returns the scheme://host of the control endpoint (the --control-url override, else the
// default graph.whisper.online), stripped of the /api/query path - the public base that serves the
// gateway-signed identity-doc / JWKS / did:web.
func identityDocBase() string {
	raw := strings.TrimSpace(g.controlURL)
	if raw == "" {
		raw = client.DefaultControlURL
	}
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return "https://graph.whisper.online"
}

// fetchIdentityDocs fetches the agent's gateway-signed well-known docs (identity-doc, JWKS, did:web) by
// its FQDN, for the in-tunnel listener to serve. The gateway keys the per-agent doc off the Host
// header, so the request dials the base host (a valid *.whisper.online cert / SNI) but carries the agent
// FQDN as Host - a deep agent FQDN never needs its own cert. Best-effort per doc: a miss is logged and
// skipped (the identity-doc is the one the verifier's fourth leg needs; jwks/did are Postel extras). The
// bytes are gateway-signed - the agent serves them verbatim, it signs nothing in-tunnel.
func fetchIdentityDocs(base, fqdn string, logf func(string, ...any)) []wgtun.ServedDoc {
	fqdn = strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
	if base == "" || fqdn == "" {
		return nil
	}
	wanted := []struct {
		path       string
		fallbackCT string
	}{
		{"/.well-known/whisper-identity", "application/jose"},
		{"/.well-known/jwks.json", "application/jwk-set+json"},
		{"/.well-known/did.json", "application/json"},
	}
	httpClient := &http.Client{Timeout: 8 * time.Second}
	var docs []wgtun.ServedDoc
	for _, w := range wanted {
		req, err := http.NewRequest(http.MethodGet, base+w.path, nil)
		if err != nil {
			continue
		}
		req.Host = fqdn // resolve the PER-AGENT doc by Host FQDN (SNI stays the base host)
		resp, err := httpClient.Do(req)
		if err != nil {
			if logf != nil && w.path == "/.well-known/whisper-identity" {
				logf("identity-doc fetch failed (%v) - the DANE leg still passes", err)
			}
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if rerr != nil || resp.StatusCode != http.StatusOK || len(body) == 0 {
			if logf != nil && w.path == "/.well-known/whisper-identity" {
				logf("identity-doc not available (status %d) - the DANE leg still passes", resp.StatusCode)
			}
			continue
		}
		ct := resp.Header.Get("Content-Type")
		if ct == "" {
			ct = w.fallbackCT
		}
		docs = append(docs, wgtun.ServedDoc{Path: w.path, ContentType: ct, Body: body})
	}
	return docs
}

// bringUpWireGuard brings up the userspace WireGuard tunnel (Tier-1) and returns a live
// session whose local SOCKS5/HTTP endpoint egresses from the agent's /128 over the tunnel. The
// private key is OURS (keys.wg, generated locally) on the best-practice path; only if the server
// minted one (zero-key path) do we fall back to its returned base64 client_private_key. The
// key is handed ONLY to the device and never surfaced/logged/persisted.
//
// When keys.identity is set (the default for this tier), it ALSO builds the self-signed
// agent-held leaf (SANs = the /128 that was just assigned + the canonical/friendly FQDN the server
// just returned - the pin submitted BEFORE connect still matches, since SANs never touch the SPKI)
// and starts a TLS listener INSIDE the tunnel's own netstack on :443, so a DANE-EE verifier dialing
// the agent's /128 is served THIS leaf - proving the tunnel itself, not a shared/wildcard listener, answers.
// Best-effort: a listener/leaf fault only logs (never a quiet-mode print) and never fails the connect
// - the egress data path is unaffected either way.
func bringUpWireGuard(ce connectEnvelope, keys *connectKeys, port int) (*egressSession, error) {
	var wgKey *wgtun.Keypair
	if keys != nil {
		wgKey = keys.wg
	}
	privHex := ""
	if wgKey != nil {
		privHex = wgKey.PrivateKeyHex
	}
	cfg, err := wgtun.FromWgQuick(ce.wgServerPubKey, ce.wgEndpoint, ce.address, ce.wgDNS, ce.wgQuick, privHex)
	if err != nil {
		return nil, &client.ProblemError{Status: 502,
			Detail: "the control plane returned an unusable WireGuard config"}
	}
	// Zero-key fallback: we sent no public key, so the server minted the keypair and returned
	// the private key once. Convert it to hex for the device. (The default path uses OUR key.)
	if cfg.PrivateKeyHex == "" && strings.TrimSpace(ce.wgPrivKeyB64) != "" {
		if hexKey, perr := wgtun.PrivateKeyBase64ToHex(ce.wgPrivKeyB64); perr == nil {
			cfg.PrivateKeyHex = hexKey
		}
	}
	// One safe operational line on reconnects (stderr; never a key/endpoint/target). Silent
	// under --quiet so a scripted endpoint capture stays clean.
	var logf func(string, ...any)
	if !g.quiet {
		logf = func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
	}
	// bind the port we declared, and keep the direct-peer map refreshed from the
	// control plane. PeerSource returning nothing - no key, no network, an empty map - leaves
	// every east-west packet relayed, which is the behaviour this shipped with before direct paths.
	cfg.ListenPort = wgListenPort
	tun, err := wgtun.Start(cfg, wgtun.Options{
		Logf:       logf,
		Port:       port,
		PeerSource: whalePeerSource(),
	})
	if err != nil {
		return nil, &client.ProblemError{Status: 502, Detail: cleanWgError(err)}
	}
	// serve the agent-held identity leaf on the tunnel's own /128:443, now that the server has
	// returned the assigned address + canonical/friendly FQDN. Best-effort - never fails bring-up.
	if keys != nil && keys.identity != nil {
		if addr, aerr := netip.ParseAddr(strings.TrimSpace(ce.address)); aerr == nil {
			// op:connect{tier:wireguard} returns only the canonical fqdn (no separate friendly-CNAME
			// column) - the leaf carries just that one dNSName SAN + the /128 iPAddress SAN.
			leaf, lerr := keys.identity.SelfSignedLeaf(ce.fqdn, "", addr)
			if lerr == nil {
				// Fetch the gateway-signed identity-doc (+jwks/did:web) so the in-tunnel listener
				// serves them, giving a trustless DANE verifier the full 4/4 (identity_doc no longer times
				// out). Best-effort - a fetch miss just leaves the DANE leg passing (3/4), never fails bring-up.
				docs := fetchIdentityDocs(identityDocBase(), ce.fqdn, logf)
				if serr := tun.ServeTLS(leaf, identityTLSPort, docs); serr != nil && logf != nil {
					logf("identity TLS listener not started (%v) - egress is unaffected", serr)
				}
			} else if logf != nil {
				logf("identity leaf not minted (%v) - egress is unaffected", lerr)
			}
		}
	}
	return &egressSession{
		endpoint: tun.Endpoint(),
		addr:     ce.address,
		tier:     "wireguard",
		local:    tun,
	}, nil
}

// cleanWgError maps a wgtun bring-up error to a plain, non-leaky remediation line.
func cleanWgError(err error) string {
	if err == nil {
		return "couldn't start the WireGuard tunnel - please try again"
	}
	return err.Error() // wgtun already returns friendly, secret-free messages
}

// verifyEgress folds the verify step in: it fetches the keyless echo THROUGH the local
// proxy and asserts the observed source IP is within 2a04:2a01::/32 AND == the selected
// agent's /128. On success sets s.verified; on a real mismatch returns a plain, friendly
// remediation (never a stack trace).
//
// A package var so a command test can stub the network echo when a one-shot verifies
// a REUSED daemon session (the fresh-connect tail is already stubbable via connectAndVerify).
var verifyEgress = verifyEgressLive

func verifyEgressLive(ctx context.Context, c *client.Client, s *egressSession) error {
	started := time.Now()
	observed, err := c.ObservedEgressIP(ctx, s.endpoint)
	if err != nil {
		return explainVerifyFailure(s, started, err)
	}
	// The v4-egress branch needs the host's OWN direct egress IP to compare against; fetch it ONLY
	// when the observed source is not a Whisper /128 (the common v6 case needs no direct fetch).
	direct, haveDirect := "", false
	if !inWhisperRange(observed) {
		if d, derr := c.DirectEgressIP(ctx); derr == nil {
			direct, haveDirect = d, true
		}
	}
	verdict := classifyEgress(observed, s.addr, direct, haveDirect)
	switch verdict.kind {
	case egressPinned:
		if s.addr == "" {
			s.addr = observed // adopt the observed /128 when the envelope did not carry one
		}
		s.verified = true
		return nil
	case egressTunnelled:
		s.verified = true // v4-via-NAT64: tunnelled through Whisper, /128 not pinnable from a v4 dest
		return nil
	case egressMismatch:
		return &client.ProblemError{Status: 502,
			Detail: "connected, but the address didn't match your agent - please try `whisper connect` again"}
	default: // egressNotThroughWhisper
		return &client.ProblemError{Status: 502,
			Detail: "your traffic isn't going through Whisper yet - please try `whisper connect` again"}
	}
}

// dialFailureSource is anything that remembers why its last upstream dial failed and when.
// Both local endpoints satisfy it: the Tier-1.5 egress proxy and the Tier-1 WireGuard tunnel
// are the same *egress.Proxy front-end underneath.
type dialFailureSource interface {
	LastDialFailure() (string, time.Time)
}

// explainVerifyFailure replaces the verify step's GUESS with what actually happened.
//
// The verify fetch leaves through the local proxy, so when it fails all the HTTP client can
// see is that the proxy would not carry it. Neither of the proxy's wire protocols can carry a
// reason - a SOCKS5 REP byte, a bodiless 502 - so the failure reached the CLI stripped of
// everything that mattered, and the CLI answered with the only thing it could think of: the
// session token was probably rejected, run `whisper connect` again. That sentence was printed
// on a Mac whose network was dropping UDP to the egress node, so the WireGuard tunnel never
// completed a handshake and no amount of re-connecting could have helped. A remedy that cannot
// work is worse than no remedy: it sends the person away from the thing that is actually
// broken.
//
// The dialer underneath does know which layer failed, and writes it as a sentence for a
// person; the front-end now keeps the last one. Take it - but ONLY when it belongs to THIS
// verification. A reason recorded before this fetch started is some earlier request's, and
// reporting it here would just be a different wrong answer. With nothing that qualifies, the
// original error stands unchanged.
func explainVerifyFailure(s *egressSession, started time.Time, err error) error {
	if s == nil {
		return err
	}
	src, ok := s.local.(dialFailureSource)
	if !ok {
		return err
	}
	why, at := src.LastDialFailure()
	if strings.TrimSpace(why) == "" || at.Before(started) {
		return err
	}
	return &client.ProblemError{Status: 502, Detail: why}
}

// egressVerdictKind is the pure classification of an egress-verify observation.
type egressVerdictKind int

const (
	egressNotThroughWhisper egressVerdictKind = iota // proxied source == host's direct source => a leak
	egressPinned                                     // observed IS a Whisper /128 matching the agent
	egressTunnelled                                  // v4-via-NAT64: shared SNAT, but provably tunnelled
	egressMismatch                                   // a Whisper /128, but NOT the selected agent's
)

type egressVerdict struct{ kind egressVerdictKind }

// classifyEgress is the PURE verify decision (no I/O), table-testable and the single place the
// security-critical logic lives:
// - observed ∈ 2a04:2a01::/32 (a Whisper /128): PINNED when it equals wantAddr (or wantAddr is
// empty), else MISMATCH (a Whisper identity, but not the one we asked for - never silently accept).
// - otherwise the echo was reached over IPv4 (a v6 /128 cannot source a v4 packet), so the server
// saw Whisper's SHARED v4 SNAT: TUNNELLED iff it provably differs from the host's own direct
// egress IP (haveDirect && observed != direct), OR the host has NO direct path at all
// (!haveDirect) yet the proxied echo still succeeded (Whisper is the only working path). If the
// proxied source EQUALS the host's direct source, the traffic is leaking straight out, NOT
// through Whisper: NOT-THROUGH-WHISPER (fail closed).
func classifyEgress(observed, wantAddr, direct string, haveDirect bool) egressVerdict {
	if inWhisperRange(observed) {
		if wantAddr != "" && !sameIP(observed, wantAddr) {
			return egressVerdict{egressMismatch}
		}
		return egressVerdict{egressPinned}
	}
	if !haveDirect || !sameIP(observed, direct) {
		return egressVerdict{egressTunnelled}
	}
	return egressVerdict{egressNotThroughWhisper}
}

// connectAndVerify is the full shared path: op:connect (already run by the caller, its
// result passed in) → local proxy/tunnel up → fold verify → a verified session. The caller
// owns Stop() (a persistent connect keeps it; a one-shot `whisper ip` stops on return).
//
// keys carries OUR locally-generated keypairs (WireGuard + identity) when the caller
// requested --tier wireguard (so bring-up has our private keys; the server only ever saw the
// public halves). It is nil for the socks5/anyip tiers. The private keys never leave this process.
//
// It is a package var (not a plain func) so command tests can stub the live-egress tail
// - the proxy bring-up + the network echo - while still exercising the op routing and
// the render/exit contract. Production assigns the real implementation below.
var connectAndVerify = connectAndVerifyLive

func connectAndVerifyLive(ctx context.Context, c *client.Client, res *client.Result, name string, keys *connectKeys) (*egressSession, error) {
	// Interactive callers (connect/run/ip/guided) use a free port - pin nothing.
	return connectAndVerifyOnPort(ctx, c, res, name, keys, 0)
}

// connectAndVerifyOnPort is connectAndVerifyLive with an explicit pinned local port (0 ⇒ a
// free one). The daemon path (`connect --ensure`) calls it with the project's DETERMINISTIC
// port so the held proxy always binds the same 127.0.0.1:<port>. It deliberately does NOT
// route through the connectAndVerify package var - the var is the stub seam for command
// tests, and the daemon binds a REAL port that those stubs must never shadow.
func connectAndVerifyOnPort(ctx context.Context, c *client.Client, res *client.Result, name string, keys *connectKeys, port int) (*egressSession, error) {
	ce, err := parseConnectEnvelope(res)
	if err != nil {
		return nil, err
	}
	sess, err := bringUpEgress(ctx, ce, keys, port)
	if err != nil {
		return nil, err
	}
	sess.name = strings.TrimSpace(name)
	if err := verifyEgress(ctx, c, sess); err != nil {
		sess.Stop()
		return nil, err
	}
	return sess, nil
}

// writeSuccessLine emits the ONE calm, Scandinavian success line on err, and the
// bearer-free endpoint on out only when quiet (so a script captures exactly one value).
//
//	default: stderr → "Connected as <name> - <addr> ✓ verified"
//	auto: stderr → the same line + " via <landed tier> <local endpoint>" (still ONE line:
//	          the user never asked for a tier, so the answer says which one they landed on
//	          and the proxy string to point tools at)
//	--quiet: stdout → "socks5h://127.0.0.1:<port>" (nothing else, anywhere)
func writeSuccessLine(out, errw io.Writer, s *egressSession, quiet bool) {
	if quiet {
		fmt.Fprintln(out, s.endpoint)
		return
	}
	label := s.name
	if label == "" {
		label = s.addr
	}
	tail := ""
	if s.negotiated {
		tail = " via " + landedTierNote(s.tier)
		if s.endpoint != "" {
			tail += " " + s.endpoint
		}
	}
	switch {
	case label != "" && s.addr != "":
		fmt.Fprintf(errw, "Connected as %s - %s ✓ verified%s\n", label, s.addr, tail)
	case s.addr != "":
		fmt.Fprintf(errw, "Connected - %s ✓ verified%s\n", s.addr, tail)
	default:
		fmt.Fprintf(errw, "Connected ✓ verified%s\n", tail)
	}
}
