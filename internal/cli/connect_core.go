// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

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
	// Normalise the tier the server sees to the canonical token (so "wg" still selects WG).
	args["tier"] = "wireguard"
	return &kp, nil
}

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
	kp, err := idkey.LoadOrGenerate(handle)
	if err != nil {
		return nil, &client.ProblemError{Status: 500, Detail: "couldn't prepare an identity key - please try again"}
	}
	// The server hashes EXACTLY this base64 DER, verbatim - never a private key, never re-encoded.
	args["identity_public_key"] = kp.MarshalSPKIBase64()
	return kp, nil
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
	endpoint string        // socks5h://127.0.0.1:<port> - THE connection string (bearer/key-free)
	addr     string        // the agent's verified /128 (== the egress source)
	name     string        // the agent's human name (for the success line)
	tier     string        // "socks5" | "anyip" | "wireguard" - the active egress tier
	verified bool          // true when the egress source IP == the agent /128
	local    localEndpoint // the running proxy (Tier-1.5) or WG tunnel (Tier-1); nil in stubs
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
	wgServerPubKey string // the box's wg-agents public key, base64
	wgEndpoint     string // the box UDP endpoint, host:port (e.g. <box>:51826)
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

// bringUpWireGuard brings up the userspace WireGuard tunnel (Tier-1) and returns a live
// session whose local SOCKS5/HTTP endpoint egresses from the agent's /128 over the tunnel. The
// private key is OURS (keys.wg, generated locally) on the best-practice path; only if the server
// minted one (zero-key path) do we fall back to its returned base64 client_private_key. The
// key is handed ONLY to the device and never surfaced/logged/persisted.
//
// when keys.identity is set (the default for this tier), it ALSO builds the self-signed
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
	tun, err := wgtun.Start(cfg, wgtun.Options{Logf: logf, Port: port})
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
				if serr := tun.ServeTLS(leaf, identityTLSPort); serr != nil && logf != nil {
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
	observed, err := c.ObservedEgressIP(ctx, s.endpoint)
	if err != nil {
		return err
	}
	if !inWhisperRange(observed) {
		return &client.ProblemError{Status: 502,
			Detail: "your traffic isn't going through Whisper yet - please try `whisper connect` again"}
	}
	// When we know the selected agent's /128, require an exact match (the egress must
	// source from THIS identity). When the address is unknown (a rare envelope), a
	// Whisper-range source is still a pass (we can't pin it tighter).
	if s.addr != "" && !sameIP(observed, s.addr) {
		return &client.ProblemError{Status: 502,
			Detail: "connected, but the address didn't match your agent - please try `whisper connect` again"}
	}
	if s.addr == "" {
		s.addr = observed
	}
	s.verified = true
	return nil
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
//	default : stderr → "Connected as <name> - <addr> ✓ verified"
//	--quiet : stdout → "socks5h://127.0.0.1:<port>" (nothing else, anywhere)
func writeSuccessLine(out, errw io.Writer, s *egressSession, quiet bool) {
	if quiet {
		fmt.Fprintln(out, s.endpoint)
		return
	}
	label := s.name
	if label == "" {
		label = s.addr
	}
	switch {
	case label != "" && s.addr != "":
		fmt.Fprintf(errw, "Connected as %s - %s ✓ verified\n", label, s.addr)
	case s.addr != "":
		fmt.Fprintf(errw, "Connected - %s ✓ verified\n", s.addr)
	default:
		fmt.Fprintln(errw, "Connected ✓ verified")
	}
}
