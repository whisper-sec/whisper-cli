// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// whale_relayed_advice_test.go is a RELAYED row's punch advice on the command layer: the row the plane
// sends for a pair behind two NATs, read into a peer the tunnel punches inside the shared window, and
// everything about such a row this client refuses to act on.

const (
	adviceServerMs = int64(1_790_000_000_000) // the box's clock when it answered
	adviceKeyB64   = "YjEtcGVlci1rZXktMzItYnl0ZXMtbG9uZy1wYWQhISE="
	otherKeyB64    = "c29tZS1vdGhlci1rZXktMzItYnl0ZXMtbG9uZy1wYWQ="
)

// adviceAt is a window 20 s after the box's clock, numbered the way the plane numbers it.
func adviceAt() (at, slot int64) {
	at = adviceServerMs + 20_000
	return at, at / 60_000
}

func adviceHeader() map[string]any {
	return map[string]any{"item": map[string]any{
		"self": true, "address": "2a04:2a01:4::9", "state": "ok",
		"discovery": map[string]any{
			"server_time_ms": float64(adviceServerMs), "period_ms": float64(60_000),
			"window_ms": float64(6_000), "skew_tolerance_ms": float64(1_500),
		},
	}}
}

// relayedRow is the row the plane sends for a pair it relays and advises a punch for (the row's own keys
// with public_key and endpoint empty, then the advice).
func relayedRow(address, key, endpoint string) map[string]any {
	at, slot := adviceAt()
	return map[string]any{"item": map[string]any{
		"address": address, "agent": "ag_db", "name": "db-01", "path": "relayed",
		"public_key": "", "endpoint": "", "why": "no shared segment and no unrewritten public endpoint",
		"nat": "port-preserved", "nat_self": "port-preserved", "punch": "likely",
		"punch_why": "the peer: port preserved", "punch_endpoint": endpoint, "punch_family": "ipv4",
		"punch_key": key, "punch_at_ms": float64(at), "punch_until_ms": float64(at + 6_000),
		"punch_slot": float64(slot),
	}}
}

func item(row map[string]any) map[string]any { return row["item"].(map[string]any) }

// installable is the peers a read would install, leaving out the Listed markers that install nothing.
func installable(peers []wgtun.Peer) []wgtun.Peer {
	var out []wgtun.Peer
	for _, p := range peers {
		if !p.Listed {
			out = append(out, p)
		}
	}
	return out
}

func TestPeersFromRows_ARelayedRowWithPunchAdviceInstallsThePeerByItsPunchKey(t *testing.T) {
	sent := time.Now()
	received := sent.Add(80 * time.Millisecond)
	peers := installable(peersFromRowsRead([]map[string]any{
		adviceHeader(), relayedRow("2a04:2a01:4::7", adviceKeyB64, "198.51.100.4:51820"),
	}, sent, received))
	if len(peers) != 1 {
		t.Fatalf("installed %d peers for a relayed row carrying punch advice, want 1: %+v", len(peers), peers)
	}
	p := peers[0]
	want, _ := wgtun.ParsePeer(adviceKeyB64, "198.51.100.4:51820", "2a04:2a01:4::7", "", "")
	if p.PublicKeyHex != want.PublicKeyHex {
		t.Fatalf("the peer is keyed %q, want punch_key's %q", p.PublicKeyHex, want.PublicKeyHex)
	}
	if p.Address.String() != "2a04:2a01:4::7" || p.Endpoint != "198.51.100.4:51820" || p.Name != "db-01" {
		t.Fatalf("peer = %+v", p)
	}
	if len(p.Candidates) != 1 || p.Candidates[0].Source != wgtun.SourceObserved {
		t.Fatalf("candidates = %+v, want the one observed endpoint", p.Candidates)
	}
	// What the pair is once a handshake lands: through the NATs.
	if p.Path != "direct-punch" {
		t.Fatalf("class = %q, want direct-punch", p.Path)
	}
	// The window, placed by the box's clock: 20 s after the read's midpoint.
	if p.Rendezvous.IsZero() {
		t.Fatal("the peer carries no window, so it would be punched untimed")
	}
	at, slot := adviceAt()
	if d := p.Rendezvous.At.Sub(sent.Add(40 * time.Millisecond)); d != 20*time.Second {
		t.Fatalf("the window opens %v after the read's midpoint, want 20s", d)
	}
	if p.Rendezvous.Slot != slot || p.Rendezvous.Until.Sub(p.Rendezvous.At) != 6*time.Second || at <= 0 {
		t.Fatalf("window = %+v", p.Rendezvous)
	}
}

func TestPeersFromRows_TheWindowLandsWhereTheBoxMeantItWhateverOurClockSays(t *testing.T) {
	// The fixture's box clock reads a day in September 2026, weeks away from this host's: only the gap
	// between the box's clock and its window is used, so the window still opens 20 s from now.
	header := adviceHeader()
	now := time.Now()
	peers := installable(peersFromRowsRead([]map[string]any{header, relayedRow("2a04:2a01:4::7", adviceKeyB64, "198.51.100.4:51820")}, now, now))
	if len(peers) != 1 {
		t.Fatalf("got %+v", peers)
	}
	if d := peers[0].Rendezvous.At.Sub(now); d != 20*time.Second {
		t.Fatalf("window opens in %v, want 20s by the box's clock", d)
	}
}

func TestPeersFromRows_RefusesAdviceTheRowDoesNotVouchFor(t *testing.T) {
	now := time.Now()
	at, slot := adviceAt()
	cases := map[string]func(m map[string]any){
		"no punch_key":               func(m map[string]any) { m["punch_key"] = "" },
		"punch_key not a key":        func(m map[string]any) { m["punch_key"] = "c2hvcnQ=" },
		"public_key another key":     func(m map[string]any) { m["public_key"] = otherKeyB64 },
		"no endpoint":                func(m map[string]any) { m["punch_endpoint"] = "" },
		"a private endpoint":         func(m map[string]any) { m["punch_endpoint"] = "192.168.1.9:51820" },
		"a ULA endpoint":             func(m map[string]any) { m["punch_endpoint"] = "[fd12::9]:51820" },
		"a private one, signed port": func(m map[string]any) { m["punch_endpoint"] = "10.0.0.1:+51820" },
		"a ULA one, signed port":     func(m map[string]any) { m["punch_endpoint"] = "[fc00::1]:+443" },
		"a mapped private address":   func(m map[string]any) { m["punch_endpoint"] = "[::ffff:10.0.0.1]:51820" },
		"a loopback endpoint":        func(m map[string]any) { m["punch_endpoint"] = "127.0.0.1:51820" },
		"a tailnet endpoint":         func(m map[string]any) { m["punch_endpoint"] = "100.64.0.9:51820" },
		"the overlay as endpoint":    func(m map[string]any) { m["punch_endpoint"] = "[2a04:2a01:4::5]:51820" },
		"a hostname":                 func(m map[string]any) { m["punch_endpoint"] = "peer.example.com:51820" },
		"an endpoint that is a list": func(m map[string]any) { m["punch_endpoint"] = []any{"198.51.100.4:51820"} },
		"an address not an agent's":  func(m map[string]any) { m["address"] = "2001:db8::7" },
		"no window":                  func(m map[string]any) { delete(m, "punch_at_ms") },
		"a zero window":              func(m map[string]any) { m["punch_at_ms"], m["punch_until_ms"] = float64(0), float64(0) },
		"no slot":                    func(m map[string]any) { delete(m, "punch_slot") },
		"a slot one period off":      func(m map[string]any) { m["punch_slot"] = float64(slot + 1) },
		"a fractional instant":       func(m map[string]any) { m["punch_at_ms"] = float64(at) + 0.5 },
		"an instant past 2^53":       func(m map[string]any) { m["punch_at_ms"] = float64(1 << 60) },
		"a window of a minute":       func(m map[string]any) { m["punch_until_ms"] = float64(at + 60_000) },
		"a window an hour off": func(m map[string]any) {
			m["punch_at_ms"], m["punch_until_ms"], m["punch_slot"] = float64(at+3_600_000), float64(at+3_606_000), float64((at+3_600_000)/60_000)
		},
		"an instant that is a string": func(m map[string]any) { m["punch_at_ms"] = "soon" },
	}
	for why, mutate := range cases {
		row := relayedRow("2a04:2a01:4::7", adviceKeyB64, "198.51.100.4:51820")
		mutate(item(row))
		if peers := installable(peersFromRowsRead([]map[string]any{adviceHeader(), row}, now, now)); len(peers) != 0 {
			t.Fatalf("%s: installed %+v", why, peers)
		}
	}
	// A JSON number the decoder kept exact, and a decimal string, are read like a float64.
	row := relayedRow("2a04:2a01:4::7", adviceKeyB64, "198.51.100.4:51820")
	item(row)["punch_at_ms"] = json.Number("1790000020000")
	item(row)["punch_until_ms"] = "1790000026000"
	if peers := installable(peersFromRowsRead([]map[string]any{adviceHeader(), row}, now, now)); len(peers) != 1 {
		t.Fatalf("an exact JSON number or a decimal string was refused: %+v", peers)
	}
}

func TestPeersFromRows_AReadTooSlowToPlaceTheWindowInstallsNothingButKeepsWhatIsThere(t *testing.T) {
	sent := time.Now()
	all := peersFromRowsRead([]map[string]any{adviceHeader(), relayedRow("2a04:2a01:4::7", adviceKeyB64, "198.51.100.4:51820")},
		sent, sent.Add(4*time.Second))
	if len(installable(all)) != 0 {
		t.Fatalf("a 4s read placed a window with 1.5s of tolerance: %+v", all)
	}
	// The advice still vouches for its key, so a peer already installed with it is held, not removed.
	if len(all) != 1 || !all[0].Listed || !all[0].Hold || all[0].PublicKeyHex == "" {
		t.Fatalf("got %+v, want one held marker naming punch_key", all)
	}
}

func TestPeersFromRows_AVerdictOfNoEvidenceHoldsAndARefusalDoesNot(t *testing.T) {
	now := time.Now()
	unknown := relayedRow("2a04:2a01:4::7", "", "")
	item(unknown)["punch"] = "unknown"
	item(unknown)["punch_at_ms"], item(unknown)["punch_until_ms"], item(unknown)["punch_slot"] = float64(0), float64(0), float64(0)
	refused := relayedRow("2a04:2a01:4::8", "", "")
	item(refused)["punch"] = "unlikely"
	all := peersFromRowsRead([]map[string]any{adviceHeader(), unknown, refused}, now, now)
	if len(all) != 2 || len(installable(all)) != 0 {
		t.Fatalf("got %+v, want two markers and nothing to install", all)
	}
	for _, p := range all {
		want := p.Address.String() == "2a04:2a01:4::7"
		if p.Hold != want {
			t.Fatalf("%s: hold = %v, want %v (unknown holds, unlikely does not)", p.Address, p.Hold, want)
		}
	}
}

func TestPeersFromRows_KeysAddressesAndEndpointsMustBeOneToOne(t *testing.T) {
	now := time.Now()
	direct := func(addr, key, ep string) map[string]any {
		return map[string]any{"item": map[string]any{"address": addr, "path": "direct-public",
			"public_key": key, "endpoint": ep}}
	}
	cases := map[string][]map[string]any{
		"one key on two addresses": {
			relayedRow("2a04:2a01:4::7", adviceKeyB64, "198.51.100.4:51820"),
			relayedRow("2a04:2a01:4::8", adviceKeyB64, "198.51.100.5:51820"),
		},
		"a direct and a relayed row sharing a key": {
			direct("2a04:2a01:4::7", adviceKeyB64, "198.51.100.9:51820"),
			relayedRow("2a04:2a01:4::8", adviceKeyB64, "198.51.100.5:51820"),
		},
		"two keys on one address": {
			relayedRow("2a04:2a01:4::7", adviceKeyB64, "198.51.100.4:51820"),
			relayedRow("2a04:2a01:4::7", otherKeyB64, "198.51.100.5:51820"),
		},
		"one observed endpoint for two keys": {
			relayedRow("2a04:2a01:4::7", adviceKeyB64, "198.51.100.4:51820"),
			relayedRow("2a04:2a01:4::8", otherKeyB64, "198.51.100.4:51820"),
		},
	}
	for why, rows := range cases {
		if peers := installable(peersFromRowsRead(append([]map[string]any{adviceHeader()}, rows...), now, now)); len(peers) != 0 {
			t.Fatalf("%s: installed %+v", why, peers)
		}
	}
	// The control: the same two relayed rows with their own keys and endpoints both install.
	ok := installable(peersFromRowsRead([]map[string]any{adviceHeader(),
		relayedRow("2a04:2a01:4::7", adviceKeyB64, "198.51.100.4:51820"),
		relayedRow("2a04:2a01:4::8", otherKeyB64, "198.51.100.5:51820"),
	}, now, now))
	if len(ok) != 2 {
		t.Fatalf("two well-formed relayed rows installed %d peers, want 2", len(ok))
	}
}

func TestPeersFromRows_ADirectLocalRowIsPunchedAtOnceThenOnItsWindow(t *testing.T) {
	// A direct-local row whose advice names its own key keeps the local endpoint first and
	// the observed one after it, and is punched the untimed way, at once, because a LAN needs no window.
	// Once that first train is spent it falls back to the pair's window (Peer.Window), read here
	// from the advice a plane from before window_at_ms sends, so it stops sending every five seconds.
	row := localRowWithAdvice("198.51.100.4:51820", peerKeyB)
	at, slot := adviceAt()
	row["punch_at_ms"], row["punch_until_ms"], row["punch_slot"] = float64(at), float64(at+6_000), float64(slot)
	now := time.Now()
	peers := installable(peersFromRowsRead([]map[string]any{adviceHeader(), {"item": row}}, now, now))
	if len(peers) != 1 || !peers[0].Rendezvous.IsZero() || peers[0].Path != "direct-local" || len(peers[0].Candidates) != 2 {
		t.Fatalf("got %+v, want one direct-local peer punched at once, with both endpoints", peers)
	}
	if peers[0].Window.IsZero() || peers[0].Window.Slot != slot {
		t.Fatalf("got window %+v, want the pair's window for after the first train", peers[0].Window)
	}
}

func TestPeersFromRows_ADirectRowsWindowSurvivesASlowRead(t *testing.T) {
	// A read too slow to place a relayed pair's window (half a round trip above the
	// plane's 1.5 s) still places a direct row's, whose two ends only have to send within tens of seconds.
	at, slot := adviceAt()
	sent := time.Now()
	received := sent.Add(8 * time.Second)
	row := map[string]any{"address": "2a04:2a01:4::7", "path": "direct-public", "public_key": peerKeyB,
		"endpoint": "198.51.100.4:51820", "window_at_ms": float64(at), "window_until_ms": float64(at + 6_000),
		"window_slot": float64(slot)}
	peers := installable(peersFromRowsRead([]map[string]any{adviceHeader(), {"item": row}}, sent, received))
	if len(peers) != 1 || peers[0].Window.IsZero() {
		t.Fatalf("got %+v, want the direct row's window placed from an 8 s read", peers)
	}
	relayed := relayedRow("2a04:2a01:4::8", adviceKeyB64, "198.51.100.5:51820")
	if got := installable(peersFromRowsRead([]map[string]any{adviceHeader(), relayed}, sent, received)); len(got) != 0 {
		t.Fatalf("a relayed pair's window was placed from an 8 s read: %+v", got)
	}
}

func TestPeersFromRows_EveryDirectRowCarriesThePairsWindowWhenThePlaneSendsIt(t *testing.T) {
	at, slot := adviceAt()
	now := time.Now()
	public := map[string]any{"address": "2a04:2a01:4::7", "path": "direct-public", "public_key": peerKeyB,
		"endpoint": "198.51.100.4:51820", "punch": "not-needed", "punch_key": "", "tunnel_key": peerKeyB,
		"window_at_ms": float64(at), "window_until_ms": float64(at + 6_000), "window_slot": float64(slot)}
	peers := installable(peersFromRowsRead([]map[string]any{adviceHeader(), {"item": public}}, now, now))
	if len(peers) != 1 || peers[0].Window.IsZero() || !peers[0].Rendezvous.IsZero() {
		t.Fatalf("got %+v, want a direct peer with the pair's window and no relayed schedule", peers)
	}
	// A window this client cannot place is no window: the row is punched untimed, as every direct row was.
	bad := map[string]any{}
	for k, v := range public {
		bad[k] = v
	}
	bad["window_slot"] = float64(slot + 7)
	peers = installable(peersFromRowsRead([]map[string]any{adviceHeader(), {"item": bad}}, now, now))
	if len(peers) != 1 || !peers[0].Window.IsZero() {
		t.Fatalf("got %+v, want the row installed with no window", peers)
	}
	// A plane with no window on the row and no advice for its key: none.
	none := map[string]any{"address": "2a04:2a01:4::7", "path": "direct-public", "public_key": peerKeyB,
		"endpoint": "198.51.100.4:51820"}
	peers = installable(peersFromRowsRead([]map[string]any{adviceHeader(), {"item": none}}, now, now))
	if len(peers) != 1 || !peers[0].Window.IsZero() {
		t.Fatalf("got %+v, want no window", peers)
	}
}

func TestPeersFromRows_TheTunnelKeyIsReadAsWhatThePlaneVouchesFor(t *testing.T) {
	// Box two had no evidence about the pair (verdict "unknown"): what its row still says is which key the
	// plane binds to the address. Present and a key, present and empty, present and not a key, and absent
	// (a plane from before it) are four different statements, and the client keeps them apart.
	now := time.Now()
	row := func(tk any, present bool) map[string]any {
		r := relayedRow("2a04:2a01:4::7", "", "")
		item(r)["punch"] = "unknown"
		item(r)["punch_at_ms"], item(r)["punch_until_ms"], item(r)["punch_slot"] = float64(0), float64(0), float64(0)
		if present {
			item(r)["tunnel_key"] = tk
		}
		if tk == "none-state" {
			item(r)["tunnel_key"], item(r)["tunnel_key_state"] = "", "none"
		}
		return r
	}
	wantHex, _ := wgtun.KeyHex(adviceKeyB64)
	for _, c := range []struct {
		name    string
		tk      any
		present bool
		vouched bool
		key     string
	}{
		{"a key", adviceKeyB64, true, true, wantHex},
		{"empty", "", true, true, ""},
		{"not a key", "not-a-wireguard-key", true, true, wgtun.VouchedUnreadable},
		{"a number", float64(7), true, true, wgtun.VouchedUnreadable},
		{"null", nil, true, true, ""},
		{"no key at all", "none-state", true, true, wgtun.VouchedNone},
		{"absent", nil, false, false, ""},
	} {
		got := peersFromRowsRead([]map[string]any{adviceHeader(), row(c.tk, c.present)}, now, now)
		if len(got) != 1 || !got[0].Listed || !got[0].Hold || got[0].Vouched != c.vouched || got[0].VouchedKeyHex != c.key {
			t.Fatalf("%s: got %+v, want a held marker vouched=%v key=%q", c.name, got, c.vouched, c.key)
		}
	}
}

// TestWhalePeerSource_InstallsARelayedPairFromTheLiveRead is the wiring test: the real whalePeerSource,
// the one connect_core hands the tunnel, against a control plane that answers the peer map with a
// relayed, advised row. Take the advice out of the read path and this fails while every parse test
// above still passes.
func TestWhalePeerSource_InstallsARelayedPairFromTheLiveRead(t *testing.T) {
	whaleTestIsolation(t)
	var header map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The box's clock is this instant, so the window is 20 s from the answer.
		now := time.Now().UnixMilli()
		at := now + 20_000
		at -= at%60_000 - 1_000 // a second into its period, numbered by it
		if at < now+1_000 {
			at += 60_000
		}
		header = map[string]any{"self": true, "address": "2a04:2a01:4::9", "state": "ok", "peer_count": 1,
			"discovery": map[string]any{"server_time_ms": now, "period_ms": 60_000, "window_ms": 6_000, "skew_tolerance_ms": 1_500}}
		row := item(relayedRow("2a04:2a01:4::7", adviceKeyB64, "198.51.100.4:51820"))
		row["punch_at_ms"], row["punch_until_ms"], row["punch_slot"] = at, at+6_000, at/60_000
		body, _ := json.Marshal(map[string]any{"ok": true, "status": 200, "result": map[string]any{
			"columns": []string{"kind", "item"},
			"rows":    [][]any{{"whale-peers", header}, {"whale-peers", row}},
		}})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	g.key = "whisper_live_test"
	g.controlURL = srv.URL + "/api/query"

	peers, err := whalePeerSource()(context.Background())
	if err != nil {
		t.Fatalf("the peer source failed: %v", err)
	}
	got := installable(peers)
	if len(got) != 1 || got[0].Rendezvous.IsZero() || got[0].Path != "direct-punch" {
		t.Fatalf("the live read did not yield the timed peer: %+v", peers)
	}
	if d := time.Until(got[0].Rendezvous.At); d < 0 || d > 81*time.Second {
		t.Fatalf("the window opens in %v, want within the next period and a bit", d)
	}
	if !strings.Contains(got[0].Endpoint, "198.51.100.4") {
		t.Fatalf("endpoint = %q", got[0].Endpoint)
	}
}
