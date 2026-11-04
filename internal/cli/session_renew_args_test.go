// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// A renewal (and so every 6-hourly check-in) declares the underlay again, on the port the session
// declared it on and at the host's addresses as they are now: the service reads a connect that
// declares none as a node with no direct path, so a check-in on a healthy tunnel would put every
// east-west packet back on the relay, and replaying the first connect's addresses would declare a
// dead path once the host had roamed. It never re-sends a vehicle
// binding: that derives the address at the first connect and needs the key beside it, while a
// renewal names the address it holds and proves the key, and the binding alone would be refused.
func TestRenewalKeepsTheDeclaredUnderlayAndDropsTheVehicleBinding(t *testing.T) {
	restore := idkey.SetIdentityDirForTest(t.TempDir())
	defer restore()
	const addr = "2a04:2a01:0:1::b16"
	kp, err := idkey.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	saved := underlayEndpoints
	defer func() { underlayEndpoints = saved }()
	roamed := "192.0.2.77"
	underlayEndpoints = func(port int) []string { return []string{fmt.Sprintf("%s:%d", roamed, port)} }
	base := map[string]any{"label": "car", "vin": "1HGCM82633A004352", "ecu_serial": "E1", "endpoints": "stale"}
	keys := &connectKeys{identity: kp, listenPort: 51900}
	args := renewalArgs(base, keys, addr, time.Now())
	if eps, _ := args["endpoints"].([]string); len(eps) != 1 || eps[0] != "192.0.2.77:51900" {
		t.Fatalf("the renewal declares the host's addresses now, on the session's port: %v", args["endpoints"])
	}
	// a host with no underlay address now declares nothing, rather than a path that is gone
	underlayEndpoints = func(int) []string { return nil }
	if _, ok := renewalArgs(base, keys, addr, time.Now())["endpoints"]; ok {
		t.Fatal("no underlay now is no declaration")
	}
	for _, k := range []string{"vin", "ecu_serial"} {
		if _, ok := args[k]; ok {
			t.Fatalf("a renewal carries no %s: %v", k, args)
		}
	}
	if args["label"] != "car" || args["agent"] != addr || args["identity_signature"] == nil {
		t.Fatalf("the rest of the base and the proof stay: %v", args)
	}
	// a session that declared nothing declares nothing again, whatever the base held
	if _, ok := renewalArgs(base, &connectKeys{identity: kp}, addr, time.Now())["endpoints"]; ok {
		t.Fatal("no declaration is re-sent as none")
	}
	if _, ok := renewalArgs(base, nil, addr, time.Now())["endpoints"]; ok {
		t.Fatal("with no keys there is no declaration to re-send")
	}
}

// The declaration a renewal re-sends is the one the session's own connect made.
func TestTheConnectKeepsItsUnderlayDeclarationForTheRenewal(t *testing.T) {
	defer idkey.SetIdentityDirForTest(t.TempDir())()
	saved := prepareWireGuard
	prepareWireGuard = func(tier string, args map[string]any) (*wgtun.Keypair, error) {
		kp, err := wgtun.GenerateKeypair()
		if err != nil {
			return nil, err
		}
		args["public_key"] = kp.PublicKeyBase64
		args["endpoints"] = []string{"192.0.2.11:51901"}
		wgListenPort = 51901
		return &kp, nil
	}
	savedPort := wgListenPort
	defer func() { prepareWireGuard, wgListenPort = saved, savedPort }()
	srv := autoTierServer(t, nil, wgConnectReplyJSON(), s5ConnectReplyJSON())
	defer srv.Close()
	c := client.New(client.Config{ControlURL: srv.URL, Cred: client.Credential{Value: "whisper_live_test",
		Source: client.SourceFlag}, Timeout: 5 * time.Second})
	_, keys, err := connectTierEnvelope(context.Background(), c, map[string]any{}, tierWireGuard, "")
	if err != nil {
		t.Fatal(err)
	}
	if keys.listenPort != wgListenPort || keys.listenPort == 0 {
		t.Fatalf("the session keeps the port its connect declared on: %d (declared %d)", keys.listenPort, wgListenPort)
	}
}

// Every holder that renews builds its keys through newConnectKeys, so none can lose the port its
// underlay was declared on (the daemon did, once: its renewals then declared no direct path).
func TestEverySessionsKeysComeFromTheOneConstructor(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var literals []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "&connectKeys{") {
				literals = append(literals, fmt.Sprintf("%s:%d", f, i+1))
			}
		}
	}
	if len(literals) != 1 || !strings.HasPrefix(literals[0], "connect_core.go:") {
		t.Fatalf("connectKeys is built only inside newConnectKeys, found: %v", literals)
	}
	saved := wgListenPort
	defer func() { wgListenPort = saved }()
	wgListenPort = 51902
	if k := newConnectKeys(nil, nil, map[string]any{"endpoints": []string{"192.0.2.12:51902"}}); k.listenPort != 51902 {
		t.Fatalf("a declared underlay keeps its port: %d", k.listenPort)
	}
	if k := newConnectKeys(nil, nil, map[string]any{}); k.listenPort != 0 {
		t.Fatalf("no declaration keeps no port: %d", k.listenPort)
	}
}
