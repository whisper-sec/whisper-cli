// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// A renewal (and so every 6-hourly check-in) declares the underlay again, on the port the running
// tunnel holds and at the host's addresses as they are now: the service reads a connect that
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
	keys := &connectKeys{identity: kp, direct: true, live: fixedPort(51900)}
	args := renewalArgs(base, keys, addr, time.Now())
	if eps, _ := args["endpoints"].([]string); len(eps) != 1 || eps[0] != "192.0.2.77:51900" {
		t.Fatalf("the renewal declares the host's addresses now, on the running tunnel's port: %v", args["endpoints"])
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
	// a session with no tunnel to declare declares nothing, whatever the base held
	if _, ok := renewalArgs(base, &connectKeys{identity: kp, direct: true}, addr, time.Now())["endpoints"]; ok {
		t.Fatal("no tunnel and no held socket is re-sent as no declaration")
	}
	// and a session whose tunnel takes no direct peers (the enforced run) never declares one
	if _, ok := renewalArgs(base, &connectKeys{identity: kp, live: fixedPort(51900)}, addr, time.Now())["endpoints"]; ok {
		t.Fatal("a session that takes no direct peers declared an underlay")
	}
	// a stopped tunnel holds no port, and declares none
	if _, ok := renewalArgs(base, &connectKeys{identity: kp, direct: true, live: fixedPort(0)}, addr, time.Now())["endpoints"]; ok {
		t.Fatal("a tunnel holding no port declared one")
	}
	if _, ok := renewalArgs(base, nil, addr, time.Now())["endpoints"]; ok {
		t.Fatal("with no keys there is no declaration to re-send")
	}
}

// Every holder that renews builds its keys through newConnectKeys, so each says, in one place,
// whether its tunnel takes direct peers (the daemon once built its own and its renewals then
// declared no direct path).
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
	if k := newConnectKeys(nil, nil, true); !k.direct {
		t.Fatal("a direct session's keys lost the flag")
	}
	if k := newConnectKeys(nil, nil, false); k.direct {
		t.Fatal("a session that takes no direct peers was marked as one")
	}
}

// fixedPort is a running tunnel as a declaration sees it: the port its device holds.
type fixedPort int

func (p fixedPort) ListenPort() int { return int(p) }
