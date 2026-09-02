// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// The typed-identity flags register an object under a domain-specific identifier it
// already carries (a VIN, a 5G NF Instance ID, an IEEE 2030.5 LFDI, a medical UDI, an OPC-UA
// ApplicationUri, a C2PA signer serial, an A2A/x402 agent id). Each sets the derivation's
// device_id and implies op:register (the op that stores + surfaces the device attribution). A
// DETERMINISTIC device-key-derived /128 is the routed connect path (`connect --tier wireguard
// --vin`), covered separately. These tests assert the call SHAPE (which op, which args) without a
// live control plane; the live end-to-end (a real /128 + reverse DNS) is proven separately.

// TestCreate_TypedIdentifiers_SetDeviceID drives EACH typed-identity flag and asserts it implies
// the op:register path (device attribution) carrying device_id set to exactly the identifier value.
func TestCreate_TypedIdentifiers_SetDeviceID(t *testing.T) {
	cases := []struct {
		flag, val, wantDevice string
	}{
		{"--vin", "1HGCM82633A004352", "1HGCM82633A004352"},
		{"--nf-instance-id", "nf-5g-0007", "nf-5g-0007"},
		{"--lfdi", "3F2A9C1B", "3F2A9C1B"},
		{"--udi", "(01)00844588003288", "(01)00844588003288"},
		{"--applicationuri", "urn:opcua:plc:asset42", "urn:opcua:plc:asset42"},
		{"--c2pa-serial", "cawg-signer-99", "cawg-signer-99"},
		{"--agent-id", "a2a-agent-xyz", "a2a-agent-xyz"},
	}
	for _, c := range cases {
		t.Run(c.flag, func(t *testing.T) {
			var seen []recordedCall
			srv := recordingServer(t, nil, &seen)
			defer srv.Close()

			savedG := g
			g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
			defer func() { g = savedG }()

			cmd := newCreateCmd()
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			cmd.SetArgs([]string{"--name", "obj", c.flag, c.val})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("create %s errored: %v", c.flag, err)
			}
			body, ok := bodyForOp(seen, "register")
			if !ok {
				t.Fatalf("%s must fire op:register, ops=%v", c.flag, opsSeen(seen))
			}
			want := "device_id:'" + c.wantDevice + "'"
			if !strings.Contains(body, want) {
				t.Fatalf("%s must set %s; body=%q", c.flag, want, body)
			}
		})
	}
}

// TestCreate_VinPlusEcu_CombinesDeterministically: --vin + --ecu-serial identify one ECU within
// one vehicle, so they combine into a single deterministic device_id.
func TestCreate_VinPlusEcu_CombinesDeterministically(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newCreateCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--name", "ecu", "--vin", "WVWZZZ1KZ", "--ecu-serial", "ECU-7"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("create --vin --ecu-serial errored: %v", err)
	}
	body, _ := bodyForOp(seen, "register")
	if !strings.Contains(body, "device_id:'vin:WVWZZZ1KZ;ecu:ECU-7'") {
		t.Fatalf("vin+ecu must combine into one device_id; body=%q", body)
	}
}

// TestCreate_MutuallyExclusiveIdentifiers: two typed identifiers is a clear usage error (an
// object has ONE identity) and NOTHING is created.
func TestCreate_MutuallyExclusiveIdentifiers(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newCreateCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--name", "x", "--vin", "V1", "--lfdi", "L1"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("two typed identifiers must error")
	}
	if !isUsageError(err) {
		t.Fatalf("want a usage error, got %v", err)
	}
	if containsOp(opsSeen(seen), "identity") || containsOp(opsSeen(seen), "register") {
		t.Fatalf("a rejected create must fire NO create op, ops=%v", opsSeen(seen))
	}
}

// TestCreate_EcuSerialWithoutVin: --ecu-serial alone is a clear usage error (the ECU is scoped
// within its vehicle).
func TestCreate_EcuSerialWithoutVin(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newCreateCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--name", "x", "--ecu-serial", "ECU-1"})
	if err := cmd.Execute(); err == nil || !isUsageError(err) {
		t.Fatalf("--ecu-serial without --vin must be a usage error, got %v", err)
	}
}

// TestCreate_Wallet_PublishesBindingViaHost: --wallet pins an x402 wallet to the just-created
// /128 by publishing a TXT binding via op:host at `_x402.<fqdn>`, with the wallet+chain value.
func TestCreate_Wallet_PublishesBindingViaHost(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newCreateCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--name", "payer", "--wallet", "0x8F3a91B2", "--wallet-chain", "eip155:8453"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("create --wallet errored: %v", err)
	}
	// It must create the identity FIRST, then publish the binding.
	ops := opsSeen(seen)
	if !containsOp(ops, "identity") || !containsOp(ops, "host") {
		t.Fatalf("create --wallet must fire op:identity then op:host, ops=%v", ops)
	}
	body, _ := bodyForOp(seen, "host")
	if !strings.Contains(body, "type:'TXT'") {
		t.Fatalf("wallet binding must be a TXT record; body=%q", body)
	}
	if !strings.Contains(body, "name:'_x402.created-name'") {
		t.Fatalf("wallet binding must anchor at _x402.<agent-fqdn>; body=%q", body)
	}
	if !strings.Contains(body, "x402-wallet=0x8F3a91B2;chain=eip155:8453") {
		t.Fatalf("wallet binding value must carry the wallet + chain; body=%q", body)
	}
}

// TestCreate_NoIdentifier_NoDeviceID: the common case (no typed flag) carries NO device_id, so
// the server allocates a fresh /128 exactly as before (no behaviour change for the default path).
func TestCreate_NoIdentifier_NoDeviceID(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newCreateCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--name", "plain"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("create errored: %v", err)
	}
	body, _ := bodyForOp(seen, "identity")
	if strings.Contains(body, "device_id") {
		t.Fatalf("a plain create must carry NO device_id; body=%q", body)
	}
}

// TestConnect_Vin_SetsNamedArgs: on connect, --vin (+ --ecu-serial) pass NAMED vin/ecu_serial
// args to op:connect (the shipped automotive routed-/128 path), not device_id.
func TestConnect_Vin_SetsNamedArgs(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "car", addr: "2a04:2a01:1::1"}}, &seen)
	defer srv.Close()
	defer stubEgressTail(t)()
	defer idkey.SetIdentityDirForTest(t.TempDir())() // the AUTO Tier-1 attempt mints a real identity key

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newConnectCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--agent", "car", "--vin", "1HGCM82633A004352", "--ecu-serial", "ECU-9"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("connect --vin errored: %v", err)
	}
	body, ok := bodyForOp(seen, "connect")
	if !ok {
		t.Fatalf("connect --vin must fire op:connect, ops=%v", opsSeen(seen))
	}
	if !strings.Contains(body, "vin:'1HGCM82633A004352'") {
		t.Fatalf("connect --vin must set the named vin arg; body=%q", body)
	}
	if !strings.Contains(body, "ecu_serial:'ECU-9'") {
		t.Fatalf("connect --ecu-serial must set the named ecu_serial arg; body=%q", body)
	}
}

// TestConnect_EcuSerialWithoutVin: --ecu-serial without --vin on connect is a usage error.
func TestConnect_EcuSerialWithoutVin(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "car", addr: "2a04:2a01:1::1"}}, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newConnectCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--agent", "car", "--ecu-serial", "ECU-1"})
	if err := cmd.Execute(); err == nil || !isUsageError(err) {
		t.Fatalf("connect --ecu-serial without --vin must be a usage error, got %v", err)
	}
}
