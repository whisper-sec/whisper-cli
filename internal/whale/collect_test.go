// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// collect_test.go asserts the distinction the whole command exists for: a node with no
// tailscale binary, a node with nothing served, and a node whose read FAILED are three
// different facts and must never collapse into one empty object.

func runnerFrom(out map[string]string, fail map[string]error) CommandRunner {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		if err, ok := fail[key]; ok {
			return nil, err
		}
		if v, ok := out[key]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("unexpected command: " + key)
	}
}

func TestCollectCapturesServeAndFunnel(t *testing.T) {
	c := CollectLocal(runnerFrom(map[string]string{
		"tailscale version":              "1.78.1\n  tailscale commit: abc",
		"tailscale serve status --json":  `{"TCP":{"443":{"HTTPS":true}}}`,
		"tailscale funnel status --json": `{"AllowFunnel":{"db-01:443":true}}`,
	}, nil))
	if c.ServeState != CollectCaptured || c.FunnelState != CollectCaptured {
		t.Fatalf("states: serve=%q funnel=%q", c.ServeState, c.FunnelState)
	}
	if c.TailscaleVersion != "1.78.1" {
		t.Fatalf("version %q", c.TailscaleVersion)
	}
	var probe map[string]any
	if err := json.Unmarshal(c.Serve, &probe); err != nil {
		t.Fatalf("the captured serve config is not JSON: %v", err)
	}
}

func TestCollectSaysWhenThereIsNoTailscaleHere(t *testing.T) {
	c := CollectLocal(runnerFrom(nil, map[string]error{"tailscale version": errors.New("executable file not found")}))
	if c.ServeState != CollectNoBinary || c.FunnelState != CollectNoBinary {
		t.Fatalf("a host with no tailscale reported serve=%q funnel=%q, which reads as \"nothing is served\"",
			c.ServeState, c.FunnelState)
	}
	if len(c.Notes) == 0 || !strings.Contains(strings.Join(c.Notes, " "), "on the node") {
		t.Fatalf("the note does not tell the operator to run this on the node: %v", c.Notes)
	}
}

func TestCollectTellsNothingConfiguredApartFromCouldNotRead(t *testing.T) {
	c := CollectLocal(runnerFrom(map[string]string{
		"tailscale version":             "1.78.1",
		"tailscale serve status --json": "{}",
	}, map[string]error{
		"tailscale funnel status --json": errors.New("exit status 1: funnel is not available"),
	}))
	if c.ServeState != CollectNone {
		t.Fatalf("an empty serve config must read as %q, got %q", CollectNone, c.ServeState)
	}
	if c.FunnelState != CollectFailed {
		t.Fatalf("a failed funnel read must read as %q, got %q", CollectFailed, c.FunnelState)
	}
	if c.Funnel != nil {
		t.Fatal("a failed read produced a config object")
	}
	if !strings.Contains(strings.Join(c.Notes, " "), "not the same as") {
		t.Fatalf("the note does not distinguish a failure from an absence: %v", c.Notes)
	}
}

func TestCollectWithNoRunnerSaysSo(t *testing.T) {
	c := CollectLocal(nil)
	if len(c.Notes) == 0 {
		t.Fatal("a collect with no runner reported nothing at all")
	}
}

func TestSaveCollectedIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "collect.json")
	c := CollectLocal(runnerFrom(map[string]string{
		"tailscale version":              "1.78.1",
		"tailscale serve status --json":  "{}",
		"tailscale funnel status --json": "{}",
	}, nil))
	if err := SaveCollected(path, c); err != nil {
		t.Fatalf("SaveCollected: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode %o", perm)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".whalenet-collect-") {
			t.Fatalf("a temporary file was left behind: %s", e.Name())
		}
	}
}

func TestCollectScrubsASecretOutOfAFailureMessage(t *testing.T) {
	c := CollectLocal(runnerFrom(map[string]string{"tailscale version": "1.78.1"},
		map[string]error{
			"tailscale serve status --json":  errors.New("bad key tskey-auth-kSECRET1234-abcdefgh"),
			"tailscale funnel status --json": errors.New("bad key tskey-auth-kSECRET1234-abcdefgh"),
		}))
	joined := strings.Join(c.Notes, " ")
	if strings.Contains(joined, "kSECRET1234") {
		t.Fatalf("a secret from a local command's stderr was written into the capture: %s", joined)
	}
}
