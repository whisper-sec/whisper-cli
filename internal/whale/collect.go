// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// collect.go is the node-side half of the migration, and it exists because of a gap in
// their API rather than a gap in ours: there is no /device/{id}/serve path in the
// Tailscale API schema at all. Serve and funnel configuration is local tailscaled state,
// so the only way to read it is to stand on the node and ask.
//
// Everything here is read-only. The two commands it runs are `tailscale serve status
// --json` and `tailscale funnel status --json`, and there is no code path that runs
// anything else.
//
// The thing it must not do is report an absent binary as an absent configuration. A node
// with no tailscale binary and a node with nothing served are completely different facts,
// and one of them means "you are collecting on the wrong host". So every outcome is a
// named state, never a silent empty object.

// CommandRunner runs one command and returns its stdout. It is the seam that makes this
// testable on a host with no tailscale installed.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner is the real one.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			// Their stderr is the useful half of a failure, so carry it rather than
			// reporting a bare "exit status 1" that names nothing.
			return out, fmt.Errorf("%s: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return out, err
	}
	return out, nil
}

// The collect state vocabulary. Closed, and every value is a distinct fact.
const (
	// CollectNoBinary: there is no tailscale on this host, so nothing was asked.
	CollectNoBinary = "no tailscale binary on this host"
	// CollectNone: tailscale answered, and nothing is configured.
	CollectNone = "nothing configured"
	// CollectCaptured: tailscale answered with a configuration, kept verbatim.
	CollectCaptured = "captured"
	// CollectFailed: the command failed. This is NOT "nothing configured".
	CollectFailed = "could not be read"
)

// Collected is one node's local state.
type Collected struct {
	Host             string          `json:"host"`
	CollectedAt      string          `json:"collected_at"`
	TailscaleVersion string          `json:"tailscale_version,omitempty"`
	ServeState       string          `json:"serve_state"`
	Serve            json.RawMessage `json:"serve,omitempty"`
	FunnelState      string          `json:"funnel_state"`
	Funnel           json.RawMessage `json:"funnel,omitempty"`
	Notes            []string        `json:"notes,omitempty"`
}

// CollectLocal reads what the local node knows. It never returns an error: every failure
// is a state on the result, because a collect that aborted on the first missing binary
// would lose the half it could have captured.
func CollectLocal(run CommandRunner) *Collected {
	host, _ := os.Hostname()
	c := &Collected{
		Host:        host,
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		ServeState:  CollectNoBinary,
		FunnelState: CollectNoBinary,
	}
	if run == nil {
		c.Notes = append(c.Notes, "no command runner was configured, so nothing was read")
		return c
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if out, err := run(ctx, "tailscale", "version"); err == nil {
		c.TailscaleVersion = strings.TrimSpace(strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0])
	} else {
		c.Notes = append(c.Notes, "no usable `tailscale` binary here ("+Scrub(err.Error())+"). "+
			"Serve and funnel state can ONLY be read on the node itself, so run this command there.")
		return c
	}

	c.ServeState, c.Serve = collectOne(ctx, run, "serve", &c.Notes)
	c.FunnelState, c.Funnel = collectOne(ctx, run, "funnel", &c.Notes)
	return c
}

// collectOne runs one status command and classifies the outcome. An empty JSON object is
// "nothing configured"; a failure is "could not be read" with the reason.
func collectOne(ctx context.Context, run CommandRunner, verb string, notes *[]string) (string, json.RawMessage) {
	out, err := run(ctx, "tailscale", verb, "status", "--json")
	if err != nil {
		*notes = append(*notes, fmt.Sprintf("`tailscale %s status --json` failed: %s. That is not the same as "+
			"nothing being served, and this file says so rather than recording an empty config", verb, Scrub(err.Error())))
		return CollectFailed, nil
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" || trimmed == "{}" {
		return CollectNone, nil
	}
	var probe any
	if json.Unmarshal([]byte(trimmed), &probe) != nil {
		*notes = append(*notes, fmt.Sprintf("`tailscale %s status --json` did not answer with JSON; its output was kept as text", verb))
		b, _ := json.Marshal(trimmed)
		return CollectCaptured, b
	}
	return CollectCaptured, json.RawMessage(trimmed)
}

// SaveCollected writes the capture atomically, mode 0600.
func SaveCollected(path string, c *Collected) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("serialising the collected state: %w", err)
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".whalenet-collect-*")
	if err != nil {
		return fmt.Errorf("writing next to %s: %w", path, err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("setting mode 0600: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("writing the collected state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing the collected state: %w", err)
	}
	return os.Rename(name, path)
}
