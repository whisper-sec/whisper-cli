// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/projcfg"
	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// deepencli_helpers_test.go: the shared harness for the wave-7 "deepen-cli" tests.
// Every helper here is prefixed deepencli_ so it can never collide with the wave 0-6
// suite's helpers (withGlobals, recordingServer, captureStd, ...) which we reuse as-is.

// deepencli_globals swaps the package globals for one test and restores them on cleanup.
// Mirrors the savedG/defer pattern the existing command tests use, minus the boilerplate.
func deepencli_globals(t *testing.T, ng globalFlags) {
	t.Helper()
	saved := g
	g = ng
	t.Cleanup(func() { g = saved })
}

// deepencli_keyedGlobals points the CLI at a stub control plane with a test key, the
// standard shape for a dispatch test (quiet keeps the human chrome out of the way).
func deepencli_keyedGlobals(t *testing.T, controlURL string) {
	t.Helper()
	deepencli_globals(t, globalFlags{controlURL: controlURL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second})
}

// deepencli_hermeticEnv isolates a test from the real user: a temp home (so the key
// ladder, the agent file, and migrateLegacyConfigDir never touch the real
// ~/.config/whisper) and no credential env. Returns the temp home.
//
// It is a one-line alias for testenv.HermeticHome, kept only because every helper in
// this suite carries the deepencli_ prefix. The isolation itself now lives in one
// place for the whole module: writing it out by hand at each site is exactly how it
// came to be POSIX-only, and how a unit test asserting a clean 401 ended up listing
// production agents on Windows.
func deepencli_hermeticEnv(t *testing.T) string {
	t.Helper()
	return testenv.HermeticHome(t)
}

// deepencli_exec silences and executes a cobra command with args, returning its error.
func deepencli_exec(t *testing.T, cmd *cobra.Command, args ...string) error {
	t.Helper()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(args)
	return cmd.Execute()
}

// deepencli_projectPaths resolves the per-project paths for a (temp) root.
func deepencli_projectPaths(t *testing.T, root string) projcfg.Paths {
	t.Helper()
	if root == "" {
		root = t.TempDir()
	}
	return projcfg.PathsFor(root)
}

// deepencli_projectConfig builds a minimal valid `.whisper/config` value.
func deepencli_projectConfig(agent, tier string, port int) projcfg.Config {
	return projcfg.Config{SchemaVersion: 1, Agent: agent, Tier: tier, Port: port}
}

// deepencli_pyEnvResult is the zero proxy-env result the summary renderers take.
func deepencli_pyEnvResult() projcfg.PyEnvResult { return projcfg.PyEnvResult{} }

// deepencli_bodyContaining finds the first recorded control-plane body containing substr.
// Needed because sniffOp does not know every op token (e.g. op:'token' sniffs as "list"),
// so bodyForOp cannot find those; a raw substring scan can.
func deepencli_bodyContaining(seen []recordedCall, substr string) (string, bool) {
	for _, c := range seen {
		if strings.Contains(c.body, substr) {
			return c.body, true
		}
	}
	return "", false
}
