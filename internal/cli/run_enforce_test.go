// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

func TestEnforcedEnvDropsProxiesAndSudoAndRestoresTheUser(t *testing.T) {
	base := []string{
		"PATH=/usr/bin", "HOME=/root", "USER=root", "LOGNAME=root", "MAIL=/var/mail/root",
		"ALL_PROXY=socks5h://127.0.0.1:1080", "https_proxy=http://127.0.0.1:3128", "Http_Proxy=x",
		"NO_PROXY=localhost", "NODE_USE_ENV_PROXY=1", "SUDO_USER=alice", "SUDO_UID=1000",
		"WHISPER_ENFORCED_ADDR=2a04:2a01::dead", "TERM=xterm",
	}
	got := envMap(enforcedEnv(base, "alice", "/home/alice", "", "2a04:2a01::42"))
	for _, k := range []string{"ALL_PROXY", "https_proxy", "Http_Proxy", "NO_PROXY", "NODE_USE_ENV_PROXY", "SUDO_USER", "SUDO_UID", "MAIL"} {
		if _, ok := got[k]; ok {
			t.Fatalf("%s must not reach an enforced agent", k)
		}
	}
	if got["HOME"] != "/home/alice" || got["USER"] != "alice" || got["LOGNAME"] != "alice" {
		t.Fatalf("the agent's own identity must be restored: %v", got)
	}
	if got["WHISPER_ENFORCED_ADDR"] != "2a04:2a01::42" {
		t.Fatal("the mark must be the enforced /128, never an inherited one")
	}
	if got["PATH"] != "/usr/bin" || got["TERM"] != "xterm" {
		t.Fatal("ordinary variables pass through")
	}
	if _, ok := got["XDG_RUNTIME_DIR"]; ok {
		t.Fatal("no runtime dir is named when it does not exist")
	}
	got = envMap(enforcedEnv(nil, "u", "/h", t.TempDir(), "a"))
	if got["XDG_RUNTIME_DIR"] == "" {
		t.Fatal("an existing runtime dir is named")
	}
}

func TestEnforceIsRefusedWithASentenceWhereThereAreNoNamespaces(t *testing.T) {
	err := enforceUnsupported("darwin")
	if err == nil || !strings.Contains(err.Error(), "needs Linux") || !strings.Contains(err.Error(), "Windows") ||
		!strings.Contains(err.Error(), "not started") {
		t.Fatalf("unsupported platform error: %v", err)
	}
}

func TestUserWithoutEnforceIsAUsageError(t *testing.T) {
	cmd := newRunCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--user", "nobody", "--", "true"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--user only applies with --enforce") {
		t.Fatalf("got %v", err)
	}
}

func TestEnforceWithoutRootIsRefusedBeforeAnythingHappens(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the root check is the Linux arm; elsewhere --enforce is refused outright")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: this case is the unprivileged refusal")
	}
	cmd := newRunCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--enforce", "--", "true"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "needs root") || !strings.Contains(err.Error(), "sudo whisper run --enforce") {
		t.Fatalf("got %v", err)
	}
}

func TestClaudeAcceptsEnforce(t *testing.T) {
	cmd := newClaudeCmd()
	if cmd.Flags().Lookup("enforce") == nil || cmd.Flags().Lookup("user") == nil {
		t.Fatal("whisper claude takes --enforce and --user, like run")
	}
}

func TestABorrowedIdentityKeyIsPreferredAndProvesPossession(t *testing.T) {
	defer idkey.SetIdentityDirForTest(t.TempDir())()
	kp, err := idkey.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	saved := identityBorrow
	defer func() { identityBorrow = saved }()
	asked := ""
	identityBorrow = func(h string) (*idkey.Keypair, bool) { asked = h; return kp, true }
	args := map[string]any{"public_key": "wgpub"}
	got, err := prepareIdentityKey(tierWireGuard, args, "2a04:2a01::42")
	if err != nil || got != kp {
		t.Fatalf("the borrowed key must be the one used: %v", err)
	}
	if asked != "2a04:2a01::42" {
		t.Fatalf("borrow asked for %q", asked)
	}
	if _, ok := args["identity_signature"]; !ok {
		t.Fatal("a borrowed key for a known /128 proves possession rather than re-pinning")
	}
	if _, ok := args["identity_public_key"]; ok {
		t.Fatal("no re-pin when possession is proved")
	}
	identityBorrow = func(string) (*idkey.Keypair, bool) { return nil, false }
	args = map[string]any{}
	if _, err := prepareIdentityKey(tierWireGuard, args, "agent-x"); err != nil {
		t.Fatal(err)
	}
	if _, ok := args["identity_public_key"]; ok {
		t.Fatal("with nothing to borrow, the sudo context must not mint a key of its own")
	}
}
