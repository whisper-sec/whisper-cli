// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// deepencli_more_test.go: the second sweep of achievable-without-root branches -
// crypto command guards, the MCP project install, login's device-flow seam, stdin
// prompts, and the guided one-agent branch.

// --- encrypt / decrypt guards -----------------------------------------------------

func TestDeepenCLI_EncryptCmd_MissingRecipientIsClear(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	err := deepencli_exec(t, newEncryptCmd())
	if err == nil || !strings.Contains(err.Error(), "--to") {
		t.Fatalf("encrypt without --to must name the missing flag, got %v", err)
	}
}

func TestDeepenCLI_EncryptCmd_UnreadableInputFailsBeforeDNS(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	absent := filepath.Join(t.TempDir(), "absent.txt")
	// The resolver default would hit the live DNS; failing BEFORE it proves the input
	// check runs first (no resolver override is set on purpose).
	err := deepencli_exec(t, newEncryptCmd(), "--to", "a1.agents.whisper.online", absent)
	if err == nil || !strings.Contains(err.Error(), "read "+absent) {
		t.Fatalf("an unreadable input must fail with the read error, got %v", err)
	}
}

func TestDeepenCLI_DecryptCmd_RejectsNonWencInput(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	f := filepath.Join(t.TempDir(), "not-encrypted.bin")
	if err := os.WriteFile(f, []byte("just plain bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := deepencli_exec(t, newDecryptCmd(), f)
	if err == nil || !strings.Contains(err.Error(), "neither an armored nor a raw") {
		t.Fatalf("non-wenc input must be rejected with the honest format error, got %v", err)
	}
}

func TestDeepenCLI_ReadInput_StdinDash(t *testing.T) {
	deepencli_pipeStdin(t, "streamed-bytes")
	data, name, err := readInput(nil)
	if err != nil || name != "" || string(data) != "streamed-bytes" {
		t.Fatalf("no-args must read stdin with no name: %q %q %v", data, name, err)
	}
	deepencli_pipeStdin(t, "dashed")
	data, _, err = readInput([]string{"-"})
	if err != nil || string(data) != "dashed" {
		t.Fatalf("an explicit - must read stdin: %q %v", data, err)
	}
}

// --- sign command guards ----------------------------------------------------------

func TestDeepenCLI_SignVerifyCmd_RequiresSigAndReadableFiles(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	dir := t.TempDir()
	content := filepath.Join(dir, "doc.pdf")
	if err := os.WriteFile(content, []byte("doc"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No --sig: the one required flag is named.
	err := deepencli_exec(t, newSignVerifyCmd(), content)
	if err == nil || !strings.Contains(err.Error(), "--sig") {
		t.Fatalf("verify without --sig must name it, got %v", err)
	}
	// Unreadable content file.
	err = deepencli_exec(t, newSignVerifyCmd(), filepath.Join(dir, "absent"), "--sig", content)
	if err == nil || !strings.Contains(err.Error(), "read ") {
		t.Fatalf("an unreadable content file must fail clearly, got %v", err)
	}
	// Unreadable signature file.
	err = deepencli_exec(t, newSignVerifyCmd(), content, "--sig", filepath.Join(dir, "absent.p7s"))
	if err == nil || !strings.Contains(err.Error(), "read ") {
		t.Fatalf("an unreadable signature file must fail clearly, got %v", err)
	}
	// A present but garbage signature fails the CMS parse CLOSED (never a pass).
	garbage := filepath.Join(dir, "garbage.p7s")
	if err := os.WriteFile(garbage, []byte("not a signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = deepencli_exec(t, newSignVerifyCmd(), content, "--sig", garbage)
	if err == nil || !strings.Contains(err.Error(), "parse signature") {
		t.Fatalf("garbage signature must fail the parse, got %v", err)
	}
}

func TestDeepenCLI_SignFileCmd_UnreadableInputFailsBeforeTheControlPlane(t *testing.T) {
	// controlURL points at a dead port: reaching it would fail differently, so the
	// read error proves the file check runs first.
	deepencli_globals(t, globalFlags{controlURL: "http://127.0.0.1:1", key: "whisper_live_x", timeout: time.Second})
	absent := filepath.Join(t.TempDir(), "absent.pdf")
	err := deepencli_exec(t, newSignFileCmd(), absent)
	if err == nil || !strings.Contains(err.Error(), "read "+absent) {
		t.Fatalf("an unreadable input must fail with the read error, got %v", err)
	}
}

// --- mcp install ------------------------------------------------------------------

func TestDeepenCLI_RunMCPInstall_WritesBothProjectConfigs(t *testing.T) {
	deepencli_globals(t, globalFlags{quiet: true})
	root := t.TempDir()
	if err := runMCPInstall(root); err != nil {
		t.Fatalf("mcp install: %v", err)
	}
	for _, rel := range []string{".mcp.json", filepath.Join(".cursor", "mcp.json")} {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("mcp install must write %s: %v", rel, err)
		}
		var cfg map[string]any
		if err := json.Unmarshal(b, &cfg); err != nil {
			t.Fatalf("%s must be strict JSON: %v", rel, err)
		}
		servers, ok := cfg["mcpServers"].(map[string]any)
		if !ok || servers["whisper"] == nil {
			t.Fatalf("%s must register the whisper server under mcpServers: %v", rel, cfg)
		}
	}
	// Idempotent: a re-run refreshes in place, never errors or duplicates.
	if err := runMCPInstall(root); err != nil {
		t.Fatalf("mcp install re-run must be idempotent: %v", err)
	}
	// A pre-existing FOREIGN server survives the surgical merge.
	pre := filepath.Join(root, ".mcp.json")
	var cfg map[string]any
	b, _ := os.ReadFile(pre)
	_ = json.Unmarshal(b, &cfg)
	cfg["mcpServers"].(map[string]any)["other"] = map[string]any{"command": "other-tool"}
	nb, _ := json.Marshal(cfg)
	if err := os.WriteFile(pre, nb, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runMCPInstall(root); err != nil {
		t.Fatalf("merge over a foreign server: %v", err)
	}
	b, _ = os.ReadFile(pre)
	_ = json.Unmarshal(b, &cfg)
	servers := cfg["mcpServers"].(map[string]any)
	if servers["other"] == nil || servers["whisper"] == nil {
		t.Fatalf("the merge must keep foreign servers AND ours: %v", servers)
	}
}

// --- login --web via the device-flow seam ----------------------------------------

func TestDeepenCLI_LoginCmd_WebRunsTheDeviceFlowAndSaves(t *testing.T) {
	deepencli_hermeticEnv(t)
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	kf := filepath.Join(t.TempDir(), "key")
	deepencli_globals(t, globalFlags{controlURL: srv.URL, keyFile: kf, consoleURL: "http://console.test", timeout: 5 * time.Second})

	saved := deviceFlowFn
	var gotConsole string
	deviceFlowFn = func(consoleURL string, _ time.Duration) (string, error) {
		gotConsole = consoleURL
		return "whisper_live_from_device_flow", nil
	}
	t.Cleanup(func() { deviceFlowFn = saved })

	captureStd(t, func() {
		if err := deepencli_exec(t, newLoginCmd(), "--web"); err != nil {
			t.Errorf("login --web errored: %v", err)
		}
	})
	if gotConsole != "http://console.test" {
		t.Fatalf("the --console-url override must reach the flow, got %q", gotConsole)
	}
	if b, _ := os.ReadFile(kf); !strings.Contains(string(b), "whisper_live_from_device_flow") {
		t.Fatalf("the issued key must be saved, got %q", b)
	}
}

func TestDeepenCLI_LoginCmd_WebFlowFailureSurfaces(t *testing.T) {
	deepencli_hermeticEnv(t)
	deepencli_globals(t, globalFlags{keyFile: filepath.Join(t.TempDir(), "key")})
	saved := deviceFlowFn
	deviceFlowFn = func(string, time.Duration) (string, error) {
		return "", errors.New("authorization expired")
	}
	t.Cleanup(func() { deviceFlowFn = saved })

	err := deepencli_exec(t, newLoginCmd(), "--web")
	if err == nil || !strings.Contains(err.Error(), "authorization expired") {
		t.Fatalf("a failed device flow must surface its error, got %v", err)
	}
	if _, serr := os.Stat(g.keyFile); serr == nil {
		t.Fatal("no key may be saved when the flow failed")
	}
}

// --- stdin prompts ----------------------------------------------------------------

func TestDeepenCLI_PromptForKeyReadsOneTrimmedLine(t *testing.T) {
	deepencli_pipeStdin(t, "  whisper_live_typed  \n")
	_, stderr := captureStd(t, func() {
		k, err := promptForKey()
		if err != nil || k != "whisper_live_typed" {
			t.Errorf("promptForKey = %q, %v", k, err)
		}
	})
	// The key page is a DESTINATION, so it must name the EDR console. The
	// sign-in satellite serves only /sign-in and /sign-up and 404s /settings,
	// so the old host sent a user who already had an account to a dead page.
	// Asserted as the full path rather than the host alone: naming the host
	// would still pass if the path were dropped, and the path is the half
	// that 404s.
	if !strings.Contains(stderr, "https://console.whisper.online/settings") {
		t.Fatalf("the prompt must tell the user where to get a key: %q", stderr)
	}
	if strings.Contains(stderr, "console.whisper.security") {
		t.Fatalf("the prompt points at the sign-in satellite, which 404s this path: %q", stderr)
	}
}

func TestDeepenCLI_PromptLoginChoice(t *testing.T) {
	deepencli_pipeStdin(t, "\n")
	captureStd(t, func() {
		k, err := promptLoginChoice()
		if err != nil || k != "" {
			t.Errorf("Enter must mean the browser flow (empty), got %q, %v", k, err)
		}
	})
	deepencli_pipeStdin(t, " whisper_live_pasted \n")
	captureStd(t, func() {
		k, err := promptLoginChoice()
		if err != nil || k != "whisper_live_pasted" {
			t.Errorf("a pasted key must come back trimmed, got %q, %v", k, err)
		}
	})
}

// --- use <name> without a key (best-effort raw save) ------------------------------

func TestDeepenCLI_UseCmd_NameWithoutKeySavesRaw(t *testing.T) {
	deepencli_hermeticEnv(t)
	af := filepath.Join(t.TempDir(), "agent")
	deepencli_globals(t, globalFlags{quiet: true})
	captureStd(t, func() {
		if err := deepencli_exec(t, newUseCmd(), "my-agent", "--agent-file", af); err != nil {
			t.Errorf("use before login must still work best-effort: %v", err)
		}
	})
	if b, _ := os.ReadFile(af); strings.TrimSpace(string(b)) != "my-agent" {
		t.Fatalf("without a key the name is saved raw (resolved later), got %q", b)
	}
}

// --- guided one-agent branch ------------------------------------------------------

func TestDeepenCLI_GuidedOne_TTYEnterUsesTheOnlyAgent(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	gio, out, errb, restore := guidedHarness(t, srv.URL, filepath.Join(t.TempDir(), "agent"), "\n")
	defer restore()
	g.key = "whisper_live_test"

	only := agentChoice{name: "solo", addr: "2a04:2a01:9::50"}
	if err := guidedOne(guidedOptions{tty: true, quiet: true}, gio, only); err != nil {
		t.Fatalf("guidedOne enter: %v", err)
	}
	if !strings.Contains(out.String(), "2a04:2a01:9::50") {
		t.Fatalf("Enter must connect the only agent (quiet prints its /128): out=%q err=%q", out, errb)
	}
	if containsOp(opsSeen(seen), "identity") {
		t.Fatalf("accepting the only agent must not create anything, ops=%v", opsSeen(seen))
	}
}

func TestDeepenCLI_GuidedOne_TTYDeclineCreatesANamedAgent(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	// Decline the only agent, then type the new agent's name at the prompt.
	gio, out, _, restore := guidedHarness(t, srv.URL, filepath.Join(t.TempDir(), "agent"), "n\nfresh-name\n")
	defer restore()
	g.key = "whisper_live_test"

	only := agentChoice{name: "solo", addr: "2a04:2a01:9::50"}
	if err := guidedOne(guidedOptions{tty: true, quiet: true}, gio, only); err != nil {
		t.Fatalf("guidedOne decline: %v", err)
	}
	body, ok := bodyForOp(seen, "identity")
	if !ok || !strings.Contains(body, "fresh-name") {
		t.Fatalf("declining must create the NAMED agent (never unnamed), body=%q ops=%v", body, opsSeen(seen))
	}
	if !strings.Contains(out.String(), "2a04:2a01:9::abcd") {
		t.Fatalf("the created agent's /128 must be connected: %q", out.String())
	}
}

func TestDeepenCLI_GuidedOne_HeadlessUsesItWithNoPrompt(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	gio, out, errb, restore := guidedHarness(t, srv.URL, filepath.Join(t.TempDir(), "agent"), "")
	defer restore()
	g.key = "whisper_live_test"

	only := agentChoice{name: "solo", addr: "2a04:2a01:9::50"}
	if err := guidedOne(guidedOptions{tty: false, quiet: true}, gio, only); err != nil {
		t.Fatalf("guidedOne headless: %v", err)
	}
	if !strings.Contains(out.String(), "2a04:2a01:9::50") {
		t.Fatalf("headless must use the only agent, zero friction: %q", out.String())
	}
	if strings.Contains(errb.String(), "[Y/n]") {
		t.Fatal("headless must never prompt")
	}
}

// --- flow event NDJSON ------------------------------------------------------------

func TestDeepenCLI_EmitFlowEvent(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	stdout, _ := captureStd(t, func() {
		emitFlowEvent(client.FlowEvent{Event: "step", Data: json.RawMessage(`{"n":1}`)})
		emitFlowEvent(client.FlowEvent{Event: "log", Data: json.RawMessage("bare text line")})
	})
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("one NDJSON line per event, got %q", stdout)
	}
	var first map[string]json.RawMessage
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 1 must be valid JSON: %v", err)
	}
	if string(first["event"]) != `"step"` || string(first["data"]) != `{"n":1}` {
		t.Fatalf("JSON data rides verbatim: %v", first)
	}
	var second map[string]json.RawMessage
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("line 2 must be valid JSON: %v", err)
	}
	if string(second["data"]) != `"bare text line"` {
		t.Fatalf("non-JSON data must be carried as a JSON string, never dropped: %v", second)
	}
}
