// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// whale_syspolicy_test.go proves the managed-settings half, and it is written against
// the defect this campaign keeps finding rather than against the happy path.
//
// 1. SHIPPED BUT UNREACHABLE. A policy that can be written and read back but that nothing
// honours is decoration. TestSysPolicyReachesTheGlobalsFromTheRootCommand and
// TestManagedPolicyRefusesInteractiveLoginFromTheRealLoginCommand start at
// NewRootCommand().Execute(), the entry point a user starts at, and assert the EFFECT.
// Delete the PersistentPreRunE from root.go and the first one fails.
// 2. ACCURATE CODE, INACCURATE PROSE. TestEverySettingNamesWhereItApplies and
// TestHelpTextDoesNotClaimAPolicyOverridesAFlag check the sentences against the code.
// 3. A GUARD THAT CANNOT FAIL. Every "absent" assertion here has a control beside it that
// would be non-empty if the probe worked.

// managedKeyFileForHost is the KeyFile a test policy sets: the machine-wide path this
// binary's own template ships FOR THE HOST the test is running on.
//
// It used to be the /etc/whisper/key literal at every site, which made the fixture a
// POSIX path rather than a managed one. The reader validates KeyFile with filepath.IsAbs,
// and that is right: a policy is read on the machine it governs, and a relative path there
// would resolve against whatever directory the command was run from. So on Windows the
// literal was correctly REJECTED, the setting under test never reached the process, and
// every assertion about it failed for a reason that had nothing to do with the code.
func managedKeyFileForHost() string { return managedKeyFileExample(runtime.GOOS) }

// withSysPolicy installs a store for one test and restores everything after. The globals
// it touches are process-wide, so this is the only way any test here may set them.
func withSysPolicy(t *testing.T, vals map[string]any, origin string) {
	t.Helper()
	prevRead, prevActive, prevControl, prevKeyFile := readSysPolicyStore, activeSysPolicy, g.controlURL, g.keyFile
	t.Cleanup(func() {
		readSysPolicyStore = prevRead
		activeSysPolicy = prevActive
		g.controlURL, g.keyFile = prevControl, prevKeyFile
	})
	readSysPolicyStore = func() sysPolicyStore {
		return sysPolicyStore{Origin: origin, Searched: []string{origin}, Present: true, Values: vals}
	}
}

// captureScreen runs f with BOTH standard streams redirected and returns everything it
// printed. Both, because the table goes to stdout and whaleNote goes to stderr: capturing
// only one is how an assertion passes while the sentence it is checking is on the other
// stream, which is exactly what happened the first time this was written.
func captureScreen(t *testing.T, f func()) string {
	t.Helper()
	ro, wo, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	re, we, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prevOut, prevErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = wo, we
	done := make(chan string, 2)
	for _, r := range []*os.File{ro, re} {
		go func(r *os.File) {
			var b bytes.Buffer
			_, _ = b.ReadFrom(r)
			done <- b.String()
		}(r)
	}
	f()
	wo.Close()
	we.Close()
	os.Stdout, os.Stderr = prevOut, prevErr
	return <-done + <-done
}

// --- 1. the effect, traced from the entry point a user starts at ----------------------

// TestSysPolicyReachesTheGlobalsFromTheRootCommand is the anti-unreachable gate. It does
// not call applySysPolicy: it executes the real command tree, exactly as main() does, and
// asserts the managed values arrived. Remove root.go's PersistentPreRunE and it fails.
func TestSysPolicyReachesTheGlobalsFromTheRootCommand(t *testing.T) {
	wantKeyFile := managedKeyFileForHost()
	withSysPolicy(t, map[string]any{
		"ControlURL": "https://control.example.org/api/query",
		"KeyFile":    wantKeyFile,
	}, "/etc/whisper/policy.json")
	g.controlURL, g.keyFile = "", ""

	root := NewRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"whale", "syspolicy", "list", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("`whisper whale syspolicy list` failed: %v", err)
	}
	if g.controlURL != "https://control.example.org/api/query" {
		t.Errorf("the managed ControlURL never reached the process: g.controlURL = %q. Nothing on the "+
			"real command path applies the policy, so every setting in it is decoration", g.controlURL)
	}
	if g.keyFile != wantKeyFile {
		t.Errorf("the managed KeyFile never reached the process: g.keyFile = %q, want %q",
			g.keyFile, wantKeyFile)
	}
}

// TestAFlagStillWinsOverThePolicy pins the ordering the help text promises.
func TestAFlagStillWinsOverThePolicy(t *testing.T) {
	withSysPolicy(t, map[string]any{"ControlURL": "https://control.example.org/api/query"},
		"/etc/whisper/policy.json")

	root := NewRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--control-url", "https://passed-on-the-command-line.example/api/query",
		"whale", "syspolicy", "list", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if g.controlURL != "https://passed-on-the-command-line.example/api/query" {
		t.Errorf("the policy overrode an explicit --control-url (%q). The help text says a flag still "+
			"wins; one of the two has to change", g.controlURL)
	}
}

// TestManagedPolicyRefusesInteractiveLoginFromTheRealLoginCommand walks `whisper login`
// from the root, so it proves the refusal is on the path a person takes, and it proves it
// by whether the browser device flow RAN - not merely by whether an error came back.
func TestManagedPolicyRefusesInteractiveLoginFromTheRealLoginCommand(t *testing.T) {
	prevFlow := deviceFlowFn
	t.Cleanup(func() { deviceFlowFn = prevFlow })
	ran := false
	deviceFlowFn = func(string, time.Duration) (string, error) {
		ran = true
		return "", errors.New("the device flow was reached")
	}

	// CONTROL first: with no policy, `login --web` must reach the device flow. Without
	// this, the assertion below would pass on a binary that simply cannot log in at all.
	withSysPolicy(t, map[string]any{}, "/etc/whisper/policy.json")
	root := NewRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"login", "--web"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "the device flow was reached") {
		t.Fatalf("control failed: with no policy, `login --web` did not reach the device flow (err=%v)", err)
	}
	if !ran {
		t.Fatal("control failed: the device flow never ran even with no policy")
	}

	ran = false
	wantKeyFile := managedKeyFileForHost()
	withSysPolicy(t, map[string]any{
		"AllowInteractiveLogin": false,
		"KeyFile":               wantKeyFile,
	}, "/etc/whisper/policy.json")
	root = NewRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"login", "--web"})
	err := root.Execute()
	if err == nil {
		t.Fatal("`whisper login --web` succeeded on a host whose policy sets AllowInteractiveLogin=false")
	}
	if ran {
		t.Error("the browser sign-in ran anyway; the refusal is not on the path")
	}
	if !strings.Contains(err.Error(), "AllowInteractiveLogin") {
		t.Errorf("the refusal does not name the setting that caused it: %v", err)
	}
	if !strings.Contains(err.Error(), wantKeyFile) {
		t.Errorf("the refusal does not tell the user where the key they DO have comes from: %v", err)
	}
	if !strings.Contains(err.Error(), "whisper login <key>") {
		t.Errorf("the refusal does not name the way forward: %v", err)
	}

	// And what the user actually SEES. Execute() prints friendly(err), which collapses
	// every 401/403 problem that is not our own "no key" into "your key was not accepted -
	// run: whisper login" - useless here, and untrue: the key is fine, and the command it
	// recommends is the one that was just refused. Measured on the built binary; asserting
	// the error value alone let that through once already.
	rendered := friendly(err)
	if !strings.Contains(rendered, "AllowInteractiveLogin") {
		t.Errorf("the line the user sees is %q, which says nothing about the policy that caused it", rendered)
	}
	if strings.Contains(rendered, "your key was not accepted") {
		t.Errorf("the refusal renders as a key problem, and the key is fine: %q", rendered)
	}
}

// TestManagedPolicyStillAllowsSavingAKeyYouWereGiven is the other direction. The setting
// is named AllowInteractiveLogin, so it must not block `whisper login <key>`, which is
// configuration rather than a sign-in. Without this, the name would be a lie.
func TestManagedPolicyStillAllowsSavingAKeyYouWereGiven(t *testing.T) {
	withSysPolicy(t, map[string]any{"AllowInteractiveLogin": false}, "/etc/whisper/policy.json")
	keyPath := filepath.Join(t.TempDir(), "key")

	root := NewRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	// A control URL that refuses instantly keeps the fail-soft verification off the
	// network; saveAndVerify saves first and only then verifies, which is the behaviour
	// under test here.
	root.SetArgs([]string{"login", "whisper_live_notarealkey", "--key-file", keyPath,
		"--control-url", "http://127.0.0.1:1/", "--timeout", "2s"})
	if err := root.Execute(); err != nil {
		t.Fatalf("`whisper login <key>` was refused on a managed host: %v", err)
	}
	b, err := os.ReadFile(keyPath)
	if err != nil || strings.TrimSpace(string(b)) != "whisper_live_notarealkey" {
		t.Fatalf("the key was not saved: %q err=%v", string(b), err)
	}
}

// TestGuidedFrontDoorRefusesInsteadOfWalkingIntoASignIn covers the third enforcement
// point: bare `whisper` is where a user on a managed machine would otherwise be walked
// into signing into a personal tenant. guidedClient is the function bare `whisper` runs.
func TestGuidedFrontDoorRefusesInsteadOfWalkingIntoASignIn(t *testing.T) {
	// No credential anywhere: an empty key file, and the env rung left to the test
	// environment, which carries no WHISPER_API_KEY.
	empty := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	prevKeyFile, prevKey, prevActive := g.keyFile, g.key, activeSysPolicy
	t.Cleanup(func() { g.keyFile, g.key, activeSysPolicy = prevKeyFile, prevKey, prevActive })
	g.keyFile, g.key = empty, ""
	if os.Getenv("WHISPER_API_KEY") != "" || os.Getenv("WHISPER_KEY") != "" {
		t.Skip("a key in the environment would resolve before the branch under test")
	}
	gio := guidedIO{in: bufio.NewReader(strings.NewReader("")), out: &bytes.Buffer{}, err: &bytes.Buffer{}}

	prevLogin := guidedLogin
	t.Cleanup(func() { guidedLogin = prevLogin })
	reached := false
	guidedLogin = func() error {
		reached = true
		return errors.New("the sign-in was reached")
	}

	// CONTROL: with no policy the front door reaches the sign-in, so the refusal below is
	// the policy and not simply a keyless box failing some earlier way.
	activeSysPolicy = sysPolicy{}
	_, err := guidedClient(guidedOptions{tty: true}, gio)
	if err == nil || !strings.Contains(err.Error(), "the sign-in was reached") {
		t.Fatalf("control failed: with no policy the front door did not reach the sign-in (err=%v)", err)
	}
	if !reached {
		t.Fatal("control failed: the sign-in never ran even with no policy")
	}

	reached = false
	activeSysPolicy = sysPolicy{NoInteractiveLogin: true, Origin: "/etc/whisper/policy.json"}
	_, err = guidedClient(guidedOptions{tty: true}, gio)
	if err == nil {
		t.Fatal("bare `whisper` walked a user on a managed host into an interactive sign-in")
	}
	if reached {
		t.Error("the sign-in ran anyway; the refusal is not on the front-door path")
	}
	if !strings.Contains(err.Error(), "AllowInteractiveLogin") {
		t.Errorf("the front door refused for some other reason: %v", err)
	}
}

// TestKeyLadderPromptRungHonoursThePolicy covers the third enforcement point. The prompt
// itself needs a real terminal, so the decision is a predicate and the predicate is what
// is asserted, in both directions.
func TestKeyLadderPromptRungHonoursThePolicy(t *testing.T) {
	prev := activeSysPolicy
	t.Cleanup(func() { activeSysPolicy = prev })

	activeSysPolicy = sysPolicy{}
	if !keyLadderPromptAllowed(true, true) {
		t.Fatal("control failed: with no policy the prompt rung must run, or the denial below means nothing")
	}
	activeSysPolicy = sysPolicy{NoInteractiveLogin: true}
	if keyLadderPromptAllowed(true, true) {
		t.Error("the key ladder still prompts for a key on a host whose policy switched interactive sign-in off")
	}
}

// TestZeroValuePolicyRestrictsNothing is the lockout guard. sysPolicy is stored as a
// denial rather than a permission precisely so a struct nobody filled in cannot lock a
// person out of their own CLI.
func TestZeroValuePolicyRestrictsNothing(t *testing.T) {
	prev := activeSysPolicy
	t.Cleanup(func() { activeSysPolicy = prev })
	activeSysPolicy = sysPolicy{}
	if !interactiveLoginAllowed() {
		t.Fatal("the zero-value policy denies interactive login, so any path that forgets to resolve a " +
			"policy locks the user out of a CLI that nobody configured")
	}
}

// --- 2. reading a store ---------------------------------------------------------------

func TestLinuxStoreIsReadAndResolved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	wantKeyFile := managedKeyFileForHost()
	body, merr := json.Marshal(map[string]any{
		"ControlURL":            "https://c.example/api/query",
		"KeyFile":               wantKeyFile,
		"AllowInteractiveLogin": false,
	})
	if merr != nil {
		t.Fatal(merr)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	prev := sysPolicyPathsFor
	t.Cleanup(func() { sysPolicyPathsFor = prev })
	sysPolicyPathsFor = func(string) []string { return []string{path} }

	p, v := resolveSysPolicy(sysPolicyStoreFor("linux"))
	if !v.Managed || v.Store != path {
		t.Fatalf("the store at %s was not found: managed=%v store=%q", path, v.Managed, v.Store)
	}
	if v.Error != "" {
		t.Fatalf("the store read reported an error: %s", v.Error)
	}
	if p.ControlURL != "https://c.example/api/query" || p.KeyFile != wantKeyFile || !p.NoInteractiveLogin {
		t.Fatalf("the policy did not resolve: %+v", p)
	}
	for _, s := range v.Settings {
		if s.Source != "managed" {
			t.Errorf("%s reads as %q, not managed, even though the store set it", s.Name, s.Source)
		}
	}
}

// TestAnUnreadablePolicyIsNeverRenderedAsAnAbsentOne is the error-that-renders-as-empty
// guard. A profile that is installed and broken must not look like a clean host.
func TestAnUnreadablePolicyIsNeverRenderedAsAnAbsentOne(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte("this is not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := sysPolicyPathsFor
	t.Cleanup(func() { sysPolicyPathsFor = prev })
	sysPolicyPathsFor = func(string) []string { return []string{path} }

	p, v := resolveSysPolicy(sysPolicyStoreFor("linux"))
	if !v.Managed {
		t.Fatal("a policy file that exists but cannot be parsed reported managed=false, which is " +
			"indistinguishable from a machine with no policy at all")
	}
	if v.Error == "" {
		t.Fatal("no error was reported for an unparseable policy file")
	}
	if p.Origin != "" {
		t.Error("the policy claims an origin it could not actually read")
	}
	// What the person actually SEES, captured from the real renderer: the note carries the
	// reason, and the store line has to carry the state.
	out := captureScreen(t, func() { renderSysPolicy(v) })
	if !strings.Contains(out, "UNREADABLE") {
		t.Errorf("the human table does not say the policy is unreadable, so a broken profile reads "+
			"as a clean host:\n%s", out)
	}
	if !strings.Contains(out, "not a readable settings dictionary") {
		t.Errorf("the human table does not say WHY, so there is nothing to fix:\n%s", out)
	}

	// CONTROL: the same path holding valid JSON reports no error, so the assertions above
	// are reading a real failure and not a broken probe.
	if err := os.WriteFile(path, []byte(`{"ControlURL":"https://c.example/api/query"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, v2 := resolveSysPolicy(sysPolicyStoreFor("linux")); v2.Error != "" {
		t.Fatalf("control failed: a valid policy file also reported an error (%s)", v2.Error)
	}
}

// TestNoPolicyIsNotAnError: an unmanaged machine is the normal case and must be silent.
func TestNoPolicyIsNotAnError(t *testing.T) {
	prev := sysPolicyPathsFor
	t.Cleanup(func() { sysPolicyPathsFor = prev })
	sysPolicyPathsFor = func(string) []string { return []string{filepath.Join(t.TempDir(), "absent.json")} }

	p, v := resolveSysPolicy(sysPolicyStoreFor("linux"))
	if v.Managed || v.Error != "" {
		t.Fatalf("an absent policy read as managed=%v error=%q", v.Managed, v.Error)
	}
	if p != (sysPolicy{}) {
		t.Fatalf("an absent policy produced settings: %+v", p)
	}
	if len(v.Settings) != len(sysPolicySpecs()) {
		t.Fatalf("list showed %d settings, want %d - defaults must still be listed", len(v.Settings), len(sysPolicySpecs()))
	}
	for _, s := range v.Settings {
		if s.Source != "default" || s.Value == "" {
			t.Errorf("%s = %q (%s): every setting must show its built-in default", s.Name, s.Value, s.Source)
		}
	}
}

// TestDarwinStoreGoesThroughPlutil pins the one thing an XML-only reader would get wrong:
// the plist MDM writes into /Library/Managed Preferences is BINARY, so the reader has to
// convert it, and a test that only fed it XML would pass while the product read nothing.
func TestDarwinStoreGoesThroughPlutil(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, sysPolicyDomain+".plist")
	// A real binary plist starts with this magic. The bytes after it are irrelevant here:
	// the point is that the reader must not try to parse them itself.
	if err := os.WriteFile(path, append([]byte("bplist00"), 0x00, 0xd1, 0x01, 0x02), 0o644); err != nil {
		t.Fatal(err)
	}
	prevPaths, prevConv := sysPolicyPathsFor, applePlistToJSON
	t.Cleanup(func() { sysPolicyPathsFor, applePlistToJSON = prevPaths, prevConv })
	sysPolicyPathsFor = func(string) []string { return []string{path} }

	var got string
	applePlistToJSON = func(p string) ([]byte, error) {
		got = p
		return []byte(`{"ControlURL":"https://mac.example/api/query"}`), nil
	}
	p, v := resolveSysPolicy(sysPolicyStoreFor("darwin"))
	if got != path {
		t.Fatalf("the darwin reader converted %q, not the store it found at %q", got, path)
	}
	if v.Error != "" || p.ControlURL != "https://mac.example/api/query" {
		t.Fatalf("the converted plist did not resolve: err=%q policy=%+v", v.Error, p)
	}

	// The command itself cannot run off a Mac, so pin its argv instead: a drift here would
	// only ever be caught on the hardware it was written for.
	bin, args := applePlistCommand("/x.plist")
	if bin != "/usr/bin/plutil" {
		t.Errorf("darwin conversion runs %q, want /usr/bin/plutil", bin)
	}
	if strings.Join(args, " ") != "-convert json -o - /x.plist" {
		t.Errorf("plutil argv = %v; it must convert to json on stdout", args)
	}
}

// TestDarwinLooksAtTheManagedPreferencesDirectory pins the location, because a reader
// pointed at a path no MDM ever writes is the unreachable defect in its purest form.
func TestDarwinLooksAtTheManagedPreferencesDirectory(t *testing.T) {
	paths := defaultSysPolicyPaths("darwin")
	if len(paths) == 0 {
		t.Fatal("darwin searches nowhere")
	}
	last := paths[len(paths)-1]
	if last != "/Library/Managed Preferences/"+sysPolicyDomain+".plist" {
		t.Errorf("the device-level darwin store is %q, which is not where MDM flattens a "+
			"com.apple.ManagedClient.preferences payload", last)
	}
	if got := defaultSysPolicyPaths("linux"); len(got) != 1 || got[0] != "/etc/whisper/policy.json" {
		t.Errorf("linux store = %v, want /etc/whisper/policy.json under the machine-wide config directory", got)
	}
	if got := defaultSysPolicyPaths("windows"); got != nil {
		t.Errorf("windows must have no file path (it is the registry), got %v", got)
	}
}

// --- 3. liberal in, conservative out ---------------------------------------------------

func TestPolicyValuesAreAcceptedLiberally(t *testing.T) {
	for _, tc := range []struct {
		name string
		vals map[string]any
		want sysPolicy
	}{
		{"a real boolean", map[string]any{"AllowInteractiveLogin": false}, sysPolicy{NoInteractiveLogin: true}},
		{"a string boolean (a .reg / hand-edited file)", map[string]any{"AllowInteractiveLogin": "false"}, sysPolicy{NoInteractiveLogin: true}},
		{"a DWORD 0 (windows)", map[string]any{"AllowInteractiveLogin": uint64(0)}, sysPolicy{NoInteractiveLogin: true}},
		{"a JSON number (plutil)", map[string]any{"AllowInteractiveLogin": float64(0)}, sysPolicy{NoInteractiveLogin: true}},
		{"\"no\"", map[string]any{"AllowInteractiveLogin": "no"}, sysPolicy{NoInteractiveLogin: true}},
		{"a lowercase key", map[string]any{"controlurl": "https://c.example/api/query"}, sysPolicy{ControlURL: "https://c.example/api/query"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, v := resolveSysPolicy(sysPolicyStore{Present: true, Origin: "test", Values: tc.vals})
			tc.want.Origin = "test"
			if p != tc.want {
				t.Fatalf("resolved %+v, want %+v (notes: %v)", p, tc.want, v.Notes)
			}
		})
	}
}

func TestUnusableValuesAreRefusedAndSaidOutLoud(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vals    map[string]any
		wantSub string
	}{
		{"a control URL that is not a URL", map[string]any{"ControlURL": "graph.whisper.online"}, "must be an http(s) URL"},
		{"a relative key file", map[string]any{"KeyFile": "whisper/key"}, "must be an absolute path"},
		{"a key file that is a number", map[string]any{"KeyFile": float64(7)}, "must be a string"},
		{"a boolean that is a sentence", map[string]any{"AllowInteractiveLogin": "sometimes"}, "must be a boolean"},
		{"an empty string", map[string]any{"ControlURL": "  "}, "empty string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, v := resolveSysPolicy(sysPolicyStore{Present: true, Origin: "test", Values: tc.vals})
			if p != (sysPolicy{Origin: "test"}) {
				t.Errorf("a value we refuse was applied anyway: %+v", p)
			}
			joined := strings.Join(v.Notes, " | ")
			if !strings.Contains(joined, tc.wantSub) {
				t.Errorf("nothing told the administrator why it was ignored; notes = %q", joined)
			}
			for _, s := range v.Settings {
				if s.Source == "managed" {
					t.Errorf("%s reads as managed even though its value was refused", s.Name)
				}
			}
		})
	}
}

func TestAnUnknownKeyIsNamedRatherThanIgnoredSilently(t *testing.T) {
	_, v := resolveSysPolicy(sysPolicyStore{Present: true, Origin: "test",
		Values: map[string]any{"ControlUrls": "https://typo.example/api/query"}})
	if !strings.Contains(strings.Join(v.Notes, " | "), "ControlUrls") {
		t.Errorf("an administrator's typo was swallowed; notes = %v", v.Notes)
	}
	// CONTROL: the correctly spelled key produces no such note.
	_, ok := resolveSysPolicy(sysPolicyStore{Present: true, Origin: "test",
		Values: map[string]any{"ControlURL": "https://c.example/api/query"}})
	if strings.Contains(strings.Join(ok.Notes, " | "), "does not know") {
		t.Errorf("control failed: a known key was reported as unknown; notes = %v", ok.Notes)
	}
}

// TestACommentKeyIsNotReportedAsATypo: the JSON template carries its own note as
// _comment, so the file we print must pass the check we ship.
func TestACommentKeyIsNotReportedAsATypo(t *testing.T) {
	_, v := resolveSysPolicy(sysPolicyStore{Present: true, Origin: "test",
		Values: map[string]any{"_comment": "hello", "ControlURL": "https://c.example/api/query"}})
	if strings.Contains(strings.Join(v.Notes, " | "), "_comment") {
		t.Errorf("the template's own comment key is reported as an unknown setting; notes = %v", v.Notes)
	}
	// CONTROL: the same key without the underscore IS reported, so the skip is the
	// underscore convention and not a broken check.
	_, c := resolveSysPolicy(sysPolicyStore{Present: true, Origin: "test",
		Values: map[string]any{"comment": "hello"}})
	if !strings.Contains(strings.Join(c.Notes, " | "), "comment") {
		t.Errorf("control failed: an unknown key without the underscore was also skipped; notes = %v", c.Notes)
	}
}

// --- 4. the template, and the round trip the acceptance criterion asks for --------------

// TestTemplateRoundTripsThroughTheReader is the acceptance criterion, executed: the
// template this command prints, installed as the store, is read back by the same reader
// with every setting reporting source=managed.
// TestAppleProfileIsAValidPlistCarryingEverySetting parses the .mobileconfig as XML and
// walks to the settings dictionary. The shape matters: an MDM that cannot find
// mcx_preference_settings installs a profile that does nothing.
func TestAppleProfileIsAValidPlistCarryingEverySetting(t *testing.T) {
	body, err := sysPolicyTemplate("darwin")
	if err != nil {
		t.Fatal(err)
	}
	if err := xml.Unmarshal([]byte(body), new(struct {
		XMLName xml.Name `xml:"plist"`
	})); err != nil {
		t.Fatalf("the generated .mobileconfig is not well-formed XML: %v", err)
	}
	for _, want := range []string{
		"com.apple.ManagedClient.preferences",
		"<key>" + sysPolicyDomain + "</key>",
		"<key>Forced</key>",
		"<key>mcx_preference_settings</key>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the profile is missing %q, so an MDM would deliver nothing", want)
		}
	}
	for _, spec := range sysPolicySpecs() {
		if !strings.Contains(body, "<key>"+spec.Name+"</key>") {
			t.Errorf("the profile does not carry %s, so the template and the reader have drifted", spec.Name)
		}
	}
	if strings.Contains(body, "<string>true</string>") {
		t.Error("a boolean is written as a string; a plist boolean is <true/> and an MDM would reject or " +
			"mistype it")
	}
	// Two profiles installed on one machine must not collide.
	other, err := sysPolicyTemplate("darwin")
	if err != nil {
		t.Fatal(err)
	}
	if other == body {
		t.Error("two generated profiles are byte-identical, so their PayloadUUIDs collide")
	}
}

func TestWindowsTemplateNamesTheRealPolicyKey(t *testing.T) {
	body, err := sysPolicyTemplate("windows")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "["+windowsSysPolicyKeyPath+"]") {
		t.Errorf(".reg file does not write to %s", windowsSysPolicyKeyPath)
	}
	if !strings.Contains(body, `"AllowInteractiveLogin"=dword:00000001`) {
		t.Errorf("the boolean is not a DWORD, which is what the registry reader asks for:\n%s", body)
	}
	if !strings.Contains(body, `"KeyFile"="C:\\ProgramData\\Whisper\\key"`) {
		t.Errorf("the Windows path is not escaped for .reg syntax:\n%s", body)
	}
	if !strings.HasPrefix(body, "Windows Registry Editor Version 5.00") {
		t.Error(".reg file has no header, so reg import refuses it")
	}
	for _, line := range strings.Split(body, "\n") {
		if line != "" && !strings.HasSuffix(line, "\r") {
			t.Fatalf(".reg line does not end CRLF, and regedit refuses bare newlines: %q", line)
		}
	}
	// regedit reads a "Version 5.00" file as UTF-16 only when it starts with the UTF-16
	// BOM, and otherwise as ANSI. One curly quote in a help string would import as
	// mojibake, and nothing about writing the sentence would tell you.
	for i := 0; i < len(body); i++ {
		if body[i] > 127 {
			t.Fatalf(".reg file contains the non-ASCII byte %#x at offset %d, which regedit would "+
				"import as mojibake", body[i], i)
		}
	}
}

// TestTemplateHelpDoesNotPromiseAHarmlessInstall checks a sentence against the code. The
// template's KeyFile is the machine-wide path an MDM provisions, NOT the per-user default,
// so a profile installed verbatim on a machine with no key there leaves the CLI with no
// key from a file. The help said "harmless, the shipped defaults" once; it was wrong.
func TestTemplateHelpDoesNotPromiseAHarmlessInstall(t *testing.T) {
	long := newWhaleSysPolicyTemplateCmd().Long
	if strings.Contains(long, "harmless") || strings.Contains(long, "change nothing surprising") {
		t.Error("the template help calls the profile harmless to install as-is, and its KeyFile " +
			"value is not the per-user default, so it is not")
	}
	if !strings.Contains(long, "KeyFile") {
		t.Error("the template help does not warn about the KeyFile line at all")
	}
	// The claim under test, asserted against the code that produces the value.
	for _, goos := range []string{"darwin", "windows", "linux"} {
		if managedKeyFileExample(goos) == client.DefaultKeyFile() {
			t.Errorf("on %s the template ships the per-user default as KeyFile, which makes the "+
				"warning above wrong in the other direction", goos)
		}
	}
	// And the artefacts themselves carry it, because the person installing a .reg or a
	// .mobileconfig may never have run the command that printed it.
	for _, goos := range []string{"darwin", "windows", "linux"} {
		body, err := sysPolicyTemplate(goos)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body, "provisions the key") {
			t.Errorf("the %s template does not say what KeyFile is for inside the file itself", goos)
		}
	}
}

func TestLinuxTemplateIsValidJSON(t *testing.T) {
	body, err := sysPolicyTemplate("linux")
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		t.Fatalf("the linux template is not valid JSON: %v", err)
	}
	if _, ok := obj["AllowInteractiveLogin"].(bool); !ok {
		t.Errorf("AllowInteractiveLogin is not a JSON boolean: %#v", obj["AllowInteractiveLogin"])
	}
}

func TestTemplatePlatformIsAcceptedLiberally(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "macos": "darwin", "Mac": "darwin", "OSX": "darwin", "darwin": "darwin",
		"win": "windows", "Windows": "windows", "linux": "linux",
	} {
		got, err := normaliseSysPolicyPlatform(in)
		if err != nil {
			t.Errorf("--platform %q was refused: %v", in, err)
			continue
		}
		if want != "" && got != want {
			t.Errorf("--platform %q resolved to %q, want %q", in, got, want)
		}
	}
	if _, err := normaliseSysPolicyPlatform("solaris"); err == nil {
		t.Error("an unknown platform was accepted, so a typo would print the wrong profile")
	}
}

// --- 5. the prose ----------------------------------------------------------------------

// TestEverySettingNamesWhereItApplies is the decoration guard: a setting with no APPLIES
// text is one nobody can check, and one that nothing honours is the defect this whole file
// exists to prevent.
func TestEverySettingNamesWhereItApplies(t *testing.T) {
	for _, s := range sysPolicySpecs() {
		if strings.TrimSpace(s.Applies) == "" {
			t.Errorf("%s does not say where it takes effect", s.Name)
		}
		if strings.TrimSpace(s.Help) == "" {
			t.Errorf("%s has no help", s.Name)
		}
		if s.Kind != "string" && s.Kind != "bool" {
			t.Errorf("%s has type %q, which neither the reader nor any template knows how to write", s.Name, s.Kind)
		}
	}
}

// TestHelpTextDoesNotClaimAPolicyOverridesAFlag checks the sentences against the code:
// applySysPolicy fills in only what the command line left empty, and the help must not
// promise enforcement it does not deliver.
func TestHelpTextDoesNotClaimAPolicyOverridesAFlag(t *testing.T) {
	long := newWhaleSysPolicyCmd().Long
	if !strings.Contains(long, "not a security boundary") {
		t.Error("the help does not say this is configuration management rather than enforcement, which " +
			"is the one thing a reader could get wrong")
	}
	for _, s := range sysPolicySpecs() {
		if s.Name == "AllowInteractiveLogin" && !strings.Contains(s.Applies, "`whisper login`") {
			t.Errorf("AllowInteractiveLogin does not name the command it changes: %q", s.Applies)
		}
	}
}
