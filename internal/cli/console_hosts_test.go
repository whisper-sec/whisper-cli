// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// Where the CLI sends a person, and the two ways that has gone wrong.
//
// A host is retired: console.whisper.online and partners.whisper.online now only redirect
// to their new names, so a line that prints one sends the reader through a hop to a host
// the line never named. And a live host is the wrong one: the Endpoint Security console
// signs people in through the console but issues no API keys, so a "get a key" hint that
// names it sends the user to sign in at one console and look for a key minted by another.
//
// The first is guarded over everything the binary can print, the second by pinning every
// key hint and the login help to the constants the device flow itself dials.

// retiredHosts are names that only redirect now. Nothing the CLI prints may contain one.
var retiredHosts = []string{"console.whisper.online", "partners.whisper.online"}

// retiredHostIn returns the first retired host s mentions, or "". Host names are
// case-insensitive, so the comparison is too.
func retiredHostIn(s string) string {
	lower := strings.ToLower(s)
	for _, h := range retiredHosts {
		if strings.Contains(lower, h) {
			return h
		}
	}
	return ""
}

// TestConsoleHosts_NoHelpTextNamesARetiredHost renders the help of every command in the
// tree, hidden ones included, and fails on any retired host in it.
func TestConsoleHosts_NoHelpTextNamesARetiredHost(t *testing.T) {
	root := NewRootCommand()
	var walked int
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		walked++
		for name, text := range map[string]string{
			"short":   c.Short,
			"long":    c.Long,
			"example": c.Example,
			"usage":   c.UsageString(),
		} {
			if h := retiredHostIn(text); h != "" {
				t.Errorf("%q %s text names the retired host %s:\n%s", c.CommandPath(), name, h, text)
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	// A walk that reached a handful of commands would pass for the wrong reason.
	if walked < 40 {
		t.Fatalf("walked only %d commands; the tree did not build the way this test expects", walked)
	}
}

// retiredHostLiterals parses one Go source and returns every string literal that names a
// retired host. Comments are not literals, so a dated measurement kept in a comment stays.
func retiredHostLiterals(fset *token.FileSet, name string, src any) ([]string, int, error) {
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, 0, err
	}
	var hits []string
	var literals int
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		literals++
		v, err := strconv.Unquote(lit.Value)
		if err != nil {
			v = lit.Value
		}
		if h := retiredHostIn(v); h != "" {
			hits = append(hits, fset.Position(lit.Pos()).String()+": "+h)
		}
		return true
	})
	return hits, literals, nil
}

// TestConsoleHosts_NoGoSourcePrintsARetiredHost reads every non-test Go file in the
// module and fails on a string literal that names a retired host. It covers what the help
// walk cannot reach: prompts, errors and notes built at run time. Every other file under
// internal/ is read whole, because that is where the text the binary embeds and prints
// lives (the catalog, the docs index), and a JSON or text file has no comments to spare.
func TestConsoleHosts_NoGoSourcePrintsARetiredHost(t *testing.T) {
	// Controls first. The extractor must flag a literal and must not flag a comment, or an
	// empty result below means nothing.
	fset := token.NewFileSet()
	seeded := "package x\n\n// measured on console.whisper.online once\nvar s = \"open Console.Whisper.Online in a browser\"\n"
	hits, _, err := retiredHostLiterals(fset, "seeded.go", seeded)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("the seeded source has one retired literal and one comment; got %v", hits)
	}

	root := consoleHostsModuleRoot(t)
	var files, literals, assets int
	var sawLiveConsole bool
	var offenders []string
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "vendor", "node_modules", "target", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, "_test.go") {
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			rel, err := filepath.Rel(root, p)
			if err != nil || !strings.HasPrefix(filepath.ToSlash(rel), "internal/") {
				return err
			}
			body, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			assets++
			if h := retiredHostIn(string(body)); h != "" {
				offenders = append(offenders, rel+": "+h)
			}
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		h, n, err := retiredHostLiterals(fset, p, src)
		if err != nil {
			return err
		}
		files++
		literals += n
		offenders = append(offenders, h...)
		if strings.Contains(string(src), `"`+client.DefaultConsoleURL+`"`) {
			sawLiveConsole = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 || literals < 1000 || assets < 2 {
		t.Fatalf("scanned %d files, %d literals and %d other files; the walk did not cover the module",
			files, literals, assets)
	}
	if !sawLiveConsole {
		t.Fatal("no source carries the console's own URL as a literal; the walk missed the client package")
	}
	for _, o := range offenders {
		t.Errorf("a string the CLI can print names a retired host: %s", o)
	}
}

// consoleHostsModuleRoot is the directory holding go.mod, found by walking up from the
// test's own package directory, so the scan covers the whole binary rather than one package.
func consoleHostsModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		if filepath.Dir(d) == d {
			t.Fatalf("no go.mod above %s", dir)
		}
	}
}

// TestConsoleHosts_TheKeysPageIsOnTheSignInConsole pins the constants the hints are built
// from. The literal is the measured route: the console serves a keys page at /api-keys
// behind sign-in, and a signed-out visitor is sent through sign-in and brought back to it.
func TestConsoleHosts_TheKeysPageIsOnTheSignInConsole(t *testing.T) {
	if client.APIKeysURL != "https://console.whisper.security/api-keys" {
		t.Fatalf("APIKeysURL = %q", client.APIKeysURL)
	}
	if client.APIKeysURL != client.DefaultConsoleURL+client.APIKeysPath {
		t.Fatalf("APIKeysURL %q is not on DefaultConsoleURL %q", client.APIKeysURL, client.DefaultConsoleURL)
	}
	if hostOf(client.EndpointConsoleURL) == hostOf(client.DefaultConsoleURL) {
		t.Fatal("the endpoint console and the sign-in console are distinct hosts")
	}
}

// TestConsoleHosts_EveryKeyHintNamesTheSignInConsole runs each line that tells a person
// where to sign in or where to get a key, and checks it names the console the device
// flow dials, never the endpoint console and never a retired host.
func TestConsoleHosts_EveryKeyHintNamesTheSignInConsole(t *testing.T) {
	saved := g
	t.Cleanup(func() { g = saved })
	g = globalFlags{}
	t.Setenv("WHISPER_API_KEY", "")
	t.Setenv("WHISPER_KEY", "")
	signIn := hostOf(client.DefaultConsoleURL)

	login := newLoginCmd()
	hints := map[string]string{"login long": login.Long}

	deepencli_pipeStdin(t, "") // a pipe: not interactive, so each command takes its headless branch
	run := func(args ...string) string {
		cmd := newLoginCmd()
		cmd.SetArgs(args)
		cmd.SetOut(&strings.Builder{})
		cmd.SetErr(&strings.Builder{})
		err := cmd.Execute()
		if err == nil {
			t.Fatalf("login %v with no key and no terminal must refuse with guidance", args)
		}
		return err.Error()
	}
	hints["login, no key"] = run()
	hints["login --manual, no key"] = run("--manual")
	if err := saveAndVerify(""); err != nil {
		hints["save an empty key"] = err.Error()
	}
	g.keyFile = filepath.Join(t.TempDir(), "absent-key")
	if _, err := resolveClient(true, false); err != nil {
		hints["a command that needs a key"] = err.Error()
	}
	hints["resolver, no key"] = errResolverNeedsKey().Error()
	_, hints["the key prompt"] = captureStd(t, func() {
		deepencli_pipeStdin(t, "\n")
		_, _ = promptForKey()
	})
	_, choice := captureStd(t, func() {
		deepencli_pipeStdin(t, "\n")
		_, _ = promptLoginChoice()
	})

	if len(hints) != 7 {
		t.Fatalf("expected 7 key hints, collected %d: %v", len(hints), hints)
	}
	for name, text := range hints {
		if !strings.Contains(text, client.APIKeysURL) {
			t.Errorf("%s does not name the keys page %s:\n%s", name, client.APIKeysURL, text)
		}
		if strings.Contains(text, hostOf(client.EndpointConsoleURL)) {
			t.Errorf("%s names the endpoint console, which issues no keys:\n%s", name, text)
		}
		if h := retiredHostIn(text); h != "" {
			t.Errorf("%s names the retired host %s:\n%s", name, h, text)
		}
	}
	// The sign-in lines name the console's host, the way a person types it.
	for name, text := range map[string]string{
		"login short":      login.Short,
		"login long":       login.Long,
		"the login prompt": choice,
	} {
		if !strings.Contains(strings.ToLower(text), "sign in at "+signIn) &&
			!strings.Contains(text, "open "+signIn+" in your browser") {
			t.Errorf("%s must name the console it signs in at (%s): %q", name, signIn, text)
		}
		if strings.Contains(text, hostOf(client.EndpointConsoleURL)) {
			t.Errorf("%s names the endpoint console, which runs no device flow: %q", name, text)
		}
	}
}

// TestConsoleHosts_AnOverriddenConsoleIsTheOneNamed: with --console-url the device flow
// dials another console, so the hints must follow it there.
func TestConsoleHosts_AnOverriddenConsoleIsTheOneNamed(t *testing.T) {
	saved := g
	t.Cleanup(func() { g = saved })
	g = globalFlags{consoleURL: " https://console.example.test/ "}

	if got, want := apiKeysURL(), "https://console.example.test/api-keys"; got != want {
		t.Fatalf("apiKeysURL() = %q, want %q", got, want)
	}
	_, stderr := captureStd(t, func() {
		deepencli_pipeStdin(t, "\n")
		_, _ = promptLoginChoice()
	})
	if !strings.Contains(stderr, "sign in at console.example.test ") {
		t.Fatalf("the prompt must name the overridden console: %q", stderr)
	}

	g = globalFlags{}
	if got := apiKeysURL(); got != client.APIKeysURL {
		t.Fatalf("with no override apiKeysURL() = %q, want %q", got, client.APIKeysURL)
	}
}
