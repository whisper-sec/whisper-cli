// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// whale_syspolicy.go is `whisper whale syspolicy`: the settings a fleet
// administrator delivers by MDM, read back from the platform's own policy store, and the
// profile template that puts them there.
//
// The rule this file is built around is the one this codebase keeps breaking: a setting
// that can be written and read back but that nothing HONOURS is decoration. So the
// catalogue below is deliberately short, and every entry in it names the place its value
// takes effect. `list` prints that column. If a key ever appears here without a code path
// behind it, the wiring test in whale_syspolicy_test.go fails, because it asserts the
// effect and not the plumbing.
//
// It is configuration management, not a security boundary, and the help text says so in
// those words. The binary runs as the user; anyone who can run it can also pass a flag.
// What a policy buys is a machine that arrives already pointed at the right control plane
// with the right key, and a user who is not invited to sign into a personal tenant by
// accident. Claiming more than that would be the second defect this campaign keeps
// finding: accurate code under an inaccurate sentence.

// sysPolicyDomain is the preference domain / registry key name the policy lives under. It
// is the same identifier the macOS package installs as (security.whisper.cli), so an
// administrator writes one name into their MDM and it matches the thing on disk.
const sysPolicyDomain = "security.whisper.cli"

// windowsSysPolicySubKey is where Windows keeps machine policy for an application, and
// windowsSysPolicyKeyPath is the same key spelled the way a .reg file spells it. Both
// live here rather than in the windows-only file so the .reg template can be generated
// from any host, which is also how it gets tested.
const windowsSysPolicySubKey = `SOFTWARE\Policies\Whisper`

const windowsSysPolicyKeyPath = `HKEY_LOCAL_MACHINE\` + windowsSysPolicySubKey

// --- the catalogue ------------------------------------------------------------------

// sysPolicySpec is one managed setting: its key, its type, what it is for, and - the
// load-bearing field - where in this binary the value actually changes behaviour.
type sysPolicySpec struct {
	Name    string // the key exactly as an MDM writes it
	Kind    string // "string" | "bool"
	Help    string
	Applies string
}

// sysPolicySpecs is the whole surface. Short on purpose: three keys that each do
// something, rather than twenty that read well in a table.
func sysPolicySpecs() []sysPolicySpec {
	return []sysPolicySpec{
		{
			Name:    "ControlURL",
			Kind:    "string",
			Applies: "the --control-url default",
			Help: "the control-plane front door every command talks to. It fills --control-url when " +
				"the command line did not pass one, so a managed host reaches your control plane with " +
				"no per-user setup.",
		},
		{
			Name:    "KeyFile",
			Kind:    "string",
			Applies: "the --key-file default",
			Help: "the file the API key is read from, and the file `whisper login <key>` writes. It " +
				"fills --key-file when the command line did not pass one, so a key your MDM already " +
				"dropped on the machine is the key every command uses.",
		},
		{
			Name:    "AllowInteractiveLogin",
			Kind:    "bool",
			Applies: "`whisper login`, and every key prompt",
			Help: "whether a person at this machine may sign in interactively; true unless you set it. " +
				"When false, `whisper login` with no key argument refuses instead of opening the browser " +
				"sign-in, bare `whisper` refuses instead of walking someone through one, and no command " +
				"prompts for a key. `whisper login <key>` still saves a key you handed out.",
		},
	}
}

// sysPolicyTemplateValue is the value the generated profile ships for a key. Every one of
// them is a real, harmless value, so the template can be installed as-is and change
// nothing surprising: the administrator edits the one or two lines they care about rather
// than hunting for the placeholders they must not leave behind.
func sysPolicyTemplateValue(spec sysPolicySpec, goos string) string {
	switch spec.Name {
	case "ControlURL":
		return client.DefaultControlURL
	case "KeyFile":
		return managedKeyFileExample(goos)
	case "AllowInteractiveLogin":
		return "true"
	}
	return ""
}

// managedKeyFileExample is the machine-wide place an MDM would drop a provisioned key on
// each platform. It is an example in a template, never a path this binary invents on its
// own: with no policy the key file is unchanged at ~/.config/whisper/key.
func managedKeyFileExample(goos string) string {
	switch goos {
	case "darwin":
		return "/Library/Application Support/Whisper/key"
	case "windows":
		return `C:\ProgramData\Whisper\key`
	default:
		return "/etc/whisper/key"
	}
}

// --- the store ----------------------------------------------------------------------

// sysPolicyStore is one platform policy store exactly as we found it. Err is separate
// from Present on purpose: a store that exists and cannot be parsed must never render as
// "no policy", which is the failure mode where a broken profile looks like a clean host.
type sysPolicyStore struct {
	Origin   string   `json:"origin,omitempty"`
	Searched []string `json:"searched"`
	Present  bool     `json:"present"`
	Values   map[string]any
	Err      error
}

// readSysPolicyStore is the seam every caller goes through, so a test can hand the whole
// resolver a store without a managed Mac.
var readSysPolicyStore = func() sysPolicyStore { return sysPolicyStoreFor(runtime.GOOS) }

// sysPolicyPathsFor is a var so a test can point the file-backed platforms at a temp dir.
var sysPolicyPathsFor = defaultSysPolicyPaths

// defaultSysPolicyPaths lists, most specific first, where a managed policy can live.
//
// macOS: MDM flattens a com.apple.ManagedClient.preferences payload into
// /Library/Managed Preferences, per-user first when the payload was user-scoped. Linux
// and the other unixes: one JSON file beside the sensor's own /etc/whisper/sensor.json,
// because a second convention would be a second thing to explain.
//
// These are paths on a NAMED platform, not on the host: the goos argument is the whole
// point of the signature. So they are joined with path.Join, which always writes "/",
// and never filepath.Join, which writes the HOST's separator. Asked for the darwin store
// from a Windows box, filepath.Join answered
// `\Library\Managed Preferences\security.whisper.cli.plist`, which is not a location any
// MDM writes to and not a string worth printing to anybody. On darwin itself the two
// agree exactly, so nothing about the platform that matters changes.
func defaultSysPolicyPaths(goos string) []string {
	switch goos {
	case "darwin":
		var out []string
		if u := currentUsername(); u != "" {
			out = append(out, path.Join("/Library/Managed Preferences", u, sysPolicyDomain+".plist"))
		}
		return append(out, path.Join("/Library/Managed Preferences", sysPolicyDomain+".plist"))
	case "windows":
		return nil // the registry, not a path: see whale_syspolicy_windows.go
	default:
		return []string{"/etc/whisper/policy.json"}
	}
}

// currentUsername is best effort. A machine where we cannot name the user still has the
// device-level plist, so failing here costs nothing and must not be an error.
func currentUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return strings.TrimSpace(os.Getenv("USER"))
}

// sysPolicyStoreFor finds and reads the policy store for a platform. It is written
// against a goos argument rather than runtime.GOOS so every branch is reachable from a
// test on any host.
func sysPolicyStoreFor(goos string) sysPolicyStore {
	if goos == "windows" {
		return windowsSysPolicyStore()
	}
	paths := sysPolicyPathsFor(goos)
	st := sysPolicyStore{Searched: paths}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			continue
		}
		st.Origin = p
		st.Present = true
		st.Values, st.Err = readSysPolicyFile(goos, p)
		return st
	}
	return st
}

// applePlistToJSON converts a preference plist to JSON with the tool every macOS has.
// It is a var so a test can exercise the darwin branch on any host.
//
// plutil is used rather than an in-tree parser for one reason: the plist MDM writes into
// /Library/Managed Preferences is a BINARY plist, so an XML-only reader would pass every
// test here and read nothing at all on the hardware it was written for.
var applePlistToJSON = func(path string) ([]byte, error) {
	bin, args := applePlistCommand(path)
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("plutil could not read %s: %s", path, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("plutil could not read %s: %w", path, err)
	}
	return out, nil
}

// applePlistCommand is the conversion this binary runs on a Mac. It is a named function
// so a test on any host can pin the argv: the command itself cannot be executed off a
// Mac, and an argv that drifted would fail only on the hardware it was written for.
func applePlistCommand(path string) (string, []string) {
	return "/usr/bin/plutil", []string{"-convert", "json", "-o", "-", path}
}

// readSysPolicyFile reads one store file into raw values.
func readSysPolicyFile(goos, path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", path, err)
	}
	if goos == "darwin" {
		if raw, err = applePlistToJSON(path); err != nil {
			return nil, err
		}
	}
	var vals map[string]any
	if err := json.Unmarshal(raw, &vals); err != nil {
		return nil, fmt.Errorf("%s is not a readable settings dictionary: %w", path, err)
	}
	return vals, nil
}

// --- resolution ---------------------------------------------------------------------

// sysPolicy is the resolved policy this process runs under.
//
// The interactive-login field is stored INVERTED, as a denial rather than a permission,
// so that the zero value of this struct is "nothing is restricted" - exactly a machine
// with no policy at all. A struct that is copied, reset or constructed by a path that
// forgets a field must never lock a person out of their own CLI.
type sysPolicy struct {
	ControlURL         string
	KeyFile            string
	NoInteractiveLogin bool
	Origin             string // where the values came from; "" when no store was found
}

// sysPolicySetting is one row of `syspolicy list`.
type sysPolicySetting struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	Source  string `json:"source"` // "managed" | "default"
	Help    string `json:"help"`
	Applies string `json:"applies"`
}

// sysPolicyView is the whole answer, and what --json emits.
type sysPolicyView struct {
	Platform string             `json:"platform"`
	Store    string             `json:"store,omitempty"`
	Searched []string           `json:"searched"`
	Managed  bool               `json:"managed"`
	Error    string             `json:"error,omitempty"`
	Settings []sysPolicySetting `json:"settings"`
	Notes    []string           `json:"notes,omitempty"`
}

// resolveSysPolicy turns a store into the policy plus the view that explains it.
//
// Liberal in what it accepts, per the robustness principle: a key may be spelled in any
// case, and a boolean may arrive as a real boolean, as "true"/"yes"/"on", or as 1/0,
// because those are the shapes an MDM, a .reg file and a hand-edited JSON produce.
// Conservative in what it does: a value it cannot use is REPORTED and ignored, never
// half-applied. A control URL that is not a URL, or a relative key file that would
// resolve against whatever directory the user happened to be in, are both refused.
func resolveSysPolicy(store sysPolicyStore) (sysPolicy, sysPolicyView) {
	p := sysPolicy{}
	v := sysPolicyView{
		Platform: runtime.GOOS,
		Store:    store.Origin,
		Searched: store.Searched,
		Managed:  store.Present,
	}
	if store.Err != nil {
		v.Error = store.Err.Error()
	}
	if store.Present && store.Err == nil {
		p.Origin = store.Origin
	}
	for _, spec := range sysPolicySpecs() {
		raw, found := lookupSysPolicyValue(store.Values, spec.Name)
		set := sysPolicySetting{Name: spec.Name, Type: spec.Kind, Source: "default", Help: spec.Help, Applies: spec.Applies}
		switch spec.Name {
		case "ControlURL":
			set.Value = client.DefaultControlURL
		case "KeyFile":
			set.Value = client.DefaultKeyFile()
		case "AllowInteractiveLogin":
			set.Value = "true"
		}
		if found {
			applied, note := applySysPolicySetting(&p, spec, raw)
			if note != "" {
				v.Notes = append(v.Notes, note)
			}
			if applied != "" {
				set.Value = applied
				set.Source = "managed"
			}
		}
		v.Settings = append(v.Settings, set)
	}
	// A store we found and could not read is the case that must never look like a clean
	// host. The state is said by the store line the table prints; this adds the reason,
	// which is the part that tells an administrator what to fix.
	if store.Present && store.Err != nil {
		v.Notes = append(v.Notes, "reason: "+store.Err.Error())
	}
	// Unknown keys are the administrator's typo, and silence is the wrong answer.
	for _, k := range unknownSysPolicyKeys(store.Values) {
		v.Notes = append(v.Notes, "the policy sets "+k+", which this version does not know; it is ignored. "+
			"`whisper whale syspolicy list` names every key that does something")
	}
	return p, v
}

// lookupSysPolicyValue is the case-insensitive lookup. Exact first, so a store that
// carries both spellings is never ambiguous.
func lookupSysPolicyValue(vals map[string]any, name string) (any, bool) {
	if vals == nil {
		return nil, false
	}
	if v, ok := vals[name]; ok {
		return v, true
	}
	for k, v := range vals {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return nil, false
}

// unknownSysPolicyKeys names everything in the store that no spec claims.
func unknownSysPolicyKeys(vals map[string]any) []string {
	if len(vals) == 0 {
		return nil
	}
	known := map[string]bool{}
	for _, s := range sysPolicySpecs() {
		known[strings.ToLower(s.Name)] = true
	}
	var out []string
	for k := range vals {
		// A leading underscore is the documented "this is not a setting" convention, and it
		// is how the JSON template carries its own comment: JSON has nowhere else to put
		// one. Warning about it would mean the file we print fails the check we ship.
		if strings.HasPrefix(k, "_") {
			continue
		}
		if !known[strings.ToLower(k)] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// applySysPolicySetting validates one raw value and writes it into the policy. It
// returns the value as it will be shown, or "" plus a note when it was refused.
func applySysPolicySetting(p *sysPolicy, spec sysPolicySpec, raw any) (string, string) {
	switch spec.Kind {
	case "bool":
		b, ok := coerceSysPolicyBool(raw)
		if !ok {
			return "", fmt.Sprintf("%s must be a boolean, and the policy set %s; ignored", spec.Name, describeSysPolicyValue(raw))
		}
		if spec.Name == "AllowInteractiveLogin" {
			p.NoInteractiveLogin = !b
		}
		return strconv.FormatBool(b), ""
	default:
		s, ok := raw.(string)
		if !ok {
			return "", fmt.Sprintf("%s must be a string, and the policy set %s; ignored", spec.Name, describeSysPolicyValue(raw))
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return "", fmt.Sprintf("%s is set to an empty string; ignored", spec.Name)
		}
		switch spec.Name {
		case "ControlURL":
			u, err := url.Parse(s)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return "", fmt.Sprintf("ControlURL must be an http(s) URL, and the policy set %q; ignored", s)
			}
			p.ControlURL = s
		case "KeyFile":
			if !filepath.IsAbs(s) {
				return "", fmt.Sprintf("KeyFile must be an absolute path, and the policy set %q; ignored "+
					"(a relative path would resolve against whatever directory the command was run from)", s)
			}
			p.KeyFile = s
		}
		return s, ""
	}
}

// coerceSysPolicyBool accepts every shape a policy store produces for a boolean.
func coerceSysPolicyBool(raw any) (bool, bool) {
	switch v := raw.(type) {
	case bool:
		return v, true
	case float64:
		return v != 0, true
	case int:
		return v != 0, true
	case int64:
		return v != 0, true
	case uint64:
		return v != 0, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "yes", "on", "1", "enabled":
			return true, true
		case "false", "no", "off", "0", "disabled":
			return false, true
		}
	}
	return false, false
}

// describeSysPolicyValue renders a rejected value for an error message without pretending
// it was a type it was not.
func describeSysPolicyValue(raw any) string {
	switch v := raw.(type) {
	case string:
		return strconv.Quote(v)
	case nil:
		return "nothing"
	default:
		return fmt.Sprintf("%v (%T)", v, v)
	}
}

// --- what the policy actually changes -------------------------------------------------

// activeSysPolicy is the policy this process resolved, set once by the root command's
// PersistentPreRunE before any subcommand runs. Its zero value restricts nothing, so a
// path that runs without the hook - a unit test constructing a command directly - behaves
// exactly as it did before this file existed.
var activeSysPolicy sysPolicy

// applySysPolicy installs the resolved policy and fills in the globals it manages.
//
// A value passed on the command line still wins. That is the honest ordering for a tool
// the user runs themselves: a policy that silently overrode --control-url would break
// scripts without telling anyone, and it would buy nothing, since the person who can pass
// the flag can also edit the file. The policy's job is to be the DEFAULT on a machine
// nobody configured by hand.
func applySysPolicy(p sysPolicy) {
	activeSysPolicy = p
	if g.controlURL == "" && p.ControlURL != "" {
		g.controlURL = p.ControlURL
	}
	if g.keyFile == "" && p.KeyFile != "" {
		g.keyFile = p.KeyFile
	}
}

// interactiveLoginAllowed is the single question the login paths ask.
func interactiveLoginAllowed() bool { return !activeSysPolicy.NoInteractiveLogin }

// sysPolicyLoginRefusal is what a person sees when the policy has switched interactive
// sign-in off. It names the key, the file it came from, and the way forward, because an
// error that only says "no" costs an afternoon.
//
// It is deliberately NOT a client.ProblemError. friendly() collapses every 401/403 problem
// that is not our own "no key" into the single line "your key was not accepted - run:
// whisper login", which on this path is both useless and untrue: the key is fine, and
// running the command it recommends is the thing that was just refused. Measured on the
// built binary before this was changed, which is why the test below asserts the RENDERED
// line rather than the error value.
func sysPolicyLoginRefusal() error {
	where := activeSysPolicy.Origin
	if where == "" {
		where = "the managed policy on this host"
	}
	msg := "interactive sign-in is switched off by AllowInteractiveLogin in " + where + "."
	if activeSysPolicy.KeyFile != "" {
		msg += " This host reads its key from " + activeSysPolicy.KeyFile +
			", which your administrator provisions; nothing else is needed here."
	} else {
		msg += " Your administrator provisions the key for this host."
	}
	msg += " `whisper login <key>` still saves a key you were given."
	return errors.New(msg)
}

// --- the command ----------------------------------------------------------------------

func newWhaleSysPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "syspolicy",
		Short: "Settings your MDM manages on this host, and the profile that delivers them",
		Long: "whisper whale syspolicy - the managed settings in effect on this machine.\n\n" +
			"  list       every managed setting, its value, and where the value came from\n" +
			"  template   an MDM profile that delivers those settings, for this platform\n\n" +
			"This is configuration management, not a security boundary, and the difference\n" +
			"matters enough to say here: the binary runs as the user, so a person who can run\n" +
			"it can also pass a flag. What a policy buys is a machine that arrives already\n" +
			"pointed at the right control plane with the right key, and a user who is not\n" +
			"invited to sign into a personal tenant by accident.\n\n" +
			"`list` shows what the POLICY says. `whisper config` shows what this process\n" +
			"actually resolved once flags and the environment were applied.",
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newWhaleSysPolicyListCmd(), newWhaleSysPolicyTemplateCmd())
	return asParent(cmd)
}

func newWhaleSysPolicyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Every managed setting, its value, and where that value came from",
		Long:  sysPolicyListLong(),
		Args:  cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, view := resolveSysPolicy(readSysPolicyStore())
			if g.jsonOut {
				emitJSONValue(view)
				return nil
			}
			renderSysPolicy(view)
			return nil
		},
	}
}

// sysPolicyListLong documents every key from the same catalogue the reader and the
// templates are built from, so `--help` cannot describe a setting that does not exist or
// miss one that does.
func sysPolicyListLong() string {
	var b strings.Builder
	b.WriteString("Read the platform policy store and print every setting this version honours.\n\n")
	b.WriteString("The APPLIES column is the point of the table: it names where the value changes what\n")
	b.WriteString("the binary does. A setting that could be written and read back but that nothing\n")
	b.WriteString("honoured would be decoration, so nothing is listed here without it.\n\n")
	b.WriteString("A policy that is installed and unreadable is reported as exactly that, never as an\n")
	b.WriteString("absent one.\n\nThe settings:\n\n")
	for _, spec := range sysPolicySpecs() {
		b.WriteString("  " + spec.Name + " (" + spec.Kind + ")\n")
		for _, line := range wrapSysPolicyHelp(spec.Help, 74) {
			b.WriteString("    " + line + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("Keys are matched without regard to case, and a boolean may be written as a real\n")
	b.WriteString("boolean, as true/false/yes/no/on/off, or as 1/0, because that is what an MDM, a\n")
	b.WriteString(".reg file and a hand-edited JSON each produce. A value that cannot be used is\n")
	b.WriteString("reported and ignored, never half-applied.")
	return b.String()
}

// wrapSysPolicyHelp is a plain greedy wrap, so the catalogue can hold one long sentence
// per key rather than pre-broken lines that would have to be re-broken by hand on edit.
func wrapSysPolicyHelp(s string, width int) []string {
	var out []string
	line := ""
	for _, w := range strings.Fields(s) {
		switch {
		case line == "":
			line = w
		case len(line)+1+len(w) <= width:
			line += " " + w
		default:
			out = append(out, line)
			line = w
		}
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

func renderSysPolicy(v sysPolicyView) {
	rows := make([][]string, 0, len(v.Settings))
	for _, s := range v.Settings {
		rows = append(rows, []string{s.Name, orDash(s.Value), s.Source, s.Applies})
	}
	printTable([]string{"SETTING", "VALUE", "SOURCE", "APPLIES"}, rows)
	fmt.Fprintln(os.Stdout)
	switch {
	case v.Managed && v.Error != "":
		whaleNote("policy store: %s - INSTALLED BUT UNREADABLE, so every value above is the built-in default", v.Store)
	case v.Managed:
		whaleNote("policy store: %s", v.Store)
	case len(v.Searched) > 0:
		whaleNote("no managed policy on this host (looked in %s)", strings.Join(v.Searched, ", "))
	default:
		whaleNote("no managed policy on this host")
	}
	for _, n := range v.Notes {
		whaleNote("%s", n)
	}
	if !v.Managed {
		whaleNote("`whisper whale syspolicy template` prints the profile that delivers these settings")
	}
}

func newWhaleSysPolicyTemplateCmd() *cobra.Command {
	var platform string
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Print an MDM profile that delivers the managed settings",
		Long: "Print a ready-to-install profile carrying every setting `syspolicy list` reads:\n" +
			"a .mobileconfig for macOS, a .reg file for Windows, and the JSON file for Linux.\n\n" +
			"It is generated from the same catalogue the reader uses, so the template and the\n" +
			"thing that reads it cannot drift apart.\n\n" +
			"Every value in it is a real one rather than a placeholder you have to remember to\n" +
			"replace. Read the KeyFile line before you install it: it points at the machine-wide\n" +
			"path an MDM would provision a key at, NOT at the per-user default, so a machine\n" +
			"with no key there ends up with no key from a file at all. Provision it, change it,\n" +
			"or drop the line.\n\n" +
			"  whisper whale syspolicy template > whisper.mobileconfig\n" +
			"  whisper whale syspolicy template --platform windows > whisper-policy.reg",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			goos, err := normaliseSysPolicyPlatform(platform)
			if err != nil {
				return err
			}
			out, err := sysPolicyTemplate(goos)
			if err != nil {
				return err
			}
			fmt.Fprint(os.Stdout, out)
			return nil
		},
	}
	cmd.Flags().StringVar(&platform, "platform", "",
		"macos | windows | linux (default: this host)")
	return cmd
}

// normaliseSysPolicyPlatform accepts the spellings a person actually types.
func normaliseSysPolicyPlatform(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return runtime.GOOS, nil
	case "mac", "macos", "osx", "darwin", "apple":
		return "darwin", nil
	case "win", "windows":
		return "windows", nil
	case "linux", "unix":
		return "linux", nil
	}
	return "", usageErr("unknown platform %q - use macos, windows or linux", s)
}

// sysPolicyTemplate renders the profile for a platform.
func sysPolicyTemplate(goos string) (string, error) {
	switch goos {
	case "darwin":
		return appleSysPolicyProfile(goos)
	case "windows":
		return windowsSysPolicyReg(goos), nil
	default:
		return linuxSysPolicyJSON(goos)
	}
}

// appleSysPolicyProfile builds a com.apple.ManagedClient.preferences payload: the shape
// every MDM accepts, and the one that lands in /Library/Managed Preferences where `list`
// reads it back.
func appleSysPolicyProfile(goos string) (string, error) {
	outer, err := sysPolicyUUID()
	if err != nil {
		return "", err
	}
	inner, err := sysPolicyUUID()
	if err != nil {
		return "", err
	}
	var settings strings.Builder
	for _, spec := range sysPolicySpecs() {
		val := sysPolicyTemplateValue(spec, goos)
		settings.WriteString("\t\t\t\t\t\t\t<key>" + spec.Name + "</key>\n")
		if spec.Kind == "bool" {
			settings.WriteString("\t\t\t\t\t\t\t<" + val + "/>\n")
			continue
		}
		settings.WriteString("\t\t\t\t\t\t\t<string>" + xmlEscape(val) + "</string>\n")
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadIdentifier</key>
	<string>` + sysPolicyDomain + `.syspolicy</string>
	<key>PayloadUUID</key>
	<string>` + outer + `</string>
	<key>PayloadDisplayName</key>
	<string>Whisper CLI</string>
	<key>PayloadDescription</key>
	<string>Settings for the Whisper CLI. Read them back on the machine with: whisper whale syspolicy list. KeyFile is where your MDM provisions the key, not the per-user default: provision it, change it, or remove it.</string>
	<key>PayloadOrganization</key>
	<string>Your organisation</string>
	<key>PayloadScope</key>
	<string>System</string>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadType</key>
			<string>com.apple.ManagedClient.preferences</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>PayloadIdentifier</key>
			<string>` + sysPolicyDomain + `.syspolicy.settings</string>
			<key>PayloadUUID</key>
			<string>` + inner + `</string>
			<key>PayloadDisplayName</key>
			<string>Whisper CLI settings</string>
			<key>PayloadContent</key>
			<dict>
				<key>` + sysPolicyDomain + `</key>
				<dict>
					<key>Forced</key>
					<array>
						<dict>
							<key>mcx_preference_settings</key>
							<dict>
` + settings.String() + `							</dict>
						</dict>
					</array>
				</dict>
			</dict>
		</dict>
	</array>
</dict>
</plist>
`, nil
}

// windowsSysPolicyReg builds the .reg file for HKLM\SOFTWARE\Policies\Whisper.
//
// Two details are load-bearing and easy to lose. Lines end CRLF, because a .reg file with
// bare newlines is rejected. And the whole file stays ASCII: regedit reads a "Version
// 5.00" file as UTF-16 only when it starts with the UTF-16 BOM, and otherwise as ANSI, so
// a single curly quote in a help string here would import as mojibake. The test enforces
// it, since nothing about writing the sentence would tell you.
func windowsSysPolicyReg(goos string) string {
	var b strings.Builder
	b.WriteString("Windows Registry Editor Version 5.00\r\n\r\n")
	b.WriteString("; Whisper CLI managed settings. Read them back on the machine with:\r\n")
	b.WriteString(";   whisper whale syspolicy list\r\n")
	b.WriteString("; Deploy with an MDM or with: reg import whisper-policy.reg\r\n")
	b.WriteString("; KeyFile below is where your MDM provisions the key, not the per-user\r\n")
	b.WriteString("; default. Provision it, change it, or delete that line.\r\n\r\n")
	b.WriteString("[" + windowsSysPolicyKeyPath + "]\r\n")
	for _, spec := range sysPolicySpecs() {
		val := sysPolicyTemplateValue(spec, goos)
		for _, line := range wrapSysPolicyHelp(spec.Help, 76) {
			b.WriteString("; " + line + "\r\n")
		}
		if spec.Kind == "bool" {
			n := "0"
			if val == "true" {
				n = "1"
			}
			b.WriteString(`"` + spec.Name + `"=dword:0000000` + n + "\r\n")
			continue
		}
		b.WriteString(`"` + spec.Name + `"="` + strings.ReplaceAll(val, `\`, `\\`) + `"` + "\r\n")
	}
	return b.String()
}

// linuxSysPolicyJSON builds /etc/whisper/policy.json. JSON has no comments, so the note
// travels as a _comment key rather than as something a parser would choke on. The leading
// underscore is the convention for "not a setting", and the reader skips those rather than
// reporting the file it printed as carrying a key it does not know.
func linuxSysPolicyJSON(goos string) (string, error) {
	obj := map[string]any{
		"_comment": "Whisper CLI managed settings, installed at /etc/whisper/policy.json. " +
			"Read them back with: whisper whale syspolicy list. KeyFile is where your MDM " +
			"provisions the key, not the per-user default: provision it, change it, or drop " +
			"the line. Keys beginning with an underscore are notes, not settings.",
	}
	for _, spec := range sysPolicySpecs() {
		val := sysPolicyTemplateValue(spec, goos)
		if spec.Kind == "bool" {
			obj[spec.Name] = val == "true"
			continue
		}
		obj[spec.Name] = val
	}
	b, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

// sysPolicyUUID mints a profile UUID. A var so the template test is deterministic; the
// real one is random because two profiles installed on one machine must not collide.
var sysPolicyUUID = randomUUID

func randomUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("could not mint a profile UUID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 1
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])), nil
}

// xmlEscape is the small subset a plist value needs.
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}
