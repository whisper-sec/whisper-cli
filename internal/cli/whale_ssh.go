// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/trustverify"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_ssh.go is `whisper whale ssh`: SSH into a fleet node with the host key proven from
// the IANA DNSSEC root before the connection is trusted, and no key ever copied to the
// target.
//
// The one design decision worth reading before the code. OpenSSH auto-accepts an SSHFP
// only when getrrsetbyname reports RRSET_VALIDATED, which it takes from the AD bit, and
// the Whisper resolver does not set the AD bit. So through the Whisper
// resolver, `ssh -o VerifyHostKeyDNS=yes` prints "Matching host key fingerprint found in
// DNS" and then STILL PROMPTS, and any design that leans on it is leaning on nothing.
//
// Therefore this command validates the SSHFP ITSELF, in this process, walking the chain
// from the compiled-in IANA root anchor with cli/trustverify, and hands OpenSSH a key that
// is already proven. Two ways, because both must work on the machines people have:
//
// - OpenSSH 8.5 and newer: -o KnownHostsCommand, which calls this binary back with the
// key the server just offered. One connection, no scan, no window in which an
// unverified key is on disk.
// - Older OpenSSH: ssh-keyscan, verified here against the same validated pins, written
// to a temporary known_hosts that lives exactly as long as the ssh process.
//
// In both, UserKnownHostsFile and GlobalKnownHostsFile are pointed at /dev/null and
// StrictHostKeyChecking is yes, so the ONLY thing that can accept the host is a
// DNSSEC-validated SSHFP. There is no trust-on-first-use path through this command.
//
// What this command does NOT decide is who may log in. That is the AuthorizedKeysCommand
// and AuthorizedPrincipalsCommand reading a DNSSEC-signed ACL ON THE TARGET, and the denial
// belongs in the target's auth log where an auditor can find it. `--explain` says where
// that decision is made rather than implying this client makes it.

// whaleSSHDefaultPort is the port ssh uses when nobody says otherwise.
const whaleSSHDefaultPort = 22

// whaleSSHScanTimeout bounds the fallback host key scan.
const whaleSSHScanTimeout = 5 * time.Second

func newWhaleSSHCmd() *cobra.Command {
	var explain, printCmd bool
	var resolver, sshPath, login string
	var port int

	cmd := &cobra.Command{
		Use:   "ssh [user@]<node> [-- ssh options]",
		Short: "SSH to a node with the host key proven from the IANA DNSSEC root",
		Long: "Connect to a fleet node over SSH, with the host key verified before the connection\n" +
			"is trusted and with no key of yours ever copied to the target.\n\n" +
			"The host key is checked HERE, in this process, against the SSHFP record published\n" +
			"for the node, validated from the IANA root trust anchor compiled into this binary.\n" +
			"It is NOT `ssh -o VerifyHostKeyDNS=yes`: that reads the AD bit, our resolver never\n" +
			"sets AD, and it would print a DNS match and then prompt you anyway.\n\n" +
			"There is no trust-on-first-use here. If no SSHFP is published, or the offered key\n" +
			"does not match one, the connection is refused and the message says which.\n\n" +
			"Who may log in is decided ON the target by its authorized-keys command reading a\n" +
			"DNSSEC-signed ACL, so a removed principal is denied there and the denial lands in\n" +
			"the target's auth log. `--explain` names both halves without connecting.\n\n" +
			"The argument shape is ssh's own: anything after the destination is the remote\n" +
			"command, and anything after -- is an ssh(1) option inserted before it.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// ssh's own argument shape, kept: [options] destination [command...]. Anything
			// after the destination is the remote command, in the position ssh puts it;
			// anything after -- is an ssh OPTION, inserted before the destination.
			// SetInterspersed(false) stops pflag at the first positional, so a later `--`
			// arrives as a plain argument and ArgsLenAtDash never sees it. Split on it here.
			args, sshOptions := splitAtDoubleDash(args, cmd.ArgsLenAtDash())
			if len(args) == 0 {
				return usageErr("name a node: `whisper whale ssh [user@]<node>`")
			}
			remoteCommand := args[1:]
			user, nodeRef := splitSSHDestination(args[0])
			if login != "" {
				user = login
			}
			cx, cancel := ctx()
			defer cancel()
			c, _ := resolveClient(false, false) // the fleet lookup is a convenience, not a requirement
			node, err := resolveWhaleNode(cx, c, nodeRef)
			if err != nil {
				return err
			}
			v := verifyWhaleSSHHost(cx, node, resolver)
			if explain {
				explainWhaleSSH(cx, c, v)
				if v.Error != "" {
					return &client.ProblemError{Status: 502, Title: "host key not proven", Detail: v.Error}
				}
				return nil
			}
			if v.Error != "" {
				return &client.ProblemError{Status: 502, Title: "host key not proven", Detail: v.Error}
			}
			return dialWhaleSSH(cx, v, user, port, sshPath, sshOptions, remoteCommand, printCmd)
		},
	}
	cmd.Flags().BoolVar(&explain, "explain", false, "name the SSHFP record and the validation chain, and connect to nothing")
	cmd.Flags().StringVarP(&login, "login", "l", "", "the login name on the target (or write it as user@node)")
	cmd.Flags().IntVarP(&port, "port", "p", whaleSSHDefaultPort, "the port to connect to")
	cmd.Flags().StringVar(&resolver, "resolver", "", "resolver to walk the DNSSEC chain through (default: the system resolvers, then public validating ones)")
	cmd.Flags().StringVar(&sshPath, "ssh", "ssh", "the ssh(1) binary to use")
	cmd.Flags().BoolVar(&printCmd, "print-command", false, "print the exact ssh command this would run, and run nothing")
	// ssh's shape: our flags stop at the destination, so `whale ssh db-01 uptime` runs
	// uptime on db-01 the way `ssh db-01 uptime` does, rather than failing on an
	// unrecognised flag.
	cmd.Flags().SetInterspersed(false)
	cmd.AddCommand(newWhaleSSHKnownHostsCmd())
	return cmd
}

// splitAtDoubleDash separates the positional arguments from the ssh options written after
// a literal `--`. dashIdx is cobra's own answer, used when pflag did see the separator.
func splitAtDoubleDash(args []string, dashIdx int) (positional, sshOptions []string) {
	if dashIdx >= 0 && dashIdx <= len(args) {
		return args[:dashIdx], args[dashIdx:]
	}
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

// splitSSHDestination accepts `user@node` and `node`, the way ssh does.
func splitSSHDestination(raw string) (user, node string) {
	s := strings.TrimSpace(raw)
	if i := strings.LastIndex(s, "@"); i > 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}

// --- verification ---------------------------------------------------------------------

// whaleSSHVerification is what we proved, and how. Every field says where it came from,
// because "verified" with no provenance is the claim this command exists to replace.
type whaleSSHVerification struct {
	Target      string           `json:"target"`
	Address     string           `json:"address,omitempty"`
	FQDN        string           `json:"fqdn,omitempty"`
	FQDNVia     string           `json:"fqdn_via,omitempty"`
	Pins        []whale.SSHFPPin `json:"sshfp,omitempty"`
	Signer      string           `json:"signer,omitempty"`
	TrustAnchor string           `json:"trust_anchor"`
	Resolver    string           `json:"resolver,omitempty"`
	Error       string           `json:"error,omitempty"`
}

const whaleSSHAnchorLine = "IANA DNSSEC root -> the zone that holds this node's SSHFP"

// whaleSSHValidate is the ONE place this command establishes trust, behind a package var so
// a test can hand it a fixture. Everything else in this file consumes its result; nothing
// else decides whether a record is trustworthy, so there is exactly one thing to audit.
var whaleSSHValidate = func(cx context.Context, val *trustverify.Validator, name string, qtype uint16) ([]dns.RR, *dns.RRSIG, error) {
	return val.ValidateRRSetSigned(cx, name, qtype)
}

// whaleSSHRun executes ssh(1) with the process's own stdio, and is a package var so the
// argv this command builds can be asserted without opening a connection.
var whaleSSHRun = func(path string, args []string) error {
	child := exec.Command(path, args...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	return child.Run()
}

// verifyWhaleSSHHost resolves the node's canonical name and validates its SSHFP RRset in
// this process. It returns a verification with Error set rather than an error value,
// because --explain must print everything it DID establish even when the last step failed.
func verifyWhaleSSHHost(cx context.Context, node whaleNode, resolver string) whaleSSHVerification {
	v := whaleSSHVerification{
		Target:      firstNonBlank(node.Target.Text, node.Addr.String()),
		TrustAnchor: whaleSSHAnchorLine,
		Resolver:    strings.TrimSpace(resolver),
	}
	if node.Addr.IsValid() {
		v.Address = node.Addr.String()
	}
	val := trustverify.NewValidator(trustverify.NewNetResolver(strings.TrimSpace(resolver)),
		trustverify.IANARootAnchors(), time.Now())

	// The provenance label must be the provenance. resolveWhaleNode records how it found
	// the address, and a name that came out of public DNS must not be labelled as having
	// come from your fleet: a claim about where a fact came from is a fact itself.
	switch {
	// The fleet knows the node's DNS NAME, which is not its id. Reading node.Name
	// here looked an SSHFP up under `agent-a<hex>`, got NXDOMAIN, and refused to connect
	// to a node whose SSHFP was published and valid all along - so `whale ssh db-01`,
	// the one spelling this command exists for, could never work. A fleet hit with
	// no published fqdn now falls THROUGH to the name you typed or to the validated PTR,
	// because a peer we cannot name is not a reason to refuse a node DNS can name.
	case node.Via == "fleet" && node.FQDN != "":
		v.FQDN, v.FQDNVia = trimDot(node.FQDN), "your fleet"
	case node.Target.Kind == whale.KindFQDN:
		v.FQDN, v.FQDNVia = node.Target.Text, "as you named it"
	case node.Addr.IsValid():
		// An address-only target still has one canonical name, and it is the one the
		// reverse tree proves. Reusing the same validated-PTR helper `whale whois` uses
		// keeps one answer to "what is this address called", not two.
		ptr, note := validatedPTR(cx, val, node.Addr)
		if ptr == "" {
			v.Error = "cannot find this node's name: " + note +
				". An SSHFP is published under a name, so without one there is nothing to validate"
			return v
		}
		v.FQDN, v.FQDNVia = ptr, "its PTR, validated here from the IANA root"
	default:
		v.Error = "cannot find this node's name, and an SSHFP is published under a name"
		return v
	}

	rrs, sig, err := whaleSSHValidate(cx, val, dns.Fqdn(v.FQDN), dns.TypeSSHFP)
	if err != nil {
		v.Error = unprovenHostKeyReason(v.FQDN, err)
		return v
	}
	if sig != nil {
		v.Signer = trimDot(sig.SignerName)
	}
	v.Pins = whale.ParseSSHFP(rrs)
	if len(whale.UsableSHA256Pins(v.Pins)) == 0 {
		v.Error = fmt.Sprintf("%s publishes SSHFP records but none of them is a SHA-256 fingerprint (type 2). "+
			"SHA-1 is not proof of anything here, and modern OpenSSH ignores it outright", v.FQDN)
	}
	return v
}

// unprovenHostKeyReason says WHICH of the two failures happened, because they send an
// operator to different places. A zone that publishes no SSHFP at all is a node that was
// never set up to be verified; a record that failed to validate is a DNSSEC problem. The
// old wording called both of them "did not validate", which sent people hunting a signing
// fault that was not there.
//
// The distinction is drawn from the message trustverify produces for an absent RRset. If
// that phrasing ever changes, this falls back to the general wording, which is still true
// of both cases: nothing was proven, so nothing is trusted.
func unprovenHostKeyReason(fqdn string, err error) string {
	const refuse = "Refusing to connect: without a proven host key this is trust on first use, which is what " +
		"this command exists to avoid"
	detail := strings.TrimSuffix(strings.TrimSpace(err.Error()), ".")
	if strings.Contains(detail, "no SSHFP record") {
		return fmt.Sprintf("%s publishes no SSHFP record, so there is no host key to prove and nothing to check "+
			"the server's key against (%s). %s", fqdn, detail, refuse)
	}
	return fmt.Sprintf("the SSHFP for %s did not validate (%s). %s", fqdn, detail, refuse)
}

// explainWhaleSSH prints the whole chain, and connects to nothing.
func explainWhaleSSH(cx context.Context, c *client.Client, v whaleSSHVerification) {
	if g.jsonOut {
		emitJSONValue(v)
		return
	}
	rows := [][]string{{"target", v.Target}}
	if v.Address != "" {
		rows = append(rows, []string{"address", v.Address})
	}
	if v.FQDN != "" {
		rows = append(rows, []string{"name", v.FQDN}, []string{"name from", v.FQDNVia})
	}
	for _, p := range v.Pins {
		rows = append(rows, []string{"sshfp", p.String()})
	}
	if v.Signer != "" {
		rows = append(rows, []string{"signed by", v.Signer})
	}
	rows = append(rows, []string{"trust anchor", v.TrustAnchor})
	rows = append(rows, []string{"validated by", "this client, in-process (our resolver never sets AD)"})
	printTable([]string{"WHALE SSH", ""}, rows)
	fmt.Fprintln(os.Stdout)
	if v.Error != "" {
		whaleNote("NOT proven: %s", v.Error)
	}
	whaleNote("a third party can audit the same records: kdig +dnssec %s SSHFP", v.FQDN)
	whaleNote("%s", whaleSSHPrincipalNote(cx, c))
}

// whaleSSHPrincipalNote says where the login decision is made, and reports the state of
// the ACL document rather than guessing at it. A read that FAILED is reported as a failed
// read, never as an absent policy: those are different facts and only one of them means
// "nobody is authorised".
func whaleSSHPrincipalNote(cx context.Context, c *client.Client) string {
	const where = "who may log in is decided ON the target, by its authorized-keys command reading a DNSSEC-signed ACL; " +
		"a denial appears in the target's auth log"
	if c == nil || c.Credential().IsZero() {
		return where + " (no key here, so your account's ssh ACL was not read)"
	}
	env, err := c.Agents(cx, "policy", map[string]any{})
	if err == nil {
		err = envelopeError(env)
	}
	if err != nil {
		return where + " - your account's ssh ACL COULD NOT BE READ (" + friendly(err) + "), which is not the same as it being empty"
	}
	if sshACLPublished(env) {
		return where + ", and your account publishes an ssh block in its Whalenet ACL"
	}
	return where + ", and your account publishes no ssh block in its Whalenet ACL yet"
}

// sshACLPublished looks for the `ssh` block of the Whalenet ACL in a policy read. It is
// deliberately shallow: the document's schema is the control plane's to define, and this
// only answers "is there one".
//
// It used to look for a nested item.whale.acl.ssh map, a shape op:policy has never
// emitted, so it could only ever return false and this note could only ever say "your
// account publishes no ssh block" - including to an account that publishes one. What
// op:policy really returns is flat {key,value} rows, with the whole document as a JSON
// string in whale.acl.document. That read-back has one reader, and this uses it rather
// than keeping a second guess at the same shape.
func sshACLPublished(env *client.Envelope) bool {
	doc := whale.ACLSummaryFrom(policyPairs(env)).Document
	if strings.TrimSpace(doc) == "" {
		return false
	}
	p, _, err := whale.ParsePolicy([]byte(doc))
	if err != nil {
		return false
	}
	return len(p.SSH) > 0
}

// --- dialling -----------------------------------------------------------------------

// dialWhaleSSH builds the ssh invocation and runs it.
func dialWhaleSSH(cx context.Context, v whaleSSHVerification, user string, port int, sshPath string,
	sshOptions, remoteCommand []string, printOnly bool) error {

	host := v.Address
	if host == "" {
		host = v.FQDN
	}
	// os.DevNull rather than a literal "/dev/null": OpenSSH ships on Windows too, and
	// there the null device is NUL. A path ssh cannot open would make it warn on every
	// connection about a known_hosts file we deliberately do not want it to have.
	args := []string{
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + os.DevNull,
		"-o", "GlobalKnownHostsFile=" + os.DevNull,
		// The alias is what ssh looks the host key up under, in BOTH modes, so the name
		// we validated is the name the check is made against, whatever we dialled.
		"-o", "HostKeyAlias=" + v.FQDN,
	}
	if algs := whale.HostKeyAlgorithmsFor(v.Pins); algs != "" {
		// Never let the server steer us onto a key type the zone cannot vouch for.
		args = append(args, "-o", "HostKeyAlgorithms="+algs)
	}
	if port != whaleSSHDefaultPort {
		args = append(args, "-p", strconv.Itoa(port))
	}

	var cleanup func()
	if whale.SupportsKnownHostsCommand(sshVersionBanner(sshPath)) {
		self, err := os.Executable()
		if err != nil || strings.TrimSpace(self) == "" {
			self = "whisper"
		}
		// The callback re-enters THIS binary. If it is ever installed under the name
		// `whale` (an argv[0] shim contemplates and that does not exist today),
		// the subcommand path is one word shorter, and getting that wrong would make
		// OpenSSH run a command that cannot work.
		verbs := "whale ssh known-hosts"
		if base := strings.TrimSuffix(strings.ToLower(filepath.Base(self)), ".exe"); base == "whale" {
			verbs = "ssh known-hosts"
		}
		khc := fmt.Sprintf("%s %s --fqdn %s", shellQuote(self), verbs, shellQuote(v.FQDN))
		if v.Resolver != "" {
			khc += " --resolver " + shellQuote(v.Resolver)
		}
		khc += " '%H' '%t' '%K'"
		args = append(args, "-o", "KnownHostsCommand="+khc)
		whaleNote("host key: checked as it is offered, against the SSHFP validated from the IANA root")
	} else {
		path, pin, err := pinnedKnownHostsFile(cx, v, host, port)
		if err != nil {
			return err
		}
		cleanup = func() { os.Remove(path) }
		defer cleanup()
		args = append(args, "-o", "UserKnownHostsFile="+path)
		whaleNote("host key matched %s", pin.String())
		whaleNote("your ssh is older than 8.5, so the key was fetched with ssh-keyscan and checked here " +
			"before ssh saw it; the pinned file lives only as long as this connection")
	}

	args = append(args, sshOptions...)
	dest := host
	if user != "" {
		dest = user + "@" + host
	}
	args = append(args, dest)
	args = append(args, remoteCommand...)

	if printOnly {
		fmt.Fprintln(os.Stdout, sshPath+" "+strings.Join(args, " "))
		return nil
	}

	if err := whaleSSHRun(sshPath, args); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			// os.Exit skips defers, so the pinned file goes first or it never goes.
			if cleanup != nil {
				cleanup()
			}
			os.Exit(ee.ExitCode())
		}
		if _, lookErr := exec.LookPath(sshPath); lookErr != nil {
			return usageErr("couldn't find %q to run - is OpenSSH installed and on your PATH?", sshPath)
		}
		return &client.ProblemError{Status: 500, Detail: "ssh exited unexpectedly: " + err.Error()}
	}
	return nil
}

// sshVersionBanner returns `ssh -V` output, which OpenSSH writes to stderr.
var sshVersionBanner = func(sshPath string) string {
	cmd := exec.Command(sshPath, "-V")
	var sb strings.Builder
	cmd.Stderr = &sb
	cmd.Stdout = &sb
	_ = cmd.Run()
	return sb.String()
}

// pinnedKnownHostsFile is the fallback for OpenSSH older than 8.5: fetch the offered host
// keys, prove one against the validated pins HERE, and write only that one.
func pinnedKnownHostsFile(cx context.Context, v whaleSSHVerification, host string, port int) (string, whale.SSHFPPin, error) {
	keys, err := scanHostKeys(cx, host, port)
	if err != nil {
		return "", whale.SSHFPPin{}, &client.ProblemError{Status: 502, Title: "no host key",
			Detail: fmt.Sprintf("could not fetch %s's host key to check it: %s", host, err.Error())}
	}
	var lastErr error
	for _, k := range keys {
		pin, merr := whale.MatchHostKey(k.keyType, k.base64Key, v.Pins)
		if merr != nil {
			lastErr = merr
			continue
		}
		f, ferr := os.CreateTemp("", "whale-known-hosts-*")
		if ferr != nil {
			return "", whale.SSHFPPin{}, fmt.Errorf("writing the pinned host key: %w", ferr)
		}
		if _, werr := fmt.Fprintln(f, whale.KnownHostsLine(v.FQDN, k.keyType, k.base64Key)); werr != nil {
			f.Close()
			os.Remove(f.Name())
			return "", whale.SSHFPPin{}, fmt.Errorf("writing the pinned host key: %w", werr)
		}
		if cerr := f.Close(); cerr != nil {
			os.Remove(f.Name())
			return "", whale.SSHFPPin{}, fmt.Errorf("writing the pinned host key: %w", cerr)
		}
		return f.Name(), pin, nil
	}
	detail := "the host offered no key matching the SSHFP published for it"
	if lastErr != nil {
		detail = lastErr.Error()
	}
	return "", whale.SSHFPPin{}, &client.ProblemError{Status: 502, Title: "host key not proven", Detail: detail}
}

// hostKey is one key ssh-keyscan reported.
type hostKey struct {
	keyType   string
	base64Key string
}

// scanHostKeys is a package var so the fallback path is testable with no network and no
// ssh-keyscan on the box.
var scanHostKeys = func(cx context.Context, host string, port int) ([]hostKey, error) {
	sub, cancel := context.WithTimeout(cx, whaleSSHScanTimeout+2*time.Second)
	defer cancel()
	args := []string{"-T", strconv.Itoa(int(whaleSSHScanTimeout.Seconds()))}
	if port != whaleSSHDefaultPort {
		args = append(args, "-p", strconv.Itoa(port))
	}
	args = append(args, host)
	cmd := exec.CommandContext(sub, "ssh-keyscan", args...)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		if _, lookErr := exec.LookPath("ssh-keyscan"); lookErr != nil {
			return nil, fmt.Errorf("ssh-keyscan is not on your PATH, and this OpenSSH is older than 8.5 so " +
				"the key cannot be checked as it is offered. Install OpenSSH's client tools, or upgrade ssh to 8.5+")
		}
		return nil, err
	}
	return parseKeyscan(string(out)), nil
}

// parseKeyscan reads ssh-keyscan's output. Comment lines (which is where it puts its own
// banner) are skipped, and anything that is not three fields is skipped rather than
// half-parsed.
func parseKeyscan(out string) []hostKey {
	var keys []hostKey
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		keys = append(keys, hostKey{keyType: fields[1], base64Key: fields[2]})
	}
	return keys
}

// shellQuote single-quotes a value for the shell OpenSSH runs KnownHostsCommand through.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// --- the KnownHostsCommand helper ------------------------------------------------------

// newWhaleSSHKnownHostsCmd is the callback OpenSSH 8.5+ invokes with the key the server
// just offered. It prints a known_hosts line ONLY when that key matches an SSHFP validated
// here from the IANA root, and prints nothing at all otherwise, so ssh fails closed.
//
// It is hidden because no person runs it, and it takes the fqdn explicitly rather than
// trusting the host token, so what is validated is what this client resolved and not what
// the connection suggested.
func newWhaleSSHKnownHostsCmd() *cobra.Command {
	var fqdn, resolver string
	cmd := &cobra.Command{
		Use:    "known-hosts <host-token> <key-type> <base64-key>",
		Short:  "internal: OpenSSH KnownHostsCommand callback",
		Hidden: true,
		Args:   cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(fqdn)
			if name == "" {
				return usageErr("--fqdn is required: this callback validates the name the client resolved, " +
					"not the name the connection suggested")
			}
			cx, cancel := ctx()
			defer cancel()
			val := trustverify.NewValidator(trustverify.NewNetResolver(strings.TrimSpace(resolver)),
				trustverify.IANARootAnchors(), time.Now())
			rrs, _, err := whaleSSHValidate(cx, val, dns.Fqdn(name), dns.TypeSSHFP)
			if err != nil {
				return &client.ProblemError{Status: 502, Title: "host key not proven",
					Detail: unprovenHostKeyReason(name, err)}
			}
			pin, merr := whale.MatchHostKey(args[1], args[2], whale.ParseSSHFP(rrs))
			if merr != nil {
				return &client.ProblemError{Status: 502, Title: "host key not proven", Detail: merr.Error()}
			}
			// stdout is ssh's input here and must carry the known_hosts line and nothing
			// else; the human-readable half goes to stderr.
			fmt.Fprintln(os.Stdout, whale.KnownHostsLine(args[0], args[1], args[2]))
			fmt.Fprintf(os.Stderr, "  host key matched %s, validated from the IANA root\n", pin.String())
			return nil
		},
	}
	cmd.Flags().StringVar(&fqdn, "fqdn", "", "the name whose SSHFP must vouch for this key")
	cmd.Flags().StringVar(&resolver, "resolver", "", "resolver to walk the DNSSEC chain through")
	return cmd
}
