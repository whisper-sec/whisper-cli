// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/trustverify"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_ssh_authz.go is the target half of `whisper whale ssh`: the command sshd runs
// as its AuthorizedKeysCommand, so a fleet agent logs in with its own identity key and no
// authorized_keys entry, and the snippet that wires it in.
//
// `whale ssh` proves the HOST to the caller from the node's SSHFP. This proves the CALLER to
// the host the same way: the address the connection came from (recovered through `whale
// caller` when it arrived through `connect --accept`), its validated PTR into this fleet's
// zone, the AAAA back, an active whisper-id1, and the offered key against the agent's own
// validated SSHFP. whale/sshauthz.go holds the decision; this file feeds it what sshd hands
// over, logs the verdict where an auditor looks, and prints the key line or nothing.

// sshAuthzBudget bounds one decision. sshd waits on the command inside LoginGraceTime, and a
// slow resolver must turn into a denial, never into a login that hangs.
const sshAuthzBudget = 15 * time.Second

// sshAuthzSnippetPath is where `install --write` puts the snippet: a drop-in, so the
// operator's own sshd_config is never edited.
const sshAuthzSnippetPath = "/etc/ssh/sshd_config.d/50-whisper-ssh-authz.conf"

// sshAuthzFleetsPath is where `install --write` keeps the fleet set it read from the roster.
// Per-agent tenancy gives every hosted agent its own tenant, so an owner's fleet is a list of
// zones; a file keeps sshd's command line short however long the list grows, and a refresh
// rewrites the file without touching sshd's configuration (sshd runs the check per login).
const sshAuthzFleetsPath = "/etc/ssh/whisper-ssh-authz.fleets"

// sshAuthzFleetsMax bounds what check reads from the fleets file, so a file that grew wrong
// is refused rather than read without end.
const (
	sshAuthzFleetsMaxBytes = 256 << 10
	sshAuthzFleetsMaxLines = 4096
)

// Seams, so the tests can stand in for the network, the host and the log.
var (
	sshAuthzLookup = func(resolver string) whale.AuthzLookup {
		return whale.ValidatorLookup{V: trustverify.NewValidator(trustverify.NewNetResolver(strings.TrimSpace(resolver)),
			trustverify.IANARootAnchors(), time.Now())}
	}
	sshAuthzIsLocal    = isLocalAddr
	sshAuthzLog        = logSSHAuthz
	sshAuthzEUID       = os.Geteuid
	sshAuthzExecutable = os.Executable
	// sshAuthzSshdTest proves sshd accepts the configuration (-t) and returns the effective
	// configuration it would run with (-T), so install can check its lines are the ones in force.
	// sshAuthzPathUnsafe is sshd's own safe_path rule (root-owned, writable by nobody else, along
	// the whole path), applied to the fleets file the check reads.
	sshAuthzPathUnsafe = commandPathUnsafe
	// sshAuthzRoster reads the owner's agents, the same op:list `whale status` lists peers from.
	sshAuthzRoster = func(cx context.Context) ([]whalePeer, error) {
		c, err := resolveClient(false, false)
		if err != nil {
			return nil, err
		}
		if c == nil || c.Credential().IsZero() {
			return nil, errors.New("no key in effect on this host")
		}
		return whaleFleet(cx, c)
	}
	sshAuthzSelfFleet = sshAuthzOwnFleet
	// sshAuthzGroupOf is the primary group of the account sshd runs the check as, which the
	// fleets file is readable by (and nobody else but root).
	sshAuthzGroupOf = func(name string) (int, error) {
		u, err := osuser.Lookup(name)
		if err != nil {
			return 0, err
		}
		return strconv.Atoi(u.Gid)
	}
	sshAuthzFchown   = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }
	sshAuthzSshdTest = func(config string) (string, error) {
		if out, err := exec.Command("sshd", "-t", "-f", config).CombinedOutput(); err != nil {
			return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		out, err := exec.Command("sshd", "-T", "-f", config).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("sshd -T: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return string(out), nil
	}
)

func newWhaleSSHAuthzCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh-authz",
		Short: "Let your fleet's agents log in here with their own key, proven from DNSSEC",
		Long: "The target half of `whisper whale ssh`. sshd runs `ssh-authz check` as its\n" +
			"AuthorizedKeysCommand. It admits a key only when the connection came from an\n" +
			"active agent of your fleet and the key is that agent's own, both proven from the\n" +
			"IANA DNSSEC root in this process:\n\n" +
			"  - the caller's address has a validated PTR to a name directly in one of your\n" +
			"    fleet's zones (each hosted agent has its own tenant, so install writes every\n" +
			"    tenant your roster holds), and that name's validated AAAA points back at it;\n" +
			"  - the name's whisper-id1 TXT says status=active and names the tenant the name\n" +
			"    sits in, so a revoked agent stops;\n" +
			"  - the offered key matches the name's SSHFP (its TLSA 3 1 1 pin only with --allow-tlsa).\n\n" +
			"When your fleet's WhaleACL has an ssh block, install also writes this node's\n" +
			"compiled view beside the fleets file, and a login must ALSO be admitted by an ssh\n" +
			"rule naming the caller, this node and the account. The view moves only when you\n" +
			"run install --write again; a login never calls the control plane.\n\n" +
			"Anything less, including a lookup that times out or an unsigned answer, prints\n" +
			"nothing and sshd says \"Permission denied\". sshd reads authorized_keys before it\n" +
			"runs the command, so keys you added by hand keep working. root is never admitted\n" +
			"unless you name it with --user root. Every decision goes to the auth log (on\n" +
			"macOS the unified log: log show --predicate 'eventMessage CONTAINS \"whisper-ssh-authz\"').\n\n" +
			"  install   print the sshd_config snippet, or write it with --write (as root)\n" +
			"  check     the AuthorizedKeysCommand itself",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newWhaleSSHAuthzCheckCmd(), newWhaleSSHAuthzInstallCmd())
	return cmd
}

// sshAuthzFlags are the policy flags check and install share, so the snippet install writes
// is exactly what check reads.
type sshAuthzFlags struct {
	fleet     []string
	fleetFile string
	aclFile   string
	allow     []string
	users     []string
	resolver  string
	tlsa      bool
}

func (f *sshAuthzFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&f.fleet, "fleet", nil, "a fleet whose agents may log in: a tenant (t...), its zone, or one of its node names (repeatable; install reads your roster when omitted)")
	cmd.Flags().StringVar(&f.fleetFile, "fleet-file", "", "a root-owned file listing fleets, one per line (install writes "+sshAuthzFleetsPath+" from your roster)")
	cmd.Flags().StringVar(&f.aclFile, "acl-file", "", "this node's WhaleACL ssh view (default: "+sshAuthzACLName+" beside the fleets file, else "+sshAuthzACLDefault+"; install writes it)")
	cmd.Flags().StringSliceVar(&f.allow, "allow", nil, "admit only these agents: a full name or its first label (repeatable; default every active agent of the fleet)")
	cmd.Flags().StringSliceVar(&f.users, "user", nil, "the local accounts fleet agents may log in as (repeatable; default any account except root and uid 0)")
	cmd.Flags().StringVar(&f.resolver, "resolver", "", "resolver to walk the DNSSEC chain through (default: the system resolvers, then public ones)")
	cmd.Flags().BoolVar(&f.tlsa, "allow-tlsa", false, "also accept the agent's TLSA 3 1 1 pin when no SSHFP admits the key (it pins the TLS service's key, so whoever holds that can log in too)")
}

// policy is the set check enforces: every --fleet, and every line of --fleet-file. Both may
// be given and are joined. A fleets file that cannot be trusted or read refuses the whole
// policy, inline fleets included: a set with a hole in it is not the set the operator wrote.
func (f *sshAuthzFlags) policy() (whale.AuthzPolicy, error) {
	raw := nonBlank(f.fleet)
	if p := strings.TrimSpace(f.fleetFile); p != "" {
		lines, err := readSSHAuthzFleets(p)
		if err != nil {
			return whale.AuthzPolicy{}, fmt.Errorf("--fleet-file: %v", err)
		}
		raw = append(raw, lines...)
	}
	fleets, err := whale.ParseFleets(raw)
	if err != nil {
		return whale.AuthzPolicy{}, fmt.Errorf("--fleet: %v", err)
	}
	return whale.AuthzPolicy{Fleets: fleets, Allow: nonBlank(f.allow), Users: nonBlank(f.users), AllowTLSA: f.tlsa}, nil
}

// policyWithout is the policy install writes into the command line. With a fleets file the
// fleets live in the file, which check reads per login, and the line names only the file.
func (f *sshAuthzFlags) policyWithout(file string) (whale.AuthzPolicy, error) {
	if file != "" {
		f.fleetFile = file
		return whale.AuthzPolicy{Allow: nonBlank(f.allow), Users: nonBlank(f.users), AllowTLSA: f.tlsa}, nil
	}
	return f.policy()
}

// readSSHAuthzFleets reads the fleets file the way sshd reads its own command: only when root
// owns it and nothing on its path can be written by anyone else, and only a regular file of a
// bounded size. Anything else is an error, which check turns into a denial with the reason.
func readSSHAuthzFleets(path string) ([]string, error) {
	b, err := readSSHAuthzRootFile(path, sshAuthzFleetsMaxBytes, "a fleets file")
	if err != nil {
		return nil, err
	}
	return parseSSHAuthzFleets(path, b)
}

// readSSHAuthzRootFile is the one trusted read behind every file check consults (the fleets
// file and the ssh ACL file): only a regular file root owns, on a path nobody else can
// write, no larger than max, and the same file from the stat to the last byte. what names the
// kind of file in the size refusal.
func readSSHAuthzRootFile(path string, max int64, what string) ([]byte, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", path, err)
	}
	li, err := os.Lstat(real)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", path, err)
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if why := sshAuthzPathUnsafe(real); why != "" {
		return nil, fmt.Errorf("%s cannot be trusted: %s", path, why)
	}
	fh, err := os.Open(real)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", path, err)
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil || !os.SameFile(li, fi) {
		return nil, fmt.Errorf("%s changed while it was being read", path)
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%s is %d bytes, more than %s ever needs (%d)", path, fi.Size(), what, max)
	}
	b, err := io.ReadAll(io.LimitReader(fh, max+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", path, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s grew past %d bytes while it was being read", path, max)
	}
	return b, nil
}

// parseSSHAuthzFleets reads one fleet per line. Blank lines and # comments are skipped, a
// leading byte-order mark and CRLF line ends are tolerated, and a file that names no fleet at
// all is an error: an empty set would admit nobody without saying why.
func parseSSHAuthzFleets(path string, b []byte) ([]string, error) {
	text := strings.TrimPrefix(string(b), "\ufeff")
	var out []string
	for i, line := range strings.Split(text, "\n") {
		if i >= sshAuthzFleetsMaxLines {
			return nil, fmt.Errorf("%s has more than %d lines", path, sshAuthzFleetsMaxLines)
		}
		if c := strings.IndexByte(line, '#'); c >= 0 {
			line = line[:c]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, _, err := whale.NormalizeFleet(line); err != nil {
			return nil, fmt.Errorf("%s line %d: %v", path, i+1, err)
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s names no fleet", path)
	}
	return out, nil
}

func newWhaleSSHAuthzCheckCmd() *cobra.Command {
	var f sshAuthzFlags
	var from string
	cmd := &cobra.Command{
		Use:   "check <user> <key-type> <base64-key> <%C...>",
		Short: "sshd's AuthorizedKeysCommand: print the key line to admit, or nothing",
		Long: "Run by sshd as `whisper whale ssh-authz check --fleet-file <file> -- %u %t %k %C`\n" +
			"(or with --fleet, repeatable, naming the fleets inline).\n" +
			"Prints exactly one authorized_keys line when the key belongs to an active agent of\n" +
			"the fleet that the connection really came from, and nothing otherwise. A denial\n" +
			"exits 0 with no output, so sshd simply moves on; the reason goes to the auth log.\n\n" +
			"--from <address> asks the same question about a caller you name, as a dry run: the\n" +
			"verdict is printed to stderr and no key line is ever printed.",
		Args: cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, err := f.policy()
			if err != nil {
				sshAuthzLog(false, "refused: "+err.Error())
				return usageErr("%v. Write the fleet into the snippet: `whisper whale ssh-authz install` prints it", err)
			}
			req := whale.AuthzRequest{User: args[0], KeyType: args[1], Key: args[2]}
			// %u is chosen by whoever connects, and it is the first argument, so without a
			// -- in front of it a login named --fleet=... would be read as a flag and move the
			// trust root. The -- is therefore required, not advised, and a login name that
			// still looks like a flag is refused outright.
			if cmd.ArgsLenAtDash() != 0 {
				sshAuthzLog(false, sshAuthzLogLine(whale.AuthzRequest{}, whale.AuthzDecision{Reason: "refused: put -- before " +
					"%u %t %k %C in the AuthorizedKeysCommand, so nothing sshd substitutes can be read as a flag " +
					"(`whisper whale ssh-authz install` prints the line)"}, ""))
				return usageErr("put -- before the user, key type, key and connection: " +
					"`whisper whale ssh-authz check --fleet <fleet> -- %%u %%t %%k %%C`")
			}
			if strings.HasPrefix(req.User, "-") {
				sshAuthzLog(false, sshAuthzLogLine(req, whale.AuthzDecision{Reason: "a login name that starts with - is refused"}, ""))
				return nil
			}
			// The ACL half is read before anything else is asked, so a file the operator turned on
			// and that cannot be read refuses the login rather than being read around.
			acl, aclPresent, aclErr := loadSSHAuthzACL(sshAuthzACLPathFor(f.aclFile, f.fleetFile))
			dry := strings.TrimSpace(from) != ""
			via := ""
			if dry {
				a, perr := netip.ParseAddr(strings.Trim(strings.TrimSpace(from), "[]"))
				if perr != nil {
					return usageErr("--from %q is not an address", from)
				}
				req.Source, via = a, "dry-run"
			} else {
				req.Source, via, err = sshAuthzSource(args[3:])
				if err != nil {
					d := whale.AuthzDecision{Reason: err.Error()}
					sshAuthzLog(false, sshAuthzLogLine(req, d, via))
					return nil
				}
			}
			var d whale.AuthzDecision
			switch {
			case aclErr != nil:
				d = whale.AuthzDecision{Reason: "acl: " + aclErr.Error()}
			case aclPresent && acl.Governed && !acl.ListsAddr(req.Source):
				// No ssh rule names the caller at all: refused before this host walks any chain for it.
				d = whale.AuthzDecision{Reason: "acl: no ssh rule admits " + req.Source.String() + " as " + logToken(req.User)}
			default:
				cx, cancel := context.WithTimeout(context.Background(), sshAuthzBudget)
				defer cancel()
				d = sshAuthzACLDecide(acl, aclPresent, whale.Authorize(cx, sshAuthzLookup(f.resolver), pol, req), req)
			}
			if dry {
				verdict := "DENY"
				if d.Admit {
					verdict = "ADMIT"
				}
				fmt.Fprintf(os.Stderr, "%s %s\n", verdict, sshAuthzLogLine(req, d, via))
				return nil
			}
			sshAuthzLog(d.Admit, sshAuthzLogLine(req, d, via))
			if d.Admit {
				fmt.Fprintln(os.Stdout, d.Line)
			}
			return nil
		},
	}
	f.bind(cmd)
	cmd.Flags().StringVar(&from, "from", "", "dry run: decide for this caller address and print the verdict, never a key line")
	// Flags end at the first argument: with the required --, nothing after it is a flag.
	cmd.Flags().SetInterspersed(false)
	return cmd
}

// sshAuthzLogLine is the one line every decision leaves behind.
func sshAuthzLogLine(req whale.AuthzRequest, d whale.AuthzDecision, via string) string {
	parts := []string{"user=" + logToken(req.User)}
	if req.Source.IsValid() {
		parts = append(parts, "from="+req.Source.String())
	}
	if via != "" {
		parts = append(parts, "source="+logToken(via))
	}
	if d.Name != "" {
		parts = append(parts, "agent="+d.Name)
	}
	if d.Fingerprint != "" {
		parts = append(parts, "key="+d.Fingerprint)
	}
	if d.Via != "" {
		parts = append(parts, "proof="+d.Via)
	}
	return scrubLogLine(strings.Join(parts, " ") + ": " + d.Reason)
}

// scrubLogLine keeps a log line one line of printable text, whatever bytes a key or a name
// carried into the reason.
func scrubLogLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}

// logToken keeps a value sshd passed through on one line and short, because %u is chosen by
// whoever is connecting.
func logToken(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == ' ' {
			return '_'
		}
		return r
	}, s)
	if len(s) > 64 {
		s = s[:64] + "..."
	}
	if s == "" {
		return "-"
	}
	return s
}

// sshAuthzSource recovers the caller's address from what sshd passed as %C, and says how.
//
// An accepted connection (`whisper connect --accept`) reaches sshd from loopback, and the
// holder's record gives back the /128 it really came from. Anything else that reached sshd
// from loopback came from this host, which is not a fleet member, so it is refused. Otherwise
// the caller is the half of %C that is not one of this host's own addresses: sshd_config(5)
// documents %C client first and OpenSSH 9.9 was measured expanding it server first, so the
// order is never assumed.
func sshAuthzSource(conn []string) (netip.Addr, string, error) {
	if len(conn) == 0 {
		return netip.Addr{}, "", errors.New("sshd passed no connection (%C), so the caller is unknown: " +
			"the snippet must end with %u %t %k %C")
	}
	q, err := parseCallerQuery(conn)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("the connection %q does not parse: %v", strings.Join(conn, " "), err)
	}
	if rec, ok := lookupAcceptCaller(q); ok {
		a, perr := netip.ParseAddr(rec.Caller)
		if perr != nil {
			return netip.Addr{}, "accept", fmt.Errorf("the accept record names %q, which is not an address", rec.Caller)
		}
		return a.Unmap(), "accept", nil
	}
	cands := []netip.Addr{q.client.Addr().Unmap()}
	if q.either {
		cands = append(cands, q.server.Addr().Unmap())
	}
	var remote []netip.Addr
	for _, a := range cands {
		// A connection with a loopback end was made on this host. Through an accept the
		// record above answers for it; with no record it is a local user, whatever address
		// that user bound the other end to, so it is refused rather than half-read.
		if a.IsLoopback() || a.IsUnspecified() {
			return netip.Addr{}, "sshd", errors.New("the connection came from this host itself and not through an " +
				"accepted port, so it is not a fleet member")
		}
		if !sshAuthzIsLocal(a) {
			remote = append(remote, a)
		}
	}
	switch {
	case len(remote) == 1:
		return remote[0], "sshd", nil
	case len(remote) == 0:
		return netip.Addr{}, "sshd", errors.New("the connection came from this host itself and not through an " +
			"accepted port, so it is not a fleet member")
	default:
		if remote[0] == remote[1] {
			return remote[0], "sshd", nil
		}
		return netip.Addr{}, "sshd", fmt.Errorf("neither %s nor %s is an address of this host, so which end is the "+
			"caller cannot be told; refusing rather than guessing", remote[0], remote[1])
	}
}

// isLocalAddr reports whether this host holds a: on an interface, or through a local route
// (AnyIP), which the interface list does not show but a bind to port 0 does.
func isLocalAddr(a netip.Addr) bool {
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, ia := range addrs {
			if p, perr := netip.ParsePrefix(ia.String()); perr == nil && p.Addr().Unmap().WithZone("") == a {
				return true
			}
		}
	}
	l, err := net.Listen("tcp", netip.AddrPortFrom(a, 0).String())
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// --- install ------------------------------------------------------------------------

func newWhaleSSHAuthzInstallCmd() *cobra.Command {
	var f sshAuthzFlags
	var write bool
	var path, cmdUser string
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Print the sshd_config snippet that wires ssh-authz in, or write it with --write",
		Long: "Prints the two sshd_config lines that make sshd ask `ssh-authz check` about a key\n" +
			"it does not already know. With --write (as root) it writes them to\n" +
			sshAuthzSnippetPath + ", checks the result with `sshd -t`, and takes\n" +
			"the file back out if sshd rejects it. It never reloads sshd; it prints the one\n" +
			"command that does.\n\n" +
			"Which agents may log in: every agent of your account. Each hosted agent has its own\n" +
			"tenant (the t... label in its name), so install reads your roster with this host's\n" +
			"key, the same list `whisper whale status` shows, and writes the tenants to\n" +
			sshAuthzFleetsPath + " (root-owned, readable only by root and the account\n" +
			"sshd runs the check as). Run `install --write` again after you add an agent: it\n" +
			"rewrites that list, and sshd picks it up at the next login with no reload. Each\n" +
			"login is still proven from DNSSEC, so a revoked agent is refused at once.\n\n" +
			"--fleet names the fleets yourself instead (repeatable; a tenant, a zone, or a node\n" +
			"name), written into the command line; --allow narrows any of this to named agents.\n" +
			"With no key and no --fleet, only this node's own tenant is admitted, and install\n" +
			"says so.\n\n" +
			"sshd only runs a command that root owns and nobody else can write, along its\n" +
			"whole path, so install refuses a binary that would be ignored and says where to put it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The snippet names the path as invoked (a stable /usr/local/bin link survives an
			// upgrade that moves its target); sshd checks the resolved file, and so does this.
			bin, err := sshAuthzExecutable()
			if err != nil || bin == "" {
				return fmt.Errorf("cannot find this binary's own path to write into the snippet: %v", err)
			}
			real := bin
			if r, rerr := filepath.EvalSymlinks(bin); rerr == nil {
				real = r
			}
			fleetsPath := strings.TrimSpace(f.fleetFile)
			if fleetsPath == "" {
				fleetsPath = sshAuthzFleetsPath
			}
			plan, err := planSSHAuthzFleets(&f, fleetsPath)
			if err != nil {
				return err
			}
			// The node's WhaleACL ssh view, beside the fleets file check will read.
			if p := strings.TrimSpace(f.aclFile); p != "" && (!snippetValue(p) || !filepath.IsAbs(p)) {
				return usageErr("--acl-file %q cannot go into sshd_config as it is: name an absolute path "+
					"of letters, digits and . _ - : @ + / only", p)
			}
			aclPlan, err := planSSHAuthzACL(sshAuthzACLPathFor(f.aclFile, plan.file))
			if err != nil {
				return err
			}
			pol, err := f.policyWithout(plan.file)
			if err != nil {
				return usageErr("%v", err)
			}
			if err := checkSnippetValues(bin, f, cmdUser, plan.file); err != nil {
				return usageErr("%v", err)
			}
			snippet := sshAuthzSnippet(bin, pol, f, cmdUser)
			for _, n := range plan.notes {
				whaleNote("%s", n)
			}
			for _, n := range aclPlan.notes {
				whaleNote("%s", n)
			}
			if !write {
				fmt.Fprint(os.Stdout, snippet)
				if plan.file != "" {
					fmt.Fprintf(os.Stdout, "# %s (root-owned, mode 0640, group of %s):\n", plan.file, orNobody(cmdUser))
					for _, l := range strings.Split(strings.TrimRight(plan.content, "\n"), "\n") {
						fmt.Fprintf(os.Stdout, "#   %s\n", l)
					}
				}
				if aclPlan.write {
					fmt.Fprintf(os.Stdout, "# %s (root-owned, mode 0640, group of %s):\n", aclPlan.path, orNobody(cmdUser))
					for _, l := range strings.Split(strings.TrimRight(aclPlan.content, "\n"), "\n") {
						fmt.Fprintf(os.Stdout, "#   %s\n", l)
					}
				}
				if why := commandPathUnsafe(real); why != "" {
					whaleNote("sshd will ignore this command as it stands: %s", why)
					for _, line := range strings.Split(sshAuthzPlacementHint(real, hostPlacementProbe()), "\n") {
						whaleNote("%s", line)
					}
				}
				whaleNote("write it with: sudo whisper whale ssh-authz install --write")
				return nil
			}
			if sshAuthzEUID() != 0 {
				// A plain error, not a 403: the renderer reads 401/403 as a rejected API key, and
				// this has nothing to do with a key.
				return fmt.Errorf("writing sshd's configuration needs root: --write puts the snippet in %s, which only "+
					"root may change. Run it with sudo, or drop --write to print the snippet and place it yourself", path)
			}
			if why := commandPathUnsafe(real); why != "" {
				return &client.ProblemError{Status: 409, Title: "sshd would ignore this command",
					Detail: why + ". " + sshAuthzPlacementHint(real, hostPlacementProbe())}
			}
			// (M1): the ACL file goes first. A crash before the fleets file follows leaves the new
			// view intersected with the old fleets: never wider than the new view, which is the direction
			// the operator asked for, and the next install --write completes it.
			restoreACL := func() {}
			if aclPlan.write {
				restoreACL, err = writeSSHAuthzRootFile(aclPlan.path, aclPlan.content, orNobody(cmdUser), "ssh ACL file",
					"it lists which of your agents may log in here", "--acl-file", func(p string) error {
						_, _, e := loadSSHAuthzACL(p)
						return e
					})
				if err != nil {
					return err
				}
				fmt.Fprintf(os.Stdout, "wrote %s\n", aclPlan.path)
			}
			restore := func() {}
			if plan.file != "" {
				restore, err = writeSSHAuthzFleets(plan.file, plan.content, orNobody(cmdUser))
				if err != nil {
					restoreACL()
					return err
				}
				fmt.Fprintf(os.Stdout, "wrote %s: %d fleet(s) from your roster\n", plan.file, plan.count)
			}
			if err := writeSSHAuthzSnippet(os.Stdout, path, snippet, sshAuthzCommandLine(bin, pol, f), orNobody(cmdUser)); err != nil {
				restore()
				restoreACL()
				return err
			}
			return nil
		},
	}
	f.bind(cmd)
	cmd.Flags().BoolVar(&write, "write", false, "write the snippet into sshd's configuration (needs root)")
	cmd.Flags().StringVar(&path, "path", sshAuthzSnippetPath, "where --write puts the snippet")
	cmd.Flags().StringVar(&cmdUser, "command-user", "nobody", "the unprivileged account sshd runs the check as (AuthorizedKeysCommandUser)")
	return cmd
}

// sshAuthzFleetPlan is what install decided the fleet set is, and where it goes.
type sshAuthzFleetPlan struct {
	file    string // the fleets file to write and name with --fleet-file; "" when the fleets go inline
	content string // that file's bytes
	count   int
	notes   []string
}

// planSSHAuthzFleets decides the fleet set. --fleet named by hand goes inline, as written.
// Otherwise the owner's roster, read with this host's key, gives every hosted tenant the
// account holds, written to the fleets file. Only a hosted tenant zone is ever taken from the
// roster: a name in a domain of the account's own would make that domain's whole zone a
// fleet, and that is a decision for the operator to write with --fleet, never one to infer.
//
// When the roster cannot be read, a refresh (a fleets file is already there) refuses and keeps
// the file, so a control-plane hiccup never narrows a working fleet to one node. A first
// install falls back to this node's own tenant, inline, and says that is all it admits.
func planSSHAuthzFleets(f *sshAuthzFlags, fleetsPath string) (sshAuthzFleetPlan, error) {
	if !snippetValue(fleetsPath) || !(strings.HasPrefix(fleetsPath, "/") || filepath.IsAbs(fleetsPath)) {
		return sshAuthzFleetPlan{}, usageErr("--fleet-file %q cannot go into sshd_config as it is: name an absolute path "+
			"of letters, digits and . _ - : @ + / only", fleetsPath)
	}
	if len(nonBlank(f.fleet)) > 0 {
		return sshAuthzFleetPlan{}, nil
	}
	cx, cancel := ctx()
	defer cancel()
	peers, rerr := sshAuthzRoster(cx)
	zones := sshAuthzRosterZones(peers)
	if rerr == nil && len(zones) > 0 {
		content := sshAuthzFleetsContent(zones)
		if _, err := parseSSHAuthzFleets(fleetsPath, []byte(content)); err != nil {
			return sshAuthzFleetPlan{}, fmt.Errorf("the fleet set read from your roster does not parse: %v", err)
		}
		return sshAuthzFleetPlan{file: fleetsPath, content: content, count: len(zones),
			notes: []string{fmt.Sprintf("your roster holds %d agent tenant(s); %s", len(zones), sshAuthzScope(f, "among them"))}}, nil
	}
	why := "it lists no hosted agent"
	if rerr != nil {
		why = friendly(rerr)
	}
	if _, err := os.Lstat(fleetsPath); err == nil {
		return sshAuthzFleetPlan{}, &client.ProblemError{Status: 503, Type: localActionable, Title: "cannot refresh the fleet set",
			Detail: "your roster could not be read (" + why + "), so " + fleetsPath + " was left as it is rather than " +
				"narrowed. Run this again when `whisper whale status` lists your fleet, or name the fleets with --fleet"}
	}
	fleet, err := sshAuthzSelfFleet()
	if err != nil {
		return sshAuthzFleetPlan{}, &client.ProblemError{Status: 400, Title: "cannot tell which fleet this node is in", Detail: "your roster " +
			"could not be read (" + why + ") and " + err.Error() + ". Name it: `whisper whale ssh-authz install --fleet <tenant>` " +
			"(the t... label in your node's name, which `whisper whale status` shows)"}
	}
	// The fleets path named the file a roster would have filled; with no roster there is
	// nothing to put in it, so the command line names only the node's own tenant.
	f.fleet, f.fleetFile = []string{fleet}, ""
	return sshAuthzFleetPlan{notes: []string{"your roster could not be read (" + why + "), so only this node's own tenant, " +
		strings.TrimSuffix(fleet, ".") + ", is admitted: " + sshAuthzScope(f, "in it") +
		"; with a key on this host, run install again to admit the rest of your agents"}}, nil
}

// sshAuthzScope says who the snippet really admits, in the words of the flags it carries: every
// active agent of the fleets, or only the --allow list, and as any account but root, or only the
// --user accounts. where places the agents ("among them", "in it").
func sshAuthzScope(f *sshAuthzFlags, where string) string {
	s := "every active agent " + where + " may log in"
	if allow := nonBlank(f.allow); len(allow) > 0 {
		s = "only the allowlisted agent(s) " + where + " (" + strings.Join(allow, ", ") + ") may log in, and only while active"
	}
	if users := nonBlank(f.users); len(users) > 0 {
		return s + ", as the local account(s) " + strings.Join(users, ", ") + " and no other"
	}
	return s + ", as any local account except root (uid 0)"
}

// sshAuthzRosterZones is the sorted, de-duplicated set of hosted tenant zones the roster's
// agents sit in. An agent whose state says it is no longer live is left out; one that says
// nothing is kept, because every login still proves status=active from its own record.
func sshAuthzRosterZones(peers []whalePeer) []string {
	seen := map[string]bool{}
	var zones []string
	for _, p := range peers {
		if st := strings.ToLower(strings.TrimSpace(p.State)); st != "" && st != "active" {
			continue
		}
		parent := agentDomain(p.FQDN)
		if _, ok := whale.HostedTenantZone(parent); !ok {
			continue
		}
		z := strings.TrimSuffix(dns.CanonicalName(dns.Fqdn(parent)), ".")
		if !seen[z] {
			seen[z] = true
			zones = append(zones, z)
		}
	}
	sort.Strings(zones)
	return zones
}

// sshAuthzFleetsContent is the fleets file. It carries no time stamp, so the same roster
// writes the same bytes and a refresh that changed nothing changes nothing.
func sshAuthzFleetsContent(zones []string) string {
	var b strings.Builder
	b.WriteString("# Written by `whisper whale ssh-authz install` from your roster: the tenants your agents\n")
	b.WriteString("# sit in. An agent here logs in only while DNSSEC proves it active and the key its own.\n")
	b.WriteString("# Refresh after adding an agent: sudo whisper whale ssh-authz install --write\n")
	for _, z := range zones {
		b.WriteString(z + "\n")
	}
	return b.String()
}

// writeSSHAuthzFleets puts the fleets file in place atomically: written, owned by root and the
// check's group, mode 0640 and synced before the rename, so sshd never reads a half-written or
// wrongly owned file. It then reads the file back through check's own reader, so install never
// leaves a file check would refuse. It returns how to put back what was there before.
func writeSSHAuthzFleets(path, content, cmdUser string) (func(), error) {
	return writeSSHAuthzRootFile(path, content, cmdUser, "fleets file", "it links your agents' tenants",
		"--fleet-file, such as "+sshAuthzFleetsPath, func(p string) error {
			_, err := readSSHAuthzFleets(p)
			return err
		})
}

// writeSSHAuthzRootFile is the one atomic writer behind every file check consults: written,
// owned by root and the check's group, mode 0640 and synced before the rename, then read back
// through check's own reader (verify), and put back as it was when that read refuses it. what
// names the file, why says why it must not be world-readable, and where names the flag that
// moves it.
func writeSSHAuthzRootFile(path, content, cmdUser, what, why, where string, verify func(string) error) (func(), error) {
	gid, err := sshAuthzGroupOf(cmdUser)
	if err != nil {
		return nil, fmt.Errorf("cannot find the group of %q, the account sshd runs the check as, so %s cannot be made "+
			"readable to it without making it readable to everyone (%s): %v. Name the account "+
			"with --command-user", cmdUser, path, why, err)
	}
	prev, prevErr := os.ReadFile(path)
	dir := filepath.Dir(path)
	if why := sshAuthzPathUnsafe(dir); why != "" {
		return nil, &client.ProblemError{Status: 409, Title: "check would not trust the " + what + " there",
			Detail: why + ". Name a root-owned place with " + where}
	}
	put := func(b []byte) error {
		tmp, err := os.CreateTemp(dir, ".whisper-ssh-authz-*.tmp")
		if err != nil {
			return err
		}
		name := tmp.Name()
		defer os.Remove(name) // a no-op after the rename
		fail := func(err error) error { _ = tmp.Close(); return err }
		if _, err := tmp.Write(b); err != nil {
			return fail(err)
		}
		if err := sshAuthzFchown(tmp, 0, gid); err != nil {
			return fail(err)
		}
		if err := tmp.Chmod(0o640); err != nil {
			return fail(err)
		}
		if err := tmp.Sync(); err != nil {
			return fail(err)
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := os.Rename(name, path); err != nil {
			return err
		}
		if d, err := os.Open(dir); err == nil {
			_ = d.Sync()
			_ = d.Close()
		}
		return nil
	}
	restore := func() {
		if prevErr == nil {
			_ = put(prev)
		} else {
			_ = os.Remove(path)
		}
	}
	if err := put([]byte(content)); err != nil {
		return nil, fmt.Errorf("cannot write %s: %w", path, err)
	}
	if err := verify(path); err != nil {
		restore()
		return nil, &client.ProblemError{Status: 409, Title: "check would refuse the " + what + ", so nothing was changed",
			Detail: err.Error()}
	}
	return restore, nil
}

// sshAuthzCommandLine is the AuthorizedKeysCommand. Only what the operator chose is written,
// so the command line in the file is the policy, readable at a glance.
func sshAuthzCommandLine(bin string, pol whale.AuthzPolicy, f sshAuthzFlags) string {
	args := []string{bin, "whale", "ssh-authz", "check"}
	if p := strings.TrimSpace(f.fleetFile); p != "" {
		args = append(args, "--fleet-file", p)
	}
	if p := strings.TrimSpace(f.aclFile); p != "" {
		args = append(args, "--acl-file", p)
	}
	for _, fl := range pol.Fleets {
		args = append(args, "--fleet", strings.TrimSuffix(fl.Zone, "."))
	}
	for _, a := range pol.Allow {
		args = append(args, "--allow", a)
	}
	for _, u := range pol.Users {
		args = append(args, "--user", u)
	}
	if r := strings.TrimSpace(f.resolver); r != "" {
		args = append(args, "--resolver", r)
	}
	if f.tlsa {
		args = append(args, "--allow-tlsa")
	}
	// -- ends the flags before anything sshd substitutes; check refuses a line without it.
	return strings.Join(append(args, "--", "%u", "%t", "%k", "%C"), " ")
}

func orNobody(u string) string {
	if strings.TrimSpace(u) == "" {
		return "nobody"
	}
	return strings.TrimSpace(u)
}

// snippetValue is what may go into the drop-in unquoted: sshd splits on whitespace and
// expands %-tokens, so `--user %u` would admit every account and a newline would add lines.
func snippetValue(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("._-:@+/[]", r):
		default:
			return false
		}
	}
	return true
}

func checkSnippetValues(bin string, f sshAuthzFlags, cmdUser, fleetsFile string) error {
	check := func(what, v string) error {
		if !snippetValue(v) {
			return fmt.Errorf("%s %q cannot go into sshd_config as it is: use letters, digits and . _ - : @ + / only "+
				"(no spaces, quotes or %%)", what, v)
		}
		return nil
	}
	if err := check("the binary path", bin); err != nil {
		return err
	}
	for _, fl := range nonBlank(f.fleet) {
		if err := check("--fleet", fl); err != nil {
			return err
		}
	}
	if p := strings.TrimSpace(fleetsFile); p != "" {
		if err := check("--fleet-file", p); err != nil {
			return err
		}
	} else if p := strings.TrimSpace(f.fleetFile); p != "" {
		if err := check("--fleet-file", p); err != nil {
			return err
		}
	}
	for _, a := range nonBlank(f.allow) {
		if err := check("--allow", a); err != nil {
			return err
		}
	}
	for _, u := range nonBlank(f.users) {
		if err := check("--user", u); err != nil {
			return err
		}
	}
	if r := strings.TrimSpace(f.resolver); r != "" {
		if err := check("--resolver", r); err != nil {
			return err
		}
	}
	return check("--command-user", orNobody(cmdUser))
}

// sshAuthzSnippet renders the drop-in around the command line.
func sshAuthzSnippet(bin string, pol whale.AuthzPolicy, f sshAuthzFlags, cmdUser string) string {
	cmdUser = orNobody(cmdUser)
	return "# Written by `whisper whale ssh-authz install`. Lets the active agents of your Whisper fleet\n" +
		"# log in with their own identity key, proven from the IANA DNSSEC root. sshd still reads\n" +
		"# authorized_keys first. Remove this file and reload sshd to turn it off.\n" +
		"AuthorizedKeysCommand " + sshAuthzCommandLine(bin, pol, f) + "\n" +
		"AuthorizedKeysCommandUser " + cmdUser + "\n"
}

// writeSSHAuthzSnippet writes the drop-in, proves sshd accepts the whole configuration with it
// AND runs with its two lines (sshd takes the first value it reads, so an earlier drop-in or
// a line above the Include would silently win), and takes it back out when either fails.
func writeSSHAuthzSnippet(w io.Writer, path, snippet, command, cmdUser string) error {
	dir := filepath.Dir(path)
	main := filepath.Join(filepath.Dir(dir), "sshd_config")
	if b, err := os.ReadFile(main); err == nil && !includesDropIns(string(b), dir) {
		return &client.ProblemError{Status: 409, Title: "sshd does not read " + dir,
			Detail: main + " has no `Include " + dir + "/*.conf` line, so a file there would be ignored. Add that line " +
				"near the top of " + main + " (sshd takes the first value it reads), or paste the snippet " +
				"`whisper whale ssh-authz install` prints into it yourself."}
	}
	prev, prevErr := os.ReadFile(path)
	prevMode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		prevMode = fi.Mode().Perm()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("cannot create %s: %w", dir, err)
	}
	if err := writeFileAtomic(path, []byte(snippet), 0o644); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	rollback := func() {
		if prevErr == nil { // put back what was there before, byte for byte and mode for mode
			_ = writeFileAtomic(path, prev, prevMode)
		} else {
			_ = os.Remove(path)
		}
	}
	effective, err := sshAuthzSshdTest(main)
	if err != nil {
		rollback()
		return &client.ProblemError{Status: 422, Title: "sshd rejected the configuration, so nothing was changed",
			Detail: "sshd rejected the configuration with the snippet in it, so the snippet was taken back out " +
				"and nothing was changed: " + err.Error()}
	}
	if why := effectiveMismatch(effective, command, cmdUser); why != "" {
		rollback()
		return &client.ProblemError{Status: 409, Title: "sshd would not use the snippet, so nothing was changed",
			Detail: why + ". sshd takes the first value it reads: remove the earlier AuthorizedKeysCommand, or " +
				"give this file a name that sorts before it, and run this again. The snippet was taken back out."}
	}
	fmt.Fprintf(w, "wrote %s; sshd -t accepts it and sshd -T runs with it\n", path)
	fmt.Fprintf(w, "  reload sshd to start using it: %s\n", sshReloadCommand())
	fmt.Fprintf(w, "  try it from a fleet node:      whisper whale ssh {user}@{this-node}\n")
	return nil
}

// effectiveMismatch compares sshd -T's view with the two lines we wrote. sshd prints keywords
// in lower case and the command with its arguments as written.
func effectiveMismatch(effective, command, cmdUser string) string {
	got := map[string]string{}
	for _, line := range strings.Split(effective, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok {
			got[strings.ToLower(k)] = strings.TrimSpace(v)
		}
	}
	if c := got["authorizedkeyscommand"]; c != command {
		return fmt.Sprintf("sshd -T runs AuthorizedKeysCommand %q, not this one", orVal(c, "none"))
	}
	if u := got["authorizedkeyscommanduser"]; u != cmdUser {
		return fmt.Sprintf("sshd -T runs it as %q, not %q", orVal(u, "nobody set"), cmdUser)
	}
	return ""
}

// includesDropIns reports whether sshd_config pulls in dir. Liberal: any Include naming the
// directory counts, with or without a glob.
func includesDropIns(cfg, dir string) bool {
	for _, line := range strings.Split(cfg, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !strings.EqualFold(f[0], "Include") {
			continue
		}
		for _, p := range f[1:] {
			if strings.HasPrefix(p, dir+"/") || p == dir || strings.HasPrefix(p, filepath.Base(dir)+"/") {
				return true
			}
		}
	}
	return false
}

func sshReloadCommand() string {
	if runtime.GOOS == "darwin" {
		return "sudo launchctl kickstart -k system/com.openssh.sshd"
	}
	return "sudo systemctl reload ssh || sudo systemctl reload sshd"
}

// commandPathUnsafe says why sshd would refuse to run bin: its AuthorizedKeysCommand and
// every directory above it must be owned by root and writable by nobody else. "" when it is
// fine, or when the platform does not say who owns a file.
func commandPathUnsafe(bin string) string {
	_, why := commandPathRefusal(bin)
	return why
}

// commandPathRefusal is commandPathUnsafe with the element that failed: the first one along
// the path, from bin up, that sshd's safe_path would refuse. ("", "") when none does.
func commandPathRefusal(bin string) (at, why string) {
	for p := bin; ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			return p, fmt.Sprintf("cannot read %s (%v)", p, err)
		}
		uid, ok := fileOwnerUID(fi)
		if ok && uid != 0 {
			return p, fmt.Sprintf("%s is not owned by root", p)
		}
		// sshd's own check (safe_path) makes no exception for a sticky directory such as /tmp.
		if fi.Mode().Perm()&0o022 != 0 {
			return p, fmt.Sprintf("%s can be written by accounts other than its owner", p)
		}
		if parent := filepath.Dir(p); parent == p {
			return "", ""
		}
	}
}

// sshAuthzOwnFleet finds this node's fleet from its own validated name.
func sshAuthzOwnFleet() (string, error) {
	cx, cancel := ctx()
	defer cancel()
	self := whaleSelfAddress(cx, "")
	if self == "" {
		if b, ok := client.ReadBoundFile(""); ok {
			self = b.Addr.String()
		}
	}
	a, err := netip.ParseAddr(self)
	if err != nil {
		return "", errors.New("this host has no Whisper address it can name")
	}
	val := trustverify.NewValidator(trustverify.NewNetResolver(""), trustverify.IANARootAnchors(), time.Now())
	name, note := validatedPTR(cx, val, a)
	if name == "" {
		return "", fmt.Errorf("the name of %s could not be proven (%s)", a, note)
	}
	parent := parentOfFqdn(name)
	if parent == "" {
		return "", fmt.Errorf("%s has no parent zone to call a fleet", name)
	}
	return parent, nil
}
