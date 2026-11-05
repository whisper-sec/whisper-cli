// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// sshacl.go is the node's copy of its WhaleACL ssh view: which fleet agents may log in here,
// and as which local accounts. The control plane compiles the fleet's one document per node;
// `whale ssh-authz install --write` writes this node's view into a root-owned file; `check`
// reads it at every login. The login itself stays a local decision proven from DNSSEC, with
// no control-plane call on the way.
//
// The file only ever narrows. A login must pass the flags half (the fleet, --allow, --user,
// and the DNSSEC proof) AND, when the file says the node is governed, this half: the caller's
// /128 and the name its validated PTR proved must be listed together, with the account.

// SSHACLHeader is the first line every view file starts with. A file without it was not
// written by this code, and is refused rather than guessed at.
const SSHACLHeader = "whisper-ssh-acl 1"

// SSHACLNonroot admits every local account except root (and any uid-0 alias).
const SSHACLNonroot = "autogroup:nonroot"

// SSHACLMaxEntries bounds the admit lines, as the control plane bounds the view it sends.
const SSHACLMaxEntries = 4096

var loginName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var hashValue = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// SSHACLEntry is one source this node admits.
type SSHACLEntry struct {
	// Names are the names the control plane minted for the source's /128, lower case and
	// without the trailing dot. The PTR-proven name must be one of them, so an address that
	// another agent holds now does not inherit this line.
	Names []string
	Addr  netip.Addr
	Users []string
}

// SSHACL is the parsed file.
type SSHACL struct {
	Node         netip.Addr
	Governed     bool
	ACLHash      string
	ArtifactHash string
	Entries      []SSHACLEntry
}

// Format writes the view in the file's one canonical form: the same view writes the same
// bytes, so a refresh that changed nothing changes nothing.
func (a SSHACL) Format() string {
	var b strings.Builder
	b.WriteString("# Written by `whisper whale ssh-authz install` from your fleet's WhaleACL ssh block, compiled\n")
	b.WriteString("# for this node. A login is admitted only when it passes ssh-authz's own checks AND, when\n")
	b.WriteString("# governed, an admit line names the caller's address, its proven name and the account.\n")
	b.WriteString("# Refresh after editing the ACL: sudo whisper whale ssh-authz install --write\n")
	b.WriteString(SSHACLHeader + "\n")
	b.WriteString("node " + a.Node.String() + "\n")
	if a.Governed {
		b.WriteString("governed yes\n")
	} else {
		b.WriteString("governed no\n")
	}
	if a.ACLHash != "" {
		b.WriteString("acl_hash " + a.ACLHash + "\n")
	}
	if a.ArtifactHash != "" {
		b.WriteString("artifact_hash " + a.ArtifactHash + "\n")
	}
	entries := append([]SSHACLEntry(nil), a.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Addr.Less(entries[j].Addr) })
	for _, e := range entries {
		b.WriteString("admit " + strings.Join(e.Names, ",") + " " + e.Addr.String() + " " + strings.Join(e.Users, ",") + "\n")
	}
	return b.String()
}

// ParseSSHACL reads a view file strictly. It tolerates a byte-order mark, CRLF line ends,
// blank lines and # comments, and nothing else: an unknown keyword, a repeated header line, a
// name, address or account that does not parse, or an admit line in a file that says it is
// not governed is an error. The caller turns an error into a denial, because a file the
// operator asked for and that cannot be read is not a file to log anyone in by.
func ParseSSHACL(b []byte) (SSHACL, error) {
	var a SSHACL
	text := strings.TrimPrefix(string(b), "\ufeff")
	sawHeader, sawNode, sawGoverned := false, false, false
	seen := map[netip.Addr]bool{}
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if c := strings.IndexByte(line, '#'); c >= 0 {
			line = strings.TrimSpace(line[:c])
		}
		if line == "" {
			continue
		}
		n := i + 1
		if !sawHeader {
			if line != SSHACLHeader {
				return SSHACL{}, fmt.Errorf("line %d: the file does not start with %q, so it was not written by ssh-authz install", n, SSHACLHeader)
			}
			sawHeader = true
			continue
		}
		f := strings.Fields(line)
		switch f[0] {
		case "node":
			if sawNode || len(f) != 2 {
				return SSHACL{}, fmt.Errorf("line %d: one node line, naming one address", n)
			}
			addr, err := netip.ParseAddr(f[1])
			if err != nil {
				return SSHACL{}, fmt.Errorf("line %d: %q is not an address", n, f[1])
			}
			a.Node, sawNode = addr.Unmap(), true
		case "governed":
			if sawGoverned || len(f) != 2 || (f[1] != "yes" && f[1] != "no") {
				return SSHACL{}, fmt.Errorf("line %d: one governed line, yes or no", n)
			}
			a.Governed, sawGoverned = f[1] == "yes", true
		case "acl_hash", "artifact_hash":
			if len(f) != 2 || !hashValue.MatchString(f[1]) {
				return SSHACL{}, fmt.Errorf("line %d: %s must be sha256 followed by 64 hex digits", n, f[0])
			}
			dst := &a.ACLHash
			if f[0] == "artifact_hash" {
				dst = &a.ArtifactHash
			}
			if *dst != "" {
				return SSHACL{}, fmt.Errorf("line %d: %s appears twice", n, f[0])
			}
			*dst = f[1]
		case "admit":
			e, err := parseAdmit(f)
			if err != nil {
				return SSHACL{}, fmt.Errorf("line %d: %v", n, err)
			}
			if seen[e.Addr] {
				return SSHACL{}, fmt.Errorf("line %d: %s is listed twice", n, e.Addr)
			}
			seen[e.Addr] = true
			if len(a.Entries) >= SSHACLMaxEntries {
				return SSHACL{}, fmt.Errorf("more than %d admit lines", SSHACLMaxEntries)
			}
			a.Entries = append(a.Entries, e)
		default:
			return SSHACL{}, fmt.Errorf("line %d: unknown line %q", n, f[0])
		}
	}
	switch {
	case !sawHeader:
		return SSHACL{}, errors.New("the file is empty")
	case !sawNode:
		return SSHACL{}, errors.New("the file names no node")
	case !sawGoverned:
		return SSHACL{}, errors.New("the file does not say whether the node is governed")
	case !a.Governed && len(a.Entries) > 0:
		return SSHACL{}, errors.New("the file says the node is not governed and still lists admit lines")
	}
	return a, nil
}

func parseAdmit(f []string) (SSHACLEntry, error) {
	if len(f) != 4 {
		return SSHACLEntry{}, errors.New("an admit line is: admit <name[,name]> <address> <user[,user]>")
	}
	var e SSHACLEntry
	for _, n := range strings.Split(f[1], ",") {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if _, ok := dns.IsDomainName(n); !ok || n == "" || !ldhName(n) || !strings.Contains(n, ".") {
			return SSHACLEntry{}, fmt.Errorf("%q is not an agent name", n)
		}
		e.Names = append(e.Names, n)
	}
	addr, err := netip.ParseAddr(f[2])
	if err != nil || addr.Zone() != "" {
		return SSHACLEntry{}, fmt.Errorf("%q is not an address", f[2])
	}
	e.Addr = addr.Unmap()
	for _, u := range strings.Split(f[3], ",") {
		if u != SSHACLNonroot && !loginName.MatchString(u) {
			return SSHACLEntry{}, fmt.Errorf("%q is not a local account (a lower-case login name, or %s)", u, SSHACLNonroot)
		}
		e.Users = append(e.Users, u)
	}
	return e, nil
}

// ValidSSHACLUser reports whether u is an account the view may name.
func ValidSSHACLUser(u string) bool {
	return u == SSHACLNonroot || loginName.MatchString(u)
}

// ListsAddr reports whether any admit line names src. check asks this before it walks a
// DNSSEC chain, so a caller the view does not list costs this host nothing.
func (a SSHACL) ListsAddr(src netip.Addr) bool {
	src = src.Unmap()
	for _, e := range a.Entries {
		if e.Addr == src {
			return true
		}
	}
	return false
}

// Admits is the ACL half of a decision, asked after the flags half proved name from src.
// Not governed admits (the flags half alone decides). Governed admits only when an admit
// line lists src with name among its names and user among its accounts. Every denial says
// so in words an operator can act on.
func (a SSHACL) Admits(name string, src netip.Addr, user string) (bool, string) {
	if !a.Governed {
		return true, "the node is not governed by an ACL ssh block"
	}
	src = src.Unmap()
	want := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	for _, e := range a.Entries {
		if e.Addr != src {
			continue
		}
		if !containsFold(e.Names, want) {
			return false, fmt.Sprintf("the ACL lists %s for %s, not for %s, so the address is now someone else's or the view is stale; refresh it",
				src, strings.Join(e.Names, ", "), orUnknown(want))
		}
		if userAdmitted(user, e.Users) {
			return true, "an ACL ssh rule admits " + want + " as " + user
		}
		return false, fmt.Sprintf("no ssh rule admits %s as %s (it may log in here as %s)", want, user, strings.Join(e.Users, ", "))
	}
	return false, fmt.Sprintf("no ssh rule admits %s as %s", orUnknown(want), user)
}

func userAdmitted(user string, users []string) bool {
	for _, u := range users {
		if u == user {
			return true
		}
		if u == SSHACLNonroot && user != "root" {
			// root by any other name is still root: a uid-0 alias is not "nonroot".
			if isRoot, known := UID0(user); !(known && isRoot) {
				return true
			}
		}
	}
	return false
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
