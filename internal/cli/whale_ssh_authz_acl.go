// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_ssh_authz_acl.go carries the fleet's WhaleACL ssh block to this node, so one
// document governs both east-west traffic and SSH. `install --write` reads this node's
// compiled view from the control plane and writes it beside the fleets file; `check` reads the
// file at every login and intersects it with its own decision. The login never calls the
// control plane: a refresh is the only moment the view moves.
//
// The refresh is conservative in exactly one direction. It writes or replaces the file only
// when the control plane says the view is in force (governed) or that there is nothing to
// govern (no document, or no ssh block). Any other answer, and any failure to get one, keeps
// the file that is there, so a box that is restarting or a network that is down can never
// widen a node that was governed.

// sshAuthzACLName is the file's name; it lives beside the fleets file.
const sshAuthzACLName = "whisper-ssh-authz.acl"

// sshAuthzACLMaxBytes bounds the file. A view holds at most 4096 sources (the server refuses a
// larger one), and a line of two minted names, an address and a handful of accounts is a few
// hundred bytes, so 4 MiB leaves headroom without ever reading without end.
const sshAuthzACLMaxBytes = 4 << 20

// sshAuthzACLDefault is where the file lives when no fleets file or --acl-file says otherwise.
// A variable so the tests can point it somewhere that is certainly empty.
var sshAuthzACLDefault = "/etc/ssh/" + sshAuthzACLName

// Seams for the tests: this host's /128, and the control plane's view of it.
var (
	sshAuthzSelfAddr = func(cx context.Context) (netip.Addr, error) {
		self := whaleSelfAddress(cx, "")
		if self == "" {
			if b, ok := client.ReadBoundFile(""); ok {
				self = b.Addr.String()
			}
		}
		a, err := netip.ParseAddr(strings.Trim(self, "[]"))
		if err != nil {
			return netip.Addr{}, errors.New("this host has no Whisper address it can name")
		}
		return a.Unmap(), nil
	}
	sshAuthzACLView = fetchSSHAuthzACLView
)

// sshAuthzACLPathFor is where check and install find the file: --acl-file when given, else
// beside the fleets file, else the default. Both commands derive it the same way from the
// same flags, so the snippet names --acl-file only when the operator chose one.
func sshAuthzACLPathFor(aclFlag, fleetFile string) string {
	if p := strings.TrimSpace(aclFlag); p != "" {
		return p
	}
	if p := strings.TrimSpace(fleetFile); p != "" {
		return filepath.Join(filepath.Dir(p), sshAuthzACLName)
	}
	return sshAuthzACLDefault
}

// loadSSHAuthzACL reads the file. present is false only when there is no file at all, which
// means flags-only, exactly as before. A file that is there and cannot be trusted or
// parsed is an error, which check turns into a denial: the operator turned this control on.
func loadSSHAuthzACL(path string) (acl whale.SSHACL, present bool, err error) {
	if _, lerr := os.Lstat(path); lerr != nil {
		if errors.Is(lerr, fs.ErrNotExist) {
			return whale.SSHACL{}, false, nil
		}
		return whale.SSHACL{}, true, fmt.Errorf("cannot read %s: %v", path, lerr)
	}
	b, err := readSSHAuthzRootFile(path, sshAuthzACLMaxBytes, "an ssh ACL file")
	if err != nil {
		return whale.SSHACL{}, true, err
	}
	a, err := whale.ParseSSHACL(b)
	if err != nil {
		return whale.SSHACL{}, true, fmt.Errorf("%s: %v", path, err)
	}
	return a, true, nil
}

// sshAuthzView is one node's view as the control plane sent it.
type sshAuthzView struct {
	State        string
	Governed     bool
	Node         string
	ACLHash      string
	ArtifactHash string
	Note         string
	Entries      []whale.SSHACLEntry
	Skipped      int // sources the plane holds no name for; they cannot prove one, so cannot log in
	Declared     int // the header's entries count, -1 when it sent none
}

func fetchSSHAuthzACLView(cx context.Context, node string) (sshAuthzView, error) {
	c, err := resolveClient(false, false)
	if err != nil {
		return sshAuthzView{}, err
	}
	if c == nil || c.Credential().IsZero() {
		return sshAuthzView{}, errors.New("no key in effect on this host")
	}
	env, err := c.Agents(cx, "list", map[string]any{"kind": "whale", "view": "ssh", "node": node})
	if err != nil {
		return sshAuthzView{}, err
	}
	return sshAuthzViewFrom(env)
}

// sshAuthzViewFrom reads the rows: one header with the state, then one row per source. A row
// that does not parse fails the whole view, because a view with a hole in it is not the view
// the plane compiled.
func sshAuthzViewFrom(env *client.Envelope) (sshAuthzView, error) {
	v := sshAuthzView{Declared: -1}
	// Listing is the client's one door for a failed envelope: an older control plane answers this
	// view with ok:false and a 400 naming its vocabulary, inside a 200 reply, and that must reach
	// the caller as the 400 it is (measured on the live plane, 2026-11-05).
	res, err := env.Listing()
	if err != nil {
		return v, err
	}
	header := false
	for _, rec := range res.Records() {
		item, ok := rec["item"].(map[string]any)
		if !ok {
			continue
		}
		if st, ok := item["state"].(string); ok {
			if header {
				return sshAuthzView{}, errors.New("the control plane sent two header rows")
			}
			header = true
			v.State = st
			v.Governed, _ = item["governed"].(bool)
			v.Node = cellString(item["node"])
			v.ACLHash = cellString(item["acl_hash"])
			v.ArtifactHash = cellString(item["artifact_hash"])
			v.Note = cellString(item["note"])
			if n, err := strconv.Atoi(cellString(item["entries"])); err == nil {
				v.Declared = n
			}
			continue
		}
		src := cellString(item["src"])
		addr, err := netip.ParseAddr(src)
		if err != nil {
			return sshAuthzView{}, fmt.Errorf("the control plane sent %q as a source address", src)
		}
		e := whale.SSHACLEntry{Addr: addr.Unmap()}
		for _, n := range stringsOf(item["names"]) {
			n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
			if n != "" {
				e.Names = append(e.Names, n)
			}
		}
		for _, u := range stringsOf(item["users"]) {
			if !whale.ValidSSHACLUser(u) {
				return sshAuthzView{}, fmt.Errorf("the control plane sent %q as a local account", u)
			}
			e.Users = append(e.Users, u)
		}
		if len(e.Users) == 0 {
			return sshAuthzView{}, fmt.Errorf("the control plane sent %s with no account", addr)
		}
		if len(e.Names) == 0 {
			v.Skipped++
			continue
		}
		v.Entries = append(v.Entries, e)
	}
	if !header {
		return sshAuthzView{}, errors.New("the control plane sent no header row, so the view's state is unknown")
	}
	// A list cut short on the way (a proxy, a row cap) would only narrow, but it would do it
	// silently, and the file must be the view the plane compiled, not part of it.
	if v.Declared >= 0 && v.Declared != len(v.Entries)+v.Skipped {
		return sshAuthzView{}, fmt.Errorf("the control plane declared %d source(s) and sent %d", v.Declared, len(v.Entries)+v.Skipped)
	}
	return v, nil
}

func stringsOf(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// sshAuthzACLPlan is what install decided about the ACL file.
type sshAuthzACLPlan struct {
	path    string
	write   bool // false: leave whatever is there (and there is nothing there)
	content string
	notes   []string
}

// planSSHAuthzACL reads this node's view and decides the file. When the answer cannot be
// written as it is (an error, an older control plane, a state other than ok, no_document or
// no_ssh_block) and a file is already there, the refresh refuses and keeps it. With no file
// there, the node stays flags-only, which is what it already was, and install says so.
func planSSHAuthzACL(path string) (sshAuthzACLPlan, error) {
	plan := sshAuthzACLPlan{path: path}
	old, present, oldErr := loadSSHAuthzACL(path)
	keep := func(why string) (sshAuthzACLPlan, error) {
		if present {
			return sshAuthzACLPlan{}, &client.ProblemError{Status: 503, Type: localActionable, Title: "cannot refresh the ssh ACL",
				Detail: why + ", so " + path + " was left as it is rather than replaced, and nothing else was changed. " +
					"Run this again in a moment; a node that was governed stays governed meanwhile"}
		}
		plan.notes = append(plan.notes, why+"; this node stays flags-only (its --fleet, --allow and --user) until a refresh can read its view")
		return plan, nil
	}
	cx, cancel := ctx()
	defer cancel()
	self, err := sshAuthzSelfAddr(cx)
	if err != nil {
		return keep("the WhaleACL ssh view could not be read: " + err.Error())
	}
	v, err := sshAuthzACLView(cx, self.String())
	if err != nil {
		var pe *client.ProblemError
		if errors.As(err, &pe) && pe.Status == 400 && strings.Contains(pe.Detail+" "+pe.Title, "view must be one of") {
			return keep("the control plane does not serve the compiled ssh view yet")
		}
		return keep("the WhaleACL ssh view could not be read (" + friendly(err) + ")")
	}
	if node, perr := netip.ParseAddr(v.Node); perr != nil || node.Unmap() != self {
		return keep("the control plane answered for " + orVal(v.Node, "no node") + ", not for this node, " + self.String())
	}
	next := whale.SSHACL{Node: self, ACLHash: v.ACLHash, ArtifactHash: v.ArtifactHash}
	switch v.State {
	case "ok":
		if !v.Governed {
			return keep("the control plane said ok without saying the node is governed")
		}
		next.Governed, next.Entries = true, v.Entries
	case "no_document", "no_ssh_block":
		next.ACLHash, next.ArtifactHash = hashOrEmpty(v.ACLHash), hashOrEmpty(v.ArtifactHash)
	default:
		return keep("the control plane cannot say what this node's ssh view is right now (" + orVal(v.State, "no state") +
			": " + v.Note + ")")
	}
	content := next.Format()
	if _, err := whale.ParseSSHACL([]byte(content)); err != nil {
		return keep("the view the control plane sent does not make a file check can read (" + err.Error() + ")")
	}
	plan.write, plan.content = true, content
	plan.notes = append(plan.notes, sshAuthzACLTransition(old, present, oldErr, next, v.Skipped)...)
	return plan, nil
}

func hashOrEmpty(h string) string {
	if strings.HasPrefix(h, "sha256:") && len(h) == len("sha256:")+64 {
		return h
	}
	return ""
}

// sshAuthzACLTransition says what the refresh changes, in the order an operator reads it:
// from what, to what, which sources came and went, and a loud line when nobody is left.
func sshAuthzACLTransition(old whale.SSHACL, present bool, oldErr error, next whale.SSHACL, skipped int) []string {
	was := "flags-only"
	switch {
	case present && oldErr != nil:
		was = "an unreadable ACL file, which refused every fleet login"
	case present && old.Governed:
		was = fmt.Sprintf("governed, %d source(s)", len(old.Entries))
	}
	now := "flags-only: the fleet's WhaleACL has no ssh block"
	if next.Governed {
		now = fmt.Sprintf("governed by the WhaleACL, %d source(s) may log in here", len(next.Entries))
	}
	out := []string{"ssh ACL: " + was + " -> " + now}
	if present && oldErr == nil && old.Governed && next.Governed {
		before := map[netip.Addr]whale.SSHACLEntry{}
		for _, e := range old.Entries {
			before[e.Addr] = e
		}
		after := map[netip.Addr]bool{}
		shown := 0
		for _, e := range next.Entries {
			after[e.Addr] = true
			if _, had := before[e.Addr]; !had && shown < 8 {
				out = append(out, fmt.Sprintf("  + %s (%s) as %s", e.Addr, strings.Join(e.Names, ", "), strings.Join(e.Users, ", ")))
				shown++
			}
		}
		for _, e := range old.Entries {
			if !after[e.Addr] && shown < 16 {
				out = append(out, fmt.Sprintf("  - %s (%s)", e.Addr, strings.Join(e.Names, ", ")))
				shown++
			}
		}
	}
	if skipped > 0 {
		out = append(out, fmt.Sprintf("%d source(s) the control plane holds no name for were left out: without a name they cannot prove who they are, so they could not log in anyway", skipped))
	}
	if next.Governed && len(next.Entries) == 0 {
		out = append(out, "WARNING: this node's ssh view admits NOBODY. After this refresh every fleet login here is refused "+
			"(keys in authorized_keys still work). If that is not what you meant, add an ssh rule that names this node as a dst")
	}
	return out
}

// sshAuthzACLDecide is the ACL half of one login, after the flags half has run. A denial from
// either half says which half it was, so an operator reading the auth log knows whether to look
// at the snippet's flags or at the fleet's document.
func sshAuthzACLDecide(acl whale.SSHACL, present bool, d whale.AuthzDecision, req whale.AuthzRequest) whale.AuthzDecision {
	if !d.Admit {
		d.Reason = "flags: " + d.Reason
		return d
	}
	if !present || !acl.Governed {
		return d
	}
	// The flags half reads the login name trimmed; this half reads the very same string.
	ok, why := acl.Admits(d.Name, req.Source, strings.TrimSpace(req.User))
	if !ok {
		d.Admit, d.Line, d.Via = false, "", ""
		d.Reason = "acl: " + why
		return d
	}
	d.Reason += "; " + why
	return d
}
