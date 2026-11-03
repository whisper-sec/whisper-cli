// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/secfile"
)

// project_trust.go records which projects'.whisper/config this user wrote.
//
// `whisper run` reads a project's .whisper/config as a selection (agent_pick.go, rung 3). The
// file lives in the project, so a cloned repository can ship one, naming an agent of whoever
// clones it: `{"agent":"demo","tier":"wireguard"}`. Read as the person's own choice, that bound
// the agent on the routed tier and replaced its WireGuard peer, cutting off the host that held
// it, with a stderr note as the only sign.
//
// So the proof that a config is the person's own lives OUTSIDE the project, in the user's own
// config directory beside the saved agent file: a map from the project root to the agent its
// config named when this user's `whisper init` wrote it, or when they said yes to it at a
// prompt. A config the map does not vouch for still selects its agent, but not as an explicit
// choice: it never replaces another host's peer unless the person confirms, or names the agent
// with --agent (projectGate). Keyed on the agent too, so a pull that changes the config's agent
// is a new question, not an old yes.

// projectTrustLeaf is the trust file's name beside the saved agent file.
const projectTrustLeaf = "projects"

// defaultProjectTrustFile is ~/.config/whisper/projects, beside the saved agent file.
func defaultProjectTrustFile() string {
	return filepath.Join(filepath.Dir(client.DefaultAgentFile()), projectTrustLeaf)
}

// projectTrustKey is the identity of a project root: absolute, cleaned and with symlinks
// resolved, so two spellings of one directory are one project.
func projectTrustKey(root string) string {
	root = strings.TrimSpace(root)
	if root == "" {
		return ""
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	return filepath.Clean(root)
}

// readProjectTrust reads the map. A missing or unreadable file vouches for nothing.
func readProjectTrust(path string) map[string]string {
	if path == "" {
		path = defaultProjectTrustFile()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	m := map[string]string{}
	if json.Unmarshal(b, &m) != nil || m == nil {
		return map[string]string{}
	}
	return m
}

// projectTrusted reports whether this user wrote or accepted root's config naming agent.
func projectTrusted(path, root, agent string) bool {
	key, agent := projectTrustKey(root), strings.TrimSpace(agent)
	if key == "" || agent == "" {
		return false
	}
	got, ok := readProjectTrust(path)[key]
	return ok && got == agent
}

// recordProjectTrust vouches for root's config naming agent. It writes owner-only and
// atomically, through the same writer as the saved agent file, refusing a symlinked target.
func recordProjectTrust(path, root, agent string) error {
	if path == "" {
		path = defaultProjectTrustFile()
	}
	key, agent := projectTrustKey(root), strings.TrimSpace(agent)
	if key == "" || agent == "" {
		return nil
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink - refusing to write through it (remove it and re-run)", path)
	}
	m := readProjectTrust(path)
	if m[key] == agent {
		return nil
	}
	m[key] = agent
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := secfile.MkdirAll(filepath.Dir(path)); err != nil {
		return err
	}
	return secfile.WriteFileAtomic(path, append(b, '\n'))
}

// projectGate decides what an agent picked from a project config this user never vouched for
// may do on the tier the run is about to use (pickProjectUnvouched). It returns the tier to use.
//
//   - no --tier, or --tier auto: socks5. It replaces no peer, and the config's own tier pin came
//     from the same unvouched file. Said once, with the two ways to run routed.
//   - --tier socks5: as asked.
//   - --tier wireguard: a terminal is asked, and a yes is remembered (unless the command saves
//     nothing); a script is refused with the flag that makes it explicit.
//
// A yes turns the pick into an ordinary project pick, so the peer-replacement note still follows.
func projectGate(p *agentPick, flagTier string, gio guidedIO, tty, remember bool, trustFile, cmdName string) (string, error) {
	if p.source != pickProjectUnvouched {
		return flagTier, nil
	}
	who := describeAgent(p.name, p.sel)
	sel := firstNonBlank(p.projectAgent, p.sel)
	tier := strings.ToLower(strings.TrimSpace(flagTier))
	switch {
	case tier == "" || isAutoTier(tier):
		if !g.quiet {
			fmt.Fprintf(gio.err, "whisper: %s/.whisper/config names %s, and this user's `whisper init` did not write it (it may have come with the repository), "+
				"so %s uses socks5, which replaces no other host's tunnel. To run routed, pass --agent %s --tier wireguard\n",
				p.projectRoot, who, cmdName, sel)
		}
		return tierSocks5, nil
	case !isWireGuardTier(tier):
		return flagTier, nil
	}
	refusal := usageErr("%s/.whisper/config names %s, and this user's `whisper init` did not write it (it may have come with the repository). "+
		"Binding it on the WireGuard tier replaces its tunnel wherever else it is held, so %s did not do it unasked: "+
		"pass --agent %s to choose it, or --tier socks5", p.projectRoot, who, cmdName, sel)
	if !tty {
		return "", refusal
	}
	fmt.Fprintf(gio.err, "%s/.whisper/config names %s, and this user's `whisper init` did not write it. "+
		"Binding it on WireGuard replaces its tunnel wherever else it is held. Use it? [y/N] ", p.projectRoot, who)
	ans, _ := gio.in.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "y", "yes":
	default:
		return "", refusal
	}
	if remember {
		if err := recordProjectTrust(trustFile, p.projectRoot, p.projectAgent); err != nil && !g.quiet {
			fmt.Fprintf(gio.err, "whisper: could not remember this project (%v); you will be asked again\n", err)
		}
	}
	p.source = pickProject
	return flagTier, nil
}
