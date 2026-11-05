// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/enforce"
)

// runEnforced is `whisper run --enforce` on Windows. Windows has no network namespace,
// so the agent is not steered, it is fenced: it runs as the invoking user, de-elevated, in a logon
// session of its own, and the filtering platform lets that session reach exactly one thing, the
// local proxy this run brings up, which leaves from the agent's /128. Every other connection, on
// either family, is refused, and so is ICMP echo on this host for as long as the agent runs.
func runEnforced(agent, agentFile, tier, flagUser, name string, childArgs []string) error {
	if strings.TrimSpace(flagUser) != "" {
		return usageErr("--user is not available on Windows: running as another account needs its password, " +
			"which whisper never handles. The agent runs as you, without administrator rights")
	}
	if strings.TrimSpace(enforceSeccomp) != "" {
		return usageErr("--seccomp applies to the Linux namespace only; drop it on Windows")
	}
	if !enforce.Elevated() {
		return usageErr("--enforce adds Windows Filtering Platform rules, which needs an elevated terminal: open one "+
			"with \"Run as administrator\" and run `whisper run --enforce -- %s` again. The agent itself runs without "+
			"administrator rights", name)
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return usageErr("couldn't find %q to run - is it installed and on your PATH?", name)
	}
	if abs, aerr := filepath.Abs(path); aerr == nil {
		path = abs
	}
	dir, _ := os.Getwd()

	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	sess, err := acquireRunSession(c, agent, agentFile, tier)
	if err != nil {
		return err
	}
	defer sess.Stop()
	// The proxy must already be proven to leave from the /128 before the agent exists: the agent
	// is never started behind a door that goes somewhere else.
	if !sess.verified || !inWhisperRange(sess.addr) {
		return &client.ProblemError{Status: 502, Detail: "the egress could not be verified as this agent's /128, so " +
			"the agent was not started"}
	}
	port, err := proxyPortOf(sess.endpoint)
	if err != nil {
		return &client.ProblemError{Status: 500, Detail: err.Error() + "; the agent was not started"}
	}
	label := sess.name
	if label == "" {
		label = sess.addr
	}
	logf := func(format string, args ...any) {
		if !g.quiet {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	res, err := enforce.RunWindows(enforce.WindowsSpec{
		Path:      path,
		Args:      append([]string{name}, childArgs...),
		Env:       windowsEnforcedEnv(os.Environ(), sess.endpoint, sess.addr, os.Getpid()),
		Dir:       dir,
		ProxyPort: port,
		Logf:      logf,
	}, func() {
		logf("Enforced as %s - %s ✓ verified through the agent's only door, the local proxy; every other "+
			"connection from the agent is refused, on IPv4 and IPv6", label, sess.addr)
		logf("whisper: ICMP echo is refused on this host while the agent runs (Windows sends every ping as " +
			"the system, so it cannot be refused for the agent alone)")
	})
	if err != nil {
		return &client.ProblemError{Status: 500, Detail: strings.TrimPrefix(err.Error(), "enforce: ") +
			"; the agent was not started or has been stopped"}
	}
	switch res.Killed {
	case "":
		logf("whisper: enforced run ended; the agent's filters are removed")
	case "interrupted":
		logf("whisper: enforced run interrupted; the agent's tree was stopped and its filters are removed")
	default:
		logf("whisper: enforced run stopped: %s", res.Killed)
	}
	sess.Stop() // os.Exit runs no deferred call
	os.Exit(res.Code)
	return nil
}
