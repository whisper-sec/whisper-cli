// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/enforce"
)

// contain_linux.go is `whisper contain <pid>` on Linux, in the order that never leaves a window:
//
//  1. every reason the process cannot be contained, checked before anything is touched (root, the
//     pid, its privilege, cgroup v2), so a doomed containment never connects;
//  2. the enforced tunnel, exactly as `whisper run --enforce` brings it up (bringUpEnforced), but
//     with its device in the host namespace, and its egress verified through the very route a
//     contained socket takes;
//  3. only then the process, moved into the containment (enforce.Contain);
//  4. held until Ctrl-C or the process exits, then released, and the tunnel and the /128 let go.

func runContain(pid int, agent, agentFile string) error {
	if err := enforce.Preflight(pid); err != nil {
		return containFailure(err)
	}
	target := enforceTarget{}
	if os.Getenv("SUDO_USER") != "" {
		if t, err := resolveEnforceTarget(""); err == nil {
			target = t // whose key and agent files are read when root has none of its own
		}
	}
	notDone := fmt.Sprintf("pid %d was not contained and was left as it was", pid)
	up, err := bringUpEnforced(enforcedBringUp{
		target: target, agent: agent, agentFile: agentFile,
		command: "whisper contain", notDone: notDone, interruptNote: notDone,
		start: enforce.StartHostTunnel,
	})
	if err != nil {
		return err
	}
	defer up.close()
	ce, hold, tun, logf := up.ce, up.hold, up.tun, up.logf
	hr := tun.NS.HostRoute()
	self, perr := netip.ParseAddr(ce.address)
	if hr == nil || perr != nil {
		return &client.ProblemError{Status: 500, Detail: "the containment's tunnel has no host route, so " + notDone}
	}

	// From here a signal releases the process instead of killing this command with the process
	// moved. The handler is in place before the early one goes, so no signal meets the default.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sigs)
	up.early.stop()
	if err := up.early.interrupted(); err != nil {
		return err
	}

	c, err := enforce.Contain(pid, self, *hr, logf)
	if err != nil {
		return containFailure(err)
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		notes := c.Release()
		for _, n := range notes {
			logf("whisper: %s", n)
		}
	}
	defer release()

	v4 := up.v4note
	if !hr.CarryV4 {
		v4 = "IPv4 is refused at the socket (" + hr.V4Note + "), never leaked"
	}
	logf("Contained pid %d (%d process%s) as %s - %s ✓ egress verified through the containment's route; %s",
		pid, len(c.Members), pluralES(len(c.Members)), up.label, ce.address, v4)
	logf("whisper: %s", c.Sockets)
	if note := resolverNote(readResolvConf(), up.resolvers); note != "" {
		logf("whisper: %s", note)
	}
	logf("whisper: holding until Ctrl-C or until the process exits; if this command is killed the process stays cut off "+
		"until `sudo whisper contain --release %d`", pid)

	hold.confirm = func() bool {
		pcx, pcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer pcancel()
		ip, perr := echoInsideRetry(pcx, tun.NS, "ip6")
		return perr == nil && sameIP(ip, ce.address)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	why := ""
	for why == "" {
		select {
		case sig := <-sigs:
			why = "released on " + sig.String()
		case <-tick.C:
			if !c.Populated() {
				why = fmt.Sprintf("pid %d and its children have exited", pid)
			}
		}
	}
	release()
	st := &tun.Filter.Stats
	logf("whisper: containment ended (%s): %d packets passed, %d translated, %d refused, %d dropped",
		why, st.Passed.Load(), st.Translated.Load(), st.Refused.Load(), st.Dropped.Load())
	return nil
}

func runContainRelease(pid int) error {
	moved, notes, err := enforce.ReleaseStale(pid, netip.Addr{})
	if err != nil {
		return containFailure(err)
	}
	for _, n := range notes {
		fmt.Fprintf(os.Stderr, "whisper: %s\n", n)
	}
	if !g.quiet {
		fmt.Fprintf(os.Stderr, "Released pid %d's containment: %d process%s back on this host's own network\n", pid, len(moved), pluralES(len(moved)))
		// The killed command never let its /128 go at the box, and a release holds no key to.
		fmt.Fprintf(os.Stderr, "whisper: the agent's tunnel is gone with the command that was killed; %s\n", enforcedReaperNote)
	}
	return nil
}

// containFailure turns a refusal into the usage-class error it is: nothing was changed, and the
// sentence says why.
func containFailure(err error) error {
	var ce *enforce.ContainError
	if errors.As(err, &ce) {
		return usageErr("%s", ce.Msg)
	}
	return err
}

func pluralES(n int) string {
	if n == 1 {
		return ""
	}
	return "es"
}

// readResolvConf returns the nameservers in /etc/resolv.conf.
func readResolvConf() []netip.Addr {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseResolvConf(bufio.NewScanner(f))
}

func parseResolvConf(sc *bufio.Scanner) []netip.Addr {
	var out []netip.Addr
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(strings.SplitN(f[1], "%", 2)[0]); err == nil {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}

// resolverNote says what happens to the contained process's own lookups. A resolver on loopback
// (systemd-resolved's stub, a local dnsmasq) keeps answering, and the queries it makes upstream
// are this host's, not the process's. A resolver anywhere else is reached through the tunnel,
// where DNS to anything but Whisper's resolvers is refused.
func resolverNote(host, whisper []netip.Addr) string {
	var outside []string
	for _, a := range host {
		if a.IsLoopback() {
			continue
		}
		in := false
		for _, w := range whisper {
			if w == a {
				in = true
			}
		}
		if !in {
			outside = append(outside, a.String())
		}
	}
	if len(outside) == 0 {
		return ""
	}
	return "this host's resolver " + strings.Join(outside, ", ") + " is outside Whisper, so the process's lookups sent " +
		"to it are refused; point /etc/resolv.conf at a loopback resolver, or start the process under " +
		"`sudo whisper run --enforce`, whose resolvers are Whisper's"
}
