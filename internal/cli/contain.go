// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// contain.go is `whisper contain <pid>`: bring a process that is already running under the
// agent's egress without restarting it. The flow is contain_linux.go and the mechanism
// internal/enforce/contain_linux.go; every other platform refuses (containUnsupported).

func newContainCmd() *cobra.Command {
	var agent, agentFile string
	var release bool
	cmd := &cobra.Command{
		Use:   "contain <pid>",
		Short: "Put a running process's traffic through its Whisper /128, without restarting it (Linux, root)",
		Long: "Bring a process that is already running under Whisper egress, without restarting it.\n\n" +
			"Example:  sudo whisper contain 4242 --agent my-agent\n" +
			"          sudo whisper contain --release 4242\n\n" +
			"The process and its children are moved into a cgroup of their own, which carries two\n" +
			"kernel programs: one routes every new socket into a WireGuard tunnel from the agent's\n" +
			"/128, the other refuses any packet that would leave another way. Connections the process\n" +
			"opened before are cut; its listeners and unconnected sockets are pinned to the tunnel;\n" +
			"loopback, unix and netlink sockets keep working. It holds until Ctrl-C, which releases the\n" +
			"process, or until the process exits. If this command is killed the process stays cut\n" +
			"off, never uncontained: `sudo whisper contain --release <pid>` lets it go.\n\n" +
			"It is the weaker sibling of `sudo whisper run --enforce`, which starts a process in a\n" +
			"network namespace of its own. Containment refuses a process that runs as root or holds a\n" +
			"capability, because that process could undo it; it cannot stop the process becoming root\n" +
			"later through sudo or a setuid program, nor another process on this host that dials on\n" +
			"its behalf over loopback or a unix socket, nor a daemon it detached from its tree before.\n" +
			"Names are resolved by this host's resolver when that is on loopback; a lookup sent\n" +
			"straight to a resolver outside Whisper is refused.\n\n" +
			"Which agent: as for `whisper run --enforce`: --agent <name|id|/128>, --name <name>, the\n" +
			"project's .whisper/config, then this host's saved agent. It never creates one unless named.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr("name the process to contain: `sudo whisper contain <pid>`")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			pid, err := parsePid(args[0])
			if err != nil {
				return err
			}
			if release {
				return runContainRelease(pid)
			}
			return runContain(pid, agent, agentFile)
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "the agent whose /128 the process leaves from (name, id or /128)")
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper/agent)")
	cmd.Flags().BoolVar(&release, "release", false, "let go of a process a killed `whisper contain` left cut off")
	return cmd
}

// parsePid reads a pid liberally: surrounding space, a leading "pid", "pid:" or "pid=" (as a
// process listing or a log line prints it) are all accepted.
func parsePid(s string) (int, error) {
	t := strings.TrimSpace(strings.ToLower(s))
	t = strings.TrimPrefix(t, "pid")
	t = strings.TrimLeft(t, ":= ")
	n, err := strconv.Atoi(t)
	if err != nil || n <= 0 {
		return 0, usageErr("%q is not a process id: name it by number, as `ps` or `pgrep` prints it", s)
	}
	return n, nil
}

// containUnsupported is the refusal on a platform without cgroups. The process is not touched.
func containUnsupported(goos string) error {
	return usageErr("whisper contain moves a running process into a Linux cgroup, which %s does not have, so "+
		"nothing was changed; it is not available on %s yet. To start a process under Whisper egress there, "+
		"use `whisper run`, which sets the proxy variables for every tool that honours them", goos, goos)
}
