// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// parentcmd.go - a parent command must never answer a typo with success.
//
//	$ whisper whale zzznotacommand; echo $?
//	<the whale command help>
//	0
//
// A human sees help and re-reads their spelling. A script sees success and carries on as though the
// command ran, which is the case that costs something: a deploy step that types `whale acl show` in
// a pipeline gets a green light and no ACL.
//
// The cause is subtle and worth stating, because `whisper whale` DID carry `Args: cobra.NoArgs` and
// it looked handled. cobra validates Args inside `Command.execute()`, but that method returns
// `flag.ErrHelp` for a command with no Run/RunE **before** it ever reaches ValidateArgs. So on a
// parent that only groups subcommands, an Args validator is dead code: it is declared, it reads as
// the guard, and it can never run. Attaching a RunE is what makes it reachable.
//
// This is the same shape as the `whisper <anything> --help` exit-0 trap that made a naive
// verb-presence check in build-pkg.sh pass for every string. cobra is liberal about what it accepts
// by default, and Postel's second half does not extend to reporting that we did something we did not.

// parentRunE is the RunE every command that only groups subcommands should carry.
//
// With no arguments it prints help and succeeds, which is what a person typing `whisper whale`
// wants. With an argument that matched no subcommand it names the offending verb, lists what was
// available, and returns a usage error so the process exits non-zero.
func parentRunE(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}
	return usageErr("unknown %s subcommand %q\n\navailable: %s",
		cmd.Name(), args[0], strings.Join(subcommandNames(cmd), ", "))
}

// subcommandNames lists a command's real subcommands, sorted, for the error above. Hidden ones and
// cobra's generated help/completion commands are left out: naming them would only mislead.
func subcommandNames(cmd *cobra.Command) []string {
	var out []string
	for _, c := range cmd.Commands() {
		if c.Hidden || c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		out = append(out, c.Name())
	}
	sort.Strings(out)
	return out
}

// asParent wires parentRunE onto a grouping command, and is the single place to do it so a new
// parent cannot be added without the behaviour. It deliberately does NOT overwrite a command that
// already has its own Run/RunE: `whisper graph <recipe>` dispatches its own arguments and is a
// parent in shape only.
const parentAnnotation = "whisper.pure-parent"

func asParent(cmd *cobra.Command) *cobra.Command {
	if cmd.Run == nil && cmd.RunE == nil {
		cmd.RunE = parentRunE
		if cmd.Annotations == nil {
			cmd.Annotations = map[string]string{}
		}
		// Marks a PURE grouper, so the guard test can tell it from a command that groups
		// subcommands AND takes arguments of its own. The latter legitimately errors with no
		// argument (`whisper domain` answers "pick a subcommand: verify | submit | status | list",
		// which is the right answer), and asserting otherwise would break good behaviour.
		cmd.Annotations[parentAnnotation] = "true"
		// Args must allow the argument through to RunE, or cobra rejects it first with its own
		// terser message and the list of available verbs above is never printed.
		cmd.Args = cobra.ArbitraryArgs
	}
	return cmd
}
