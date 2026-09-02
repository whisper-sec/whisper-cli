// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Fixing `whale` alone would have left the same trap in every other grouping command and in
// every one added later, so the guard walks the WHOLE tree.

// groupingCommands returns every command that only groups subcommands: it has children and no Run of
// its own. Those are exactly the ones cobra answers with help-and-exit-0 for an unknown verb.
func groupingCommands(t *testing.T) []*cobra.Command {
	t.Helper()
	var out []string
	var found []*cobra.Command
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, kid := range c.Commands() {
			if kid.Name() == "help" || kid.Name() == "completion" {
				continue
			}
			if len(kid.Commands()) > 0 {
				found = append(found, kid)
				out = append(out, kid.CommandPath())
			}
			walk(kid)
		}
	}
	walk(NewRootCommand())
	// The control: this test is worthless if the walk finds nothing. A tree with no grouping
	// commands would pass every assertion below without checking anything.
	if len(found) < 5 {
		t.Fatalf("the walk found only %d grouping commands (%v); it is not seeing the tree, so a"+
			" pass here would mean nothing", len(found), out)
	}
	return found
}

// A typo must never report success. This is the defect: a script that types `whale acl show` in a
// pipeline got exit 0 and no ACL.
func TestNoGroupingCommandAcceptsAnUnknownSubcommand(t *testing.T) {
	for _, parent := range groupingCommands(t) {
		t.Run(parent.CommandPath(), func(t *testing.T) {
			root := NewRootCommand()
			path := strings.Fields(parent.CommandPath())[1:] // drop "whisper"
			args := append(append([]string{}, path...), "zzznotacommand")
			root.SetArgs(args)
			root.SetOut(new(strings.Builder))
			root.SetErr(new(strings.Builder))
			root.SilenceUsage, root.SilenceErrors = true, true

			err := root.Execute()
			if err == nil {
				t.Fatalf("`whisper %s zzznotacommand` returned no error, so the shell sees exit 0"+
					" and a script carries on as though the command ran", strings.Join(path, " "))
			}
			if !strings.Contains(err.Error(), "zzznotacommand") {
				t.Errorf("the error does not name the verb that was not understood: %v", err)
			}
		})
	}
}

// The control for the test above, in the other direction: a PURE grouping command with no arguments
// is a person asking what is available, and must still succeed. A fix that made every parent error
// would pass the test above while breaking `whisper whale`.
//
// Scoped to pure groupers on purpose. A command that groups subcommands AND takes its own arguments
// is right to refuse an empty invocation, and several do it well: `whisper domain` answers "pick a
// subcommand: verify | submit | status | list". Asserting success there would be asserting a
// regression.
func TestAPureGroupingCommandWithNoArgumentsStillSucceeds(t *testing.T) {
	var pure []*cobra.Command
	for _, c := range groupingCommands(t) {
		if c.Annotations[parentAnnotation] == "true" {
			pure = append(pure, c)
		}
	}
	if len(pure) == 0 {
		t.Fatal("no command is marked as a pure grouper, so this control checks nothing")
	}
	for _, parent := range pure {
		t.Run(parent.CommandPath(), func(t *testing.T) {
			root := NewRootCommand()
			root.SetArgs(strings.Fields(parent.CommandPath())[1:])
			root.SetOut(new(strings.Builder))
			root.SetErr(new(strings.Builder))
			root.SilenceUsage, root.SilenceErrors = true, true
			if err := root.Execute(); err != nil {
				t.Errorf("`%s` with no arguments must print help and succeed, got: %v",
					parent.CommandPath(), err)
			}
		})
	}
}

// The message has to be actionable, not just non-zero: name what was available.
func TestTheUnknownSubcommandErrorListsWhatWasAvailable(t *testing.T) {
	root := NewRootCommand()
	root.SetArgs([]string{"whale", "zzznotacommand"})
	root.SetOut(new(strings.Builder))
	root.SetErr(new(strings.Builder))
	root.SilenceUsage, root.SilenceErrors = true, true

	err := root.Execute()
	if err == nil {
		t.Fatal("no error")
	}
	for _, verb := range []string{"status", "whois", "ping"} {
		if !strings.Contains(err.Error(), verb) {
			t.Errorf("the error does not offer %q as an available verb: %v", verb, err)
		}
	}
}
