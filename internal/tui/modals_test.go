// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import "testing"

// TestValidateAgentName covers the create-modal mandatory-name validator (§3.2 hole b):
// the "(required)" label is now TRUE — an empty/blank/whitespace name is rejected, any
// non-blank name is accepted (the server polices reserved/premium names beyond this).
func TestValidateAgentName(t *testing.T) {
	bad := []string{"", " ", "\t", "\n", "   \t  "}
	for _, s := range bad {
		if err := validateAgentName(s); err == nil {
			t.Fatalf("validateAgentName(%q) must reject a blank name", s)
		}
	}
	good := []string{"scout", "  scout  ", "agent-1", "my agent"}
	for _, s := range good {
		if err := validateAgentName(s); err != nil {
			t.Fatalf("validateAgentName(%q) must accept a non-blank name, got %v", s, err)
		}
	}
}

// TestBuildCreateArgs_RejectsBlankAtWriteLayer covers §3.2 hole b's DEFENSE IN DEPTH: the
// create modal's submit goes through buildCreateArgs, which re-applies the trimmed-non-blank
// guard at the WRITE layer — so a blank name can NEVER fire op:identity/op:register unnamed
// even if the huh field validator were somehow bypassed. A non-blank name yields a trimmed
// label and the right op.
func TestBuildCreateArgs_RejectsBlankAtWriteLayer(t *testing.T) {
	for _, blank := range []string{"", " ", "\t", "\n", "   \t  "} {
		for _, reg := range []bool{false, true} {
			op, args, err := buildCreateArgs(blank, "", reg)
			if err == nil {
				t.Fatalf("buildCreateArgs(%q, register=%v) must reject a blank name (no unnamed agent)", blank, reg)
			}
			if op != "" || args != nil {
				t.Fatalf("buildCreateArgs(%q) on error must return no op/args, got op=%q args=%v", blank, op, args)
			}
		}
	}

	// A valid name → trimmed label + the op matching the register flag.
	op, args, err := buildCreateArgs("  scout  ", "  me@example.com ", false)
	if err != nil {
		t.Fatalf("buildCreateArgs(valid) errored: %v", err)
	}
	if op != "identity" {
		t.Fatalf("op = %q, want identity (own /128)", op)
	}
	if args["label"] != "scout" {
		t.Fatalf("label = %v, want the trimmed 'scout'", args["label"])
	}
	if args["contact_email"] != "me@example.com" {
		t.Fatalf("contact_email = %v, want the trimmed email", args["contact_email"])
	}

	op2, args2, err := buildCreateArgs("scout", "", true)
	if err != nil {
		t.Fatalf("buildCreateArgs(register) errored: %v", err)
	}
	if op2 != "register" {
		t.Fatalf("op = %q, want register", op2)
	}
	if args2["label"] != "scout" {
		t.Fatalf("register label = %v, want scout", args2["label"])
	}
}
