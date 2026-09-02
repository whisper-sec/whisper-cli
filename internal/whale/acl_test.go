// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"errors"
	"strings"
	"testing"
)

func TestACLSummaryReadsTheCellsTheControlPlaneActuallyEmits(t *testing.T) {
	// Exactly the shape the control plane returns: op:policy gives {key,value} rows, the ACL cells
	// sit among the ordinary policy cells, and the notes are numbered.
	pairs := [][2]string{
		{"default", "block"},
		{"mode", "hybrid"},
		{"whale.acl.hash", "sha256:32f4f68a5010"},
		{"whale.acl.version", "3"},
		{"whale.acl.artifact", "sha256:cfdcc729aa11"},
		{"whale.acl.default", "allow"},
		{"whale.acl.nodes", "118"},
		{"whale.acl.clauses", "4"},
		{"whale.acl.clauses.connect_only", "1"},
		{"whale.acl.refusals", "0"},
		{"whale.acl.last_refusal", ""},
		{"whale.acl.note.2", "third"},
		{"whale.acl.note.0", "first"},
		{"whale.acl.note.1", "second"},
		{"whale.acl.document", `{"default":"allow"}`},
	}
	s := ACLSummaryFrom(pairs)
	if !s.Published {
		t.Fatal("a hash means a document is in force")
	}
	if s.Hash != "sha256:32f4f68a5010" || s.Version != "3" || s.Nodes != "118" || s.Clauses != "4" {
		t.Fatalf("cells mis-read: %+v", s)
	}
	if s.ConnectOnly != "1" || s.Default != "allow" || s.Artifact != "sha256:cfdcc729aa11" {
		t.Fatalf("cells mis-read: %+v", s)
	}
	// The numbers ARE the order. The compiler explains its own document in sequence, and
	// a shuffled explanation is a different explanation.
	if strings.Join(s.Notes, ",") != "first,second,third" {
		t.Fatalf("notes out of order: %v", s.Notes)
	}
	if s.Document != `{"default":"allow"}` {
		t.Fatalf("document mis-read: %q", s.Document)
	}
}

func TestACLSummaryOfATenantWithNoDocumentClaimsNothing(t *testing.T) {
	s := ACLSummaryFrom([][2]string{{"default", "block"}, {"mode", "hybrid"}, {"retention", "90"}})
	if s.Published {
		t.Fatal("a policy with no ACL cells must not read as a published document")
	}
	if s.Document != "" || len(s.Notes) != 0 {
		t.Fatalf("invented content: %+v", s)
	}
}

// TestTheSilentFleetWideDenyIsRefused pins the case that matters: `{}` publishes
// cleanly and takes an entire fleet to
// deny-everything with a 200.
func TestTheSilentFleetWideDenyIsRefused(t *testing.T) {
	for _, doc := range []string{
		`{}`,
		"// nothing yet\n{}\n",
		"{\n  \"groups\": {\"group:sre\": [\"alice@example.com\"]},\n}\n", // groups but no grants
		`{"grants":[]}`,
		"{ /* everything is commented out\n  \"grants\": [{\"src\":[\"a\"],\"dst\":[\"b\"]}]\n*/ }",
	} {
		if err := CheckACLDocument([]byte(doc)); !errors.Is(err, ErrSilentFleetWideDeny) {
			t.Fatalf("a document with no grants and no stated default must be refused: %q -> %v", doc, err)
		}
	}
}

func TestAnExplicitLockDownIsObeyedAndSoIsARealDocument(t *testing.T) {
	for _, doc := range []string{
		`{"default":"deny"}`,  // said out loud, so it is meant
		`{"default":"allow"}`, // and the other direction
		"{\n  \"default\": \"deny\",  // on purpose\n}",
		`{"grants":[{"src":["group:sre"],"dst":["tag:prod"],"ip":["tcp:22"]}]}`,
		// A pasted Tailscale file: `acls` is not our grammar, but the refusal for that is
		// the control plane's ("unknown top-level key"), and it is a better message than
		// ours would be. Never refuse it here.
		`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`,
	} {
		if err := CheckACLDocument([]byte(doc)); err != nil {
			t.Fatalf("a document that says what it means must pass: %q -> %v", doc, err)
		}
	}
}

// TestADocumentThisSideCannotParseIsPassedOnRatherThanRefused is the Postel half. The
// control plane's HuJSON reader is more liberal than this one (single quotes, unquoted
// keys), and a local parser that refused what the server would have accepted would be
// resistance we invented ourselves.
func TestADocumentThisSideCannotParseIsPassedOnRatherThanRefused(t *testing.T) {
	for _, doc := range []string{
		`{'default': 'deny'}`, // single quotes: legal HuJSON, not legal JSON
		`{default: "deny"}`,   // an unquoted key
		`{"grants": [`,        // genuinely truncated: the server's parser must say so
		`not json at all`,
	} {
		if err := CheckACLDocument([]byte(doc)); err != nil {
			t.Fatalf("we must not out-guess the strict parser: %q -> %v", doc, err)
		}
	}
}

func TestTheRefusalOffersEveryWayOut(t *testing.T) {
	err := CheckACLDocument([]byte(`{}`))
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, want := range []string{"EVERY flow", "withdraw", `"default": "deny"`, "the grants you meant"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal must offer %q, and it says: %v", want, err)
		}
	}
}

func TestACLTestVerdictReadsTheWordTheControlPlaneEmits(t *testing.T) {
	if !(ACLTestVerdict{Verdict: "deny"}).Denied() {
		t.Fatal("deny is a denial")
	}
	if !(ACLTestVerdict{Verdict: " DENY "}).Denied() {
		t.Fatal("case and whitespace must not change a security verdict")
	}
	if (ACLTestVerdict{Verdict: "allow"}).Denied() {
		t.Fatal("allow is not a denial")
	}
	// An unrecognised word is NOT read as a denial: the exit code says "the document
	// refuses this", and only the word deny means that.
	if (ACLTestVerdict{Verdict: "no_opinion"}).Denied() {
		t.Fatal("only deny means deny")
	}
}
