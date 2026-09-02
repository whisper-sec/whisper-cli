// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// migrateplan_test.go covers the plan file itself: the hash that says it was not edited,
// the receipt ordering rollback depends on, and the round trip through disk.

func TestPlanHashIsStableAndCoversThePlannedHalfOnly(t *testing.T) {
	p := buildFixturePlan(t)
	if err := p.VerifyHash(); err != nil {
		t.Fatalf("a freshly sealed plan does not verify: %v", err)
	}
	// Appending a receipt is what `apply` does, and it must NOT invalidate the hash, or a
	// resumed apply could not verify the plan it is resuming.
	p.Record(Receipt{Step: "identity", Subject: "d1", Result: ResultApplied, Agent: "ag_1"})
	p.AcceptedWidening = true
	if err := p.VerifyHash(); err != nil {
		t.Fatalf("recording a receipt broke the hash, so apply could never resume: %v", err)
	}
	// Editing the planned half must break it.
	p.Nodes[0].Label = "somebody-elses-name"
	if err := p.VerifyHash(); err == nil {
		t.Fatal("the plan was edited and still verified: the hash would then vouch for nothing")
	}
}

func TestVerifyHashRefusesAPlanWithNoHash(t *testing.T) {
	p := &Plan{SchemaVersion: PlanSchemaVersion}
	if err := p.VerifyHash(); err == nil {
		t.Fatal("a plan with no hash verified")
	}
}

func TestReceiptsAreSequencedAndTheLastOneWins(t *testing.T) {
	p := &Plan{SchemaVersion: PlanSchemaVersion}
	r1 := p.Record(Receipt{Step: "identity", Subject: "d1", Result: ResultRefused, Detail: "429"})
	r2 := p.Record(Receipt{Step: "identity", Subject: "d1", Result: ResultApplied, Agent: "ag_1"})
	if r1.Seq != 1 || r2.Seq != 2 {
		t.Fatalf("receipt sequence is %d, %d", r1.Seq, r2.Seq)
	}
	got, ok := p.ReceiptFor("identity", "d1")
	if !ok || got.Result != ResultApplied {
		t.Fatalf("the latest receipt for a subject is %+v; a retry after a refusal must win", got)
	}
	if !got.Applied() {
		t.Fatal("an applied receipt does not report itself as applied, so rollback would skip it")
	}
}

func TestARolledBackReceiptIsNotAppliedAgain(t *testing.T) {
	r := Receipt{Result: ResultApplied, RolledBackAt: "2026-08-29T00:00:00Z"}
	if r.Applied() {
		t.Fatal("a rolled-back receipt still reports as applied, so rollback would undo it twice")
	}
}

func TestSaveAndLoadPlanRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whalenet.plan.json")
	p := buildFixturePlan(t)
	if err := SavePlan(path, p); err != nil {
		t.Fatalf("SavePlan: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("the plan is mode %o; a complete map of somebody's fleet is not world-readable", perm)
	}
	back, err := LoadPlan(path)
	if err != nil {
		t.Fatalf("LoadPlan: %v", err)
	}
	if err := back.VerifyHash(); err != nil {
		t.Fatalf("a plan did not survive a round trip through disk: %v", err)
	}
	if len(back.Nodes) != len(p.Nodes) || len(back.Fidelity) != len(p.Fidelity) {
		t.Fatal("the round trip lost content")
	}
}

func TestLoadPlanRefusesWhatItCannotUnderstand(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "nope.json")
	if _, err := LoadPlan(missing); err == nil || !strings.Contains(err.Error(), "migrate plan") {
		t.Fatalf("a missing plan must say how to make one, got %v", err)
	}

	notAPlan := filepath.Join(dir, "other.json")
	if err := os.WriteFile(notAPlan, []byte(`{"hello":"world"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPlan(notAPlan); err == nil {
		t.Fatal("an unrelated JSON file was accepted as a plan")
	}

	future := filepath.Join(dir, "future.json")
	if err := os.WriteFile(future, []byte(`{"schema_version": 99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadPlan(future)
	if err == nil || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("a future schema must be refused with the way out, got %v", err)
	}

	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPlan(broken); err == nil {
		t.Fatal("a truncated plan file was accepted")
	}
}

// The write must be atomic: an interrupted apply cannot be allowed to leave a truncated
// plan, because the plan is the only record of what to undo.
func TestSavePlanReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	first := buildFixturePlan(t)
	if err := SavePlan(path, first); err != nil {
		t.Fatal(err)
	}
	second := buildFixturePlan(t)
	second.Record(Receipt{Step: "identity", Subject: "d1", Result: ResultApplied})
	if err := SavePlan(path, second); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".whalenet-plan-") {
			t.Fatalf("a temporary file was left behind: %s", e.Name())
		}
	}
	back, err := LoadPlan(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Receipts) != 1 {
		t.Fatalf("the second write did not replace the first: %d receipts", len(back.Receipts))
	}
}

// The plan is meant to be read with jq, and the acceptance criteria grep it by class.
func TestPlanJSONUsesTheFieldNamesTheCriteriaGrep(t *testing.T) {
	p := buildFixturePlan(t)
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"fidelity", "accepted_widening", "credential_fingerprint", "hash", "nodes"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("the plan has no %q field, and the acceptance criteria read it", key)
		}
	}
	var fid []map[string]any
	if err := json.Unmarshal(raw["fidelity"], &fid); err != nil {
		t.Fatal(err)
	}
	if len(fid) == 0 || fid[0]["class"] == nil {
		t.Fatal(`fidelity entries carry no "class" field, so jq '.fidelity[] | select(.class=="UNMAPPED")' finds nothing`)
	}
}

// Replanning an unchanged tailnet must hash the same, or the hash cannot show that a
// replan found nothing new. The timestamp is deliberately outside the hash for that.
func TestPlanHashIgnoresWhenItWasRead(t *testing.T) {
	a := buildFixturePlan(t)
	b := buildFixturePlan(t)
	b.CreatedAt = "2030-01-01T00:00:00Z"
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	if a.Hash != b.Hash {
		t.Fatal("two plans of the same tailnet, read at different times, hashed differently")
	}
	if err := b.VerifyHash(); err != nil {
		t.Fatalf("the resealed plan does not verify: %v", err)
	}
}
