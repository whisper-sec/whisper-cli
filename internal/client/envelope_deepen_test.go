// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

// ---- ProblemError.Error: the most-helpful-line ladder --------------------------------

func TestDeepenClientProblemErrorPrefersTheMostHelpfulLine(t *testing.T) {
	cases := []struct {
		name string
		in   ProblemError
		want string
	}{
		{"detail wins", ProblemError{Detail: "d", Title: "t", Type: "y", Status: 500}, "d"},
		{"then title", ProblemError{Title: "t", Type: "y", Status: 500}, "t"},
		{"then type", ProblemError{Type: "y", Status: 500}, "y"},
		{"never empty", ProblemError{Status: 503}, "control plane returned status 503"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Error(); got != tc.want {
				t.Fatalf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDeepenClientAsProblemUnwrapsAndRejects(t *testing.T) {
	inner := &ProblemError{Status: 429, Detail: "slow down"}
	wrapped := fmt.Errorf("op failed: %w", inner)
	pe, ok := AsProblem(wrapped)
	if !ok || pe.Status != 429 {
		t.Fatalf("a wrapped problem must be found, got ok=%v pe=%+v", ok, pe)
	}
	if _, ok := AsProblem(errors.New("plain")); ok {
		t.Fatal("a plain error is not a problem")
	}
	if _, ok := AsProblem(nil); ok {
		t.Fatal("nil is not a problem")
	}
}

// ---- Records / decodeProblem / hasProblemFields edge shapes --------------------------

func TestDeepenClientRecordsNilResultYieldsNil(t *testing.T) {
	var r *Result
	if got := r.Records(); got != nil {
		t.Fatalf("nil Result must yield nil records, got %v", got)
	}
}

func TestDeepenClientDecodeProblemIgnoresShapelessValues(t *testing.T) {
	cases := map[string]string{
		"object with no problem fields": `{"status":500}`,
		"whitespace string":             `"   "`,
		"array":                         `[1,2]`,
		"number":                        `42`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if got := decodeProblem(json.RawMessage(raw)); got != nil {
				t.Fatalf("decodeProblem(%s) = %+v, want nil (no legible error content)", raw, got)
			}
		})
	}
	// The liberal half: a bare reason STRING is real, legible error content.
	got := decodeProblem(json.RawMessage(`"  scope denied  "`))
	if got == nil || got.Detail != "scope denied" {
		t.Fatalf("a bare reason string must surface trimmed, got %+v", got)
	}
}

func TestDeepenClientHasProblemFieldsNonObjectBodies(t *testing.T) {
	for _, body := range []string{`[1,2]`, `"str"`, `42`, `not json`} {
		if hasProblemFields([]byte(body)) {
			t.Fatalf("hasProblemFields(%s) must be false", body)
		}
	}
	if !hasProblemFields([]byte(`{"detail":"x"}`)) {
		t.Fatal("a detail field is a problem field")
	}
}
