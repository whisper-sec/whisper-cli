// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ProblemError is the RFC-7807 problem object the control plane returns on failure
// (ok:false). Its Detail is written to be helpful and secret-free — surface it
// verbatim to the operator (Postel: a clear, helpful error, never an opaque 500).
type ProblemError struct {
	Type        string   `json:"type,omitempty"`
	Title       string   `json:"title,omitempty"`
	Status      int      `json:"status,omitempty"`
	Detail      string   `json:"detail,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
}

// Error renders the most helpful single line we have: prefer detail, then title, then
// type, then a generic note — never an empty string.
func (e *ProblemError) Error() string {
	switch {
	case e.Detail != "":
		return e.Detail
	case e.Title != "":
		return e.Title
	case e.Type != "":
		return e.Type
	default:
		return fmt.Sprintf("control plane returned status %d", e.Status)
	}
}

// Result is the tabular payload every control op returns: column names plus rows of
// raw JSON values (one []any per row, positionally aligned with Columns).
type Result struct {
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`
}

// Envelope is the decoded, NORMALISED control-plane reply. Whichever wire shape the
// server sent, after DecodeEnvelope you always read Ok / Status / Result / Err here.
type Envelope struct {
	Ok     bool
	Status int
	Result *Result
	Err    *ProblemError
	// Raw is the verbatim JSON body — the scriptable `--json` path echoes this so a
	// script sees EXACTLY what the server sent (no re-encoding, no field loss).
	Raw json.RawMessage
}

// rawEnvelope is the logical/dev-guide wire shape:
//
//	{ "ok": true, "status": 200, "result": {"columns":[...],"rows":[...]}, "error": null }
type rawEnvelope struct {
	Ok     *bool         `json:"ok"`
	Status int           `json:"status"`
	Result *Result       `json:"result"`
	Error  *ProblemError `json:"error"`
	// Columns/Rows are the ALTERNATIVE Neo4j-procedure-row wrapper the live /api/query
	// returns: a `whisper.agents({op:...})` CALL comes back as its own little table —
	// outer columns `op, ok, status, result, error, retry_after`, one row per call:
	//   { "columns":[...], "rows": [ {"op":"connect","ok":true,"result":{...},...} ] }
	// That outer row can arrive EITHER as a column-keyed object (above) OR, just as
	// validly for a tabular Cypher result, as a POSITIONAL array matched against
	// Columns (`"rows":[["connect",true,200,{...},null,null]]`). We accept BOTH, and a
	// column reorder in either form, so the client works against the live box AND the
	// documented contract (Postel: liberal in what we accept — map by column NAME,
	// never by a fixed index; see decodeOuterRow).
	Columns []string          `json:"columns"`
	Rows    []json.RawMessage `json:"rows"`
}

// outerRow is one decoded row of the outer whisper.agents YIELD table (op, ok, status,
// result, error, retry_after), independent of whether it arrived on the wire as a
// column-keyed object or a positional array.
type outerRow struct {
	Ok     *bool
	Result *Result
	Error  *ProblemError
}

// decodeOuterRow decodes one element of rawEnvelope.Rows into an outerRow. It tries the
// column-keyed object form first (the common live shape); if the row is instead a
// positional array, it zips the values against columns BY NAME — so a column reorder on
// the wire never breaks extraction (Postel: liberal in what we accept). A malformed,
// short, or empty row yields a zero outerRow rather than an error: the caller degrades to
// a clear "no result" message, never an opaque decode failure.
func decodeOuterRow(raw json.RawMessage, columns []string) outerRow {
	fields := map[string]json.RawMessage{}
	if json.Unmarshal(raw, &fields) != nil {
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) == nil {
			fields = make(map[string]json.RawMessage, len(columns))
			for i, col := range columns {
				if i < len(arr) {
					fields[col] = arr[i]
				}
			}
		}
	}

	var row outerRow
	if v, ok := fields["ok"]; ok {
		var b bool
		if json.Unmarshal(v, &b) == nil {
			row.Ok = &b
		}
	}
	if v, ok := fields["result"]; ok && string(v) != "null" {
		var r Result
		if json.Unmarshal(v, &r) == nil {
			row.Result = &r
		}
	}
	if v, ok := fields["error"]; ok && string(v) != "null" {
		var e ProblemError
		if json.Unmarshal(v, &e) == nil {
			row.Error = &e
		}
	}
	return row
}

// DecodeEnvelope parses a control-plane reply body into a normalised Envelope. It is
// LIBERAL in what it accepts:
//
//  1. The dev-guide shape: {ok,status,result,error}. ok:false -> Err is set. If the top
//     level omits result (the payload lives in the outer YIELD row instead — see 2), it
//     is recovered from there rather than treated as absent.
//  2. The live outer whisper.agents YIELD-table wrapper: {columns:[op,ok,status,result,
//     error,retry_after], rows:[...]} -> the first row is read for ok/result/error,
//     whether that row arrived as a column-keyed object OR a positional array matched
//     against columns BY NAME (never a fixed index, so a column reorder never breaks
//     extraction — see decodeOuterRow). A row with ok:false is a real failure, surfaced
//     as Err, never silently downgraded to an empty/absent result.
//  3. A bare problem object {type,title,status,detail} with NO ok/result/rows -> Err.
//
// httpStatus is the transport status code; it seeds Status when the body omits it and
// lets us treat a >=400 transport status with no usable body as an error.
func DecodeEnvelope(body []byte, httpStatus int) (*Envelope, error) {
	env := &Envelope{Status: httpStatus, Raw: append(json.RawMessage(nil), body...)}

	var re rawEnvelope
	if err := json.Unmarshal(body, &re); err != nil {
		// A non-JSON reply is itself a fault — surface it as a helpful problem, never
		// a raw decode error the operator can't act on.
		if httpStatus >= 400 {
			env.Err = &ProblemError{Status: httpStatus, Detail: "control plane returned a non-JSON error reply"}
			return env, nil
		}
		return nil, fmt.Errorf("control plane returned a non-JSON reply: %w", err)
	}

	if re.Status != 0 {
		env.Status = re.Status
	}

	// Shape 1: an explicit ok flag.
	if re.Ok != nil {
		env.Ok = *re.Ok
		env.Result = re.Result
		env.Err = re.Error
		if env.Result == nil && len(re.Rows) > 0 {
			// The top level carries ok/status but the actual payload lives in the outer
			// whisper.agents YIELD row (the live tabular shape) — recover it by name
			// rather than concluding there is no result.
			row := decodeOuterRow(re.Rows[0], re.Columns)
			env.Result = row.Result
			if env.Err == nil {
				env.Err = row.Error
			}
		}
		if !env.Ok && env.Err == nil {
			// ok:false with no error object — synthesise a helpful one from the status.
			env.Err = &ProblemError{Status: env.Status, Detail: "control plane reported failure"}
		}
		if env.Err != nil && env.Err.Status == 0 {
			env.Err.Status = env.Status
		}
		return env, nil
	}

	// Shape 3: a bare problem object (no ok, no rows, but a problem-ish field present).
	if re.Error != nil || (re.Result == nil && len(re.Rows) == 0 && hasProblemFields(body)) {
		env.Ok = false
		if re.Error != nil {
			env.Err = re.Error
		} else {
			env.Err = decodeBareProblem(body, env.Status)
		}
		if env.Err.Status == 0 {
			env.Err.Status = env.Status
		}
		return env, nil
	}

	// Shape 2: the Neo4j row wrapper (or a top-level result with no ok flag) -> success,
	// UNLESS the row itself carries an explicit ok:false — a real op failure the caller
	// must see, never masked as an empty/absent result ("no egress" for a call that
	// actually failed for a legible reason).
	switch {
	case re.Result != nil:
		env.Ok = true
		env.Result = re.Result
	case len(re.Rows) > 0:
		row := decodeOuterRow(re.Rows[0], re.Columns)
		if row.Ok != nil && !*row.Ok {
			env.Ok = false
			env.Err = row.Error
			if env.Err == nil {
				env.Err = &ProblemError{Status: env.Status, Detail: "control plane reported failure"}
			}
			if env.Err.Status == 0 {
				env.Err.Status = env.Status
			}
			return env, nil
		}
		env.Ok = true
		if row.Result != nil {
			env.Result = row.Result
		} else {
			// ok (or no explicit verdict) but genuinely no result row: a clear empty
			// result, never a decode failure — the caller renders its own clear message.
			env.Result = &Result{}
		}
	default:
		// An empty, shapeless-but-valid JSON object: treat as a successful empty result
		// (read ops fail OPEN to an empty set, per the contract) rather than erroring.
		env.Ok = true
		env.Result = &Result{}
	}
	return env, nil
}

// hasProblemFields reports whether body carries any RFC-7807 field, used to recognise
// a bare problem object that lacks an ok flag / result / rows.
func hasProblemFields(body []byte) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	for _, k := range []string{"detail", "title", "type", "error"} {
		if _, ok := probe[k]; ok {
			return true
		}
	}
	return false
}

func decodeBareProblem(body []byte, status int) *ProblemError {
	var p ProblemError
	_ = json.Unmarshal(body, &p)
	if p.Status == 0 {
		p.Status = status
	}
	if p.Detail == "" && p.Title == "" && p.Type == "" {
		p.Detail = "control plane reported failure"
	}
	return &p
}

// AsProblem extracts a *ProblemError from err if it is (or wraps) one.
func AsProblem(err error) (*ProblemError, bool) {
	var pe *ProblemError
	if errors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}

// Records turns a Result into a slice of column-keyed maps — the ergonomic form the
// TUI and the human-readable subcommands render from. A nil Result yields nil.
func (r *Result) Records() []map[string]any {
	if r == nil {
		return nil
	}
	out := make([]map[string]any, 0, len(r.Rows))
	for _, row := range r.Rows {
		m := make(map[string]any, len(r.Columns))
		for i, col := range r.Columns {
			if i < len(row) {
				m[col] = row[i]
			}
		}
		out = append(out, m)
	}
	return out
}
