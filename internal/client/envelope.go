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
	// Rows is the ALTERNATIVE Neo4j-procedure-row wrapper the live /api/query returns:
	//   { "rows": [ { "result": {"columns":[...],"rows":[...]} } ] }
	// We accept BOTH so the client works against the live box AND the documented
	// contract (Postel: liberal in what we accept).
	Rows []struct {
		Result *Result `json:"result"`
	} `json:"rows"`
}

// DecodeEnvelope parses a control-plane reply body into a normalised Envelope. It is
// LIBERAL in what it accepts:
//
//  1. The dev-guide shape: {ok,status,result,error}. ok:false -> Err is set.
//  2. The live Neo4j wrapper: {rows:[{result:{columns,rows}}]} -> treated as ok:true
//     with that inner result (the proxy only wraps it this way on success).
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

	// Shape 2: the Neo4j row wrapper (or a top-level result with no ok flag) -> success.
	env.Ok = true
	switch {
	case re.Result != nil:
		env.Result = re.Result
	case len(re.Rows) > 0 && re.Rows[0].Result != nil:
		env.Result = re.Rows[0].Result
	default:
		// An empty, shapeless-but-valid JSON object: treat as a successful empty result
		// (read ops fail OPEN to an empty set, per the contract) rather than erroring.
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
