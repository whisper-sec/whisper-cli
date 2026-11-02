// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import "strings"

// RevokeMatchedNothing reports whether an op:revoke reply says that nothing was revoked: no
// agent of the caller's matched the selector, because it was revoked already or belongs to
// another account. The plane gives those one answer on purpose.
//
// Two shapes mean it, and every surface that revokes reads both:
//   - the plane's own answer since ok:false, code NOT_FOUND, on a 404 or with no status;
//   - an older plane's ok:true reply whose first row carries status not_found, which a caller
//     checking ok alone reads as a successful revoke.
//
// Either way it is a verdict, not a fault: the request was understood and nothing is left to
// do, so it is never retried. It is read off the code, never off a 404 alone: a 404 from a
// mistyped control URL or a proxy in the way is a failure to reach the plane, not a statement
// that the agent is gone.
func RevokeMatchedNothing(env *Envelope, err error) bool {
	if err == nil && env != nil && !env.Ok && env.Err != nil {
		err = env.Err
	}
	if err != nil {
		return IsNotFound(err)
	}
	if env == nil || !env.Ok {
		return false
	}
	recs := env.Result.Records()
	if len(recs) == 0 {
		return false
	}
	row := recs[0]
	if item, ok := row["item"].(map[string]any); ok {
		row = item
	}
	for _, k := range []string{"status", "state"} {
		if s, ok := row[k].(string); ok {
			return strings.EqualFold(strings.TrimSpace(s), "not_found")
		}
	}
	return false
}

// IsNotFound reports whether err is the control plane's NOT_FOUND problem: the code, on a 404
// or with no status. Any other status, or a 404 without the code, is not it.
func IsNotFound(err error) bool {
	pe, ok := AsProblem(err)
	if !ok || !strings.EqualFold(strings.TrimSpace(pe.Title), "NOT_FOUND") {
		return false
	}
	return pe.Status == 404 || pe.Status == 0
}
