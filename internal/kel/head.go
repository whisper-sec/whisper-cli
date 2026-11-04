// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package kel

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// HeadLabel is the owner-name label of the chain head record: _whisper-kel.<agent-fqdn> TXT.
const HeadLabel = "_whisper-kel"

// HeadVersion is the first character-string of every head record this version reads.
const HeadVersion = "v=wkel1"

const (
	maxHeadStrings = 32
	maxHeadRDATA   = 1024
)

var (
	headOrder    = []string{"v", "i", "s", "k", "a", "c", "n", "e", "p", "x"}
	decimalRE    = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)
	otherVersion = regexp.MustCompile(`^v=wkel[0-9]+$`)
)

// Head is a parsed _whisper-kel record: the chain's current state as DNS publishes it.
type Head struct {
	IdentityRef string
	Sequence    int64
	Kind        Kind
	Authority   Authority
	Current     string // c=, the current key digest
	Next        string // n=, the commitment; "" is sealed (n=-)
	Event       string // e=, the last event digest
	Previous    string // p=, the outgoing key during an overlap; "" when absent
	Recovery    *int64 // x=, a pending recovery's effective time (Unix seconds); nil when absent
}

// Sealed reports a head that commits to no next key.
func (h *Head) Sealed() bool { return h.Next == "" }

// HeadProblem names why a record does not parse. The names are the vectors' and stable.
type HeadProblem string

// Every way a head record can fail to parse.
const (
	HeadEmpty              HeadProblem = "EMPTY"
	HeadTooManyRecords     HeadProblem = "TOO_MANY_RECORDS"
	HeadOversized          HeadProblem = "OVERSIZED"
	HeadNotVersionFirst    HeadProblem = "NOT_VERSION_FIRST"
	HeadUnsupportedVersion HeadProblem = "UNSUPPORTED_VERSION"
	HeadMalformedField     HeadProblem = "MALFORMED_FIELD"
	HeadDuplicateField     HeadProblem = "DUPLICATE_FIELD"
	HeadOutOfOrder         HeadProblem = "OUT_OF_ORDER"
	HeadMissingField       HeadProblem = "MISSING_FIELD"
	HeadBadValue           HeadProblem = "BAD_VALUE"
)

// HeadError is a parse refusal with its stable problem name.
type HeadError struct {
	Problem HeadProblem
	Reason  string
}

func (e *HeadError) Error() string { return "kel: " + string(e.Problem) + ": " + e.Reason }

func headErr(p HeadProblem, format string, a ...any) *HeadError {
	return &HeadError{Problem: p, Reason: fmt.Sprintf(format, a...)}
}

// ParseHeadRRset finds the one v=wkel1 record in a TXT RRset (each record its character-strings as
// octets) and parses it. Other TXT records are skipped; a head of another version alone is
// UNSUPPORTED_VERSION, so a future record is not read as absent.
func ParseHeadRRset(rrset [][][]byte) (*Head, error) {
	var found [][]byte
	other := false
	for _, rr := range rrset {
		if len(rr) == 0 {
			continue
		}
		first := string(rr[0])
		if first == HeadVersion {
			if found != nil {
				return nil, headErr(HeadTooManyRecords, "more than one v=wkel1 head record")
			}
			found = rr
		} else if otherVersion.MatchString(first) {
			other = true
		}
	}
	if found != nil {
		return ParseHead(found)
	}
	if other {
		return nil, headErr(HeadUnsupportedVersion, "only a key-event head of another version is published")
	}
	return nil, headErr(HeadEmpty, "no key-event head record")
}

// ParseHead parses one record's character-strings, in order.
func ParseHead(strs [][]byte) (*Head, error) {
	if len(strs) == 0 {
		return nil, headErr(HeadEmpty, "no strings")
	}
	if len(strs) > maxHeadStrings {
		return nil, headErr(HeadOversized, "%d strings, more than %d", len(strs), maxHeadStrings)
	}
	octets := 0
	for _, s := range strs {
		if s == nil {
			return nil, headErr(HeadMalformedField, "a null string")
		}
		if len(s) > 255 {
			return nil, headErr(HeadOversized, "a string of %d octets, more than 255", len(s))
		}
		octets += len(s) + 1
	}
	if octets > maxHeadRDATA {
		return nil, headErr(HeadOversized, "%d octets of RDATA, more than %d", octets, maxHeadRDATA)
	}
	value := make([]*string, len(headOrder))
	last := -1
	for idx, raw := range strs {
		str := string(raw)
		pos := -1
		if eq := strings.IndexByte(str, '='); eq >= 0 {
			pos = indexOfField(str[:eq])
		}
		if idx == 0 {
			if pos != 0 {
				return nil, headErr(HeadNotVersionFirst, "the first string is not v=")
			}
			if str != HeadVersion {
				return nil, headErr(HeadUnsupportedVersion, "the record is not %s", HeadVersion)
			}
		}
		if pos < 0 {
			continue // a string this version does not know is ignored, wherever it is
		}
		if value[pos] != nil {
			return nil, headErr(HeadDuplicateField, "%s= appears twice", headOrder[pos])
		}
		if pos < last {
			return nil, headErr(HeadOutOfOrder, "%s= comes after %s=", headOrder[pos], headOrder[last])
		}
		v := str[strings.IndexByte(str, '=')+1:]
		value[pos] = &v
		last = pos
	}
	for pos := 1; pos <= 7; pos++ {
		if value[pos] == nil {
			return nil, headErr(HeadMissingField, "%s= is missing", headOrder[pos])
		}
	}
	if !decimalRE.MatchString(*value[2]) || (value[9] != nil && !decimalRE.MatchString(*value[9])) {
		return nil, headErr(HeadBadValue, "s= and x= are decimal without leading zeros")
	}
	seq, err := strconv.ParseInt(*value[2], 10, 64)
	if err != nil {
		return nil, headErr(HeadBadValue, "s= or x= does not fit 63 bits")
	}
	var x *int64
	if value[9] != nil {
		xv, err := strconv.ParseInt(*value[9], 10, 64)
		if err != nil {
			return nil, headErr(HeadBadValue, "s= or x= does not fit 63 bits")
		}
		x = &xv
	}
	n := *value[6]
	if n == "-" {
		n = ""
	} else if n == "" {
		return nil, headErr(HeadBadValue, "a sealed head is n=-, never an empty n=")
	}
	h := &Head{IdentityRef: *value[1], Sequence: seq, Kind: kindOf(*value[3]), Authority: authorityOf(*value[4]),
		Current: *value[5], Next: n, Event: *value[7], Recovery: x}
	if value[8] != nil {
		h.Previous = *value[8]
	}
	if problem := h.invalid(value[8] != nil); problem != "" {
		return nil, headErr(HeadBadValue, "%s", problem)
	}
	return h, nil
}

func indexOfField(key string) int {
	for i, k := range headOrder {
		if k == key {
			return i
		}
	}
	return -1
}

func (h *Head) invalid(hasP bool) string {
	if !IsIdentityRef(h.IdentityRef) {
		return "i must match [a-z0-9]{1,64}"
	}
	if h.Sequence < 0 {
		return "s must be >= 0"
	}
	if h.Kind == "" || !h.Kind.Allows(h.Authority) {
		return fmt.Sprintf("k=%s may not carry a=%s", h.Kind, h.Authority)
	}
	if !IsDigest(h.Current) || !IsDigest(h.Event) {
		return "c and e are 64 lowercase hex"
	}
	if !isOptionalDigest(h.Next) {
		return "n is a 64 lowercase hex commitment, or sealed"
	}
	if hasP && (!IsDigest(h.Previous) || h.Previous == h.Current) {
		return "p is 64 lowercase hex and differs from c"
	}
	if hasP && h.Kind != ROT {
		return "only a rot opens an overlap; a " + string(h.Kind) + " head carries no p"
	}
	if h.Recovery != nil && (*h.Recovery < 0 || h.Next == "") {
		return "x is a non-negative time on a committed head; a sealed chain has no pending recovery"
	}
	if (h.Kind == ICP) != (h.Sequence == 0) && h.Kind != REC {
		return "an icp is sequence 0, and only an icp or a rec is"
	}
	if h.Kind == REC && h.Next != "" {
		return "a rec is sealed"
	}
	if h.Kind == RIC && h.Next == "" {
		return "a ric carries a commitment"
	}
	return ""
}

// Strings renders the record's character-strings, the form the service publishes.
func (h *Head) Strings() []string {
	n := h.Next
	if n == "" {
		n = "-"
	}
	out := []string{HeadVersion, "i=" + h.IdentityRef, "s=" + strconv.FormatInt(h.Sequence, 10),
		"k=" + string(h.Kind), "a=" + string(h.Authority), "c=" + h.Current, "n=" + n, "e=" + h.Event}
	if h.Previous != "" {
		out = append(out, "p="+h.Previous)
	}
	if h.Recovery != nil {
		out = append(out, "x="+strconv.FormatInt(*h.Recovery, 10))
	}
	return out
}

// Verdict is how a history compares with the published head.
type Verdict string

// The verdicts. MATCH and LAGGING are accepted; LAGGING is the write-ahead gap inside its window.
const (
	VerdictMatch            Verdict = "MATCH"
	VerdictLagging          Verdict = "LAGGING"
	VerdictStale            Verdict = "STALE"
	VerdictBehind           Verdict = "BEHIND"
	VerdictAhead            Verdict = "AHEAD"
	VerdictFork             Verdict = "FORK"
	VerdictInvalidChain     Verdict = "INVALID_CHAIN"
	VerdictFieldMismatch    Verdict = "FIELD_MISMATCH"
	VerdictIdentityMismatch Verdict = "IDENTITY_MISMATCH"
)

// Accepted reports MATCH or LAGGING.
func (v Verdict) Accepted() bool { return v == VerdictMatch || v == VerdictLagging }

// Check compares a full history (from sequence 0) with this published head. The history may be
// one event ahead of DNS only within lagWindowMillis of headSeenMillis, the verifier's own first
// sight of the head. No RRSIG time is a term, and neither is a time the history supplies.
func (h *Head) Check(history []Link, nowMillis, headSeenMillis, lagWindowMillis int64) Verdict {
	if len(history) == 0 {
		return VerdictBehind
	}
	walked := WalkChain(history)
	if !walked.Valid {
		return VerdictInvalidChain
	}
	last := walked.Head
	if h.IdentityRef != last.IdentityRef {
		return VerdictIdentityMismatch
	}
	if last.Sequence < h.Sequence {
		return VerdictBehind
	}
	if last.Sequence-h.Sequence > 1 {
		return VerdictAhead
	}
	at := history[h.Sequence].Event
	if at.Digest() != h.Event {
		return VerdictFork
	}
	if !h.Describes(at) {
		return VerdictFieldMismatch
	}
	if h.Previous != "" && (h.Sequence == 0 || history[h.Sequence-1].Event.NewKey != h.Previous) {
		return VerdictFieldMismatch // p= names a key this chain did not hold just before the head
	}
	if last.Sequence == h.Sequence {
		return VerdictMatch
	}
	return lagged(nowMillis, headSeenMillis, lagWindowMillis)
}

// CheckAbsent compares a history with a DNSSEC-proven absence of the head record: the state
// before the chain's first v2 event. An all-v1 history matches; one whose only v2 event is its
// last is one ahead, inside the window; anything else is ahead of it.
func CheckAbsent(history []Link, nowMillis, headSeenMillis, lagWindowMillis int64) Verdict {
	if !WalkChain(history).Valid {
		return VerdictInvalidChain
	}
	v2 := 0
	for _, l := range history {
		if l.Event.IsV2() {
			v2++
		}
	}
	switch {
	case v2 == 0:
		return VerdictMatch
	case v2 > 1:
		return VerdictAhead
	}
	return lagged(nowMillis, headSeenMillis, lagWindowMillis)
}

func lagged(now, seen, window int64) Verdict {
	if now-seen <= window && now >= seen {
		return VerdictLagging
	}
	return VerdictStale
}

// Describes reports whether the head names exactly this v2 event.
func (h *Head) Describes(e *Event) bool {
	return e != nil && e.IsV2() && h.IdentityRef == e.IdentityRef && h.Sequence == e.Sequence &&
		h.Kind == e.Kind && h.Authority == e.Authority && h.Current == e.NewKey && h.Next == e.Next &&
		h.Event == e.Digest()
}
