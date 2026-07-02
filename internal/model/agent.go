// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package model holds the view-facing data the TUI renders: an Agent (an op:list row
// enriched with the op:agent counters) and a unified Event (the µs-normalised join of
// the SSE stream and the op:logs poll). Both surfaces decode the control-plane
// envelope into these, so the views never reason about wire shapes or unit splits.
package model

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Agent is one fleet member: the op:list summary, optionally enriched with the
// op:agent detail + live counters. Zero values are fine (a freshly-seen agent from the
// stream has only Address until op:agent fills the rest).
type Agent struct {
	ID      string // the LIST id ("agent-…") — used for op:agent / op:logs / kill
	Address string // the /128 — the identity, and the SSE ?agent= narrow selector
	Label   string
	FQDN    string
	PTR     string
	State   string // active / pending / released / …
	Contact string // opt-in public contact (may be empty — never fabricate)
	Created int64  // epoch ms (allocated_at)

	// Counters from op:agent (zero until detail is fetched; fail-open to zero, never 500).
	LastSeen          int64
	DNSQueries        int64
	DNSBlocked        int64
	DNSNxdomain       int64
	Packets           int64
	BytesUp           int64
	BytesDown         int64
	ConnectionsActive int64
	ConnectionsTotal  int64

	// Detailed reports whether op:agent has populated the counters (vs. a list-only row).
	Detailed bool
	// SeenInStream marks an agent discovered via the live stream / logs but possibly
	// absent from op:list (the caveat: op:list may miss connect-created agents).
	SeenInStream bool
}

// HasIdentity reports whether the agent has an allocated /128 (so the SSE narrow can
// pin it; a history-only agent shows "(no /128)").
func (a Agent) HasIdentity() bool { return a.Address != "" }

// Name is the best human handle: the label if present, else the id, else the address.
func (a Agent) Name() string {
	switch {
	case a.Label != "":
		return a.Label
	case a.ID != "":
		return a.ID
	default:
		return a.Address
	}
}

// Key is the stable identity key for de-duplication across list/stream/logs: the /128
// when known, else the id. Two sources for the same agent collapse to one row.
func (a Agent) Key() string {
	if a.Address != "" {
		return a.Address
	}
	return a.ID
}

// TenantFromFQDN extracts the opaque tenant handle from an agent fqdn of the form
// <agent>.<t-handle>.agents.<zone> — the second label. The fleet a caller already
// holds IS the tenant answer (derive, don't fetch). Returns "" when the shape does
// not match (never a wrong guess).
func TenantFromFQDN(fqdn string) string {
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	if len(labels) >= 4 && len(labels[1]) >= 9 && labels[1][0] == 't' {
		return labels[1]
	}
	return ""
}

// AgentFromListItem builds an Agent from an op:list row's `item` map (or the row
// itself if it is already the item). It is liberal in the field names it accepts.
func AgentFromListItem(rec map[string]any) Agent {
	item := rec
	if m, ok := rec["item"].(map[string]any); ok {
		item = m
	}
	return Agent{
		ID:      str(item, "agent", "id"),
		Address: str(item, "address", "addr128"),
		Label:   str(item, "label"),
		FQDN:    str(item, "fqdn"),
		PTR:     str(item, "ptr"),
		State:   firstNonEmpty(str(item, "state"), "active"),
		Contact: str(item, "contact"),
		Created: epoch(item, "created", "allocated_at"),
	}
}

// MergeDetail folds an op:agent detail record into a (typically list-derived) Agent,
// filling the 17 columns. Empty/zero detail fields never clobber a known summary value.
func (a *Agent) MergeDetail(rec map[string]any) {
	a.Detailed = true
	if v := str(rec, "agent", "id"); v != "" {
		a.ID = v
	}
	if v := str(rec, "address", "addr128"); v != "" {
		a.Address = v
	}
	if v := str(rec, "fqdn"); v != "" {
		a.FQDN = v
	}
	if v := str(rec, "ptr"); v != "" {
		a.PTR = v
	}
	if v := str(rec, "label"); v != "" {
		a.Label = v
	}
	if v := str(rec, "state"); v != "" {
		a.State = v
	}
	if v := str(rec, "contact"); v != "" {
		a.Contact = v
	}
	if v := epoch(rec, "allocated_at", "created"); v != 0 {
		a.Created = v
	}
	a.LastSeen = num(rec, "last_seen")
	a.DNSQueries = num(rec, "dns_queries")
	a.DNSBlocked = num(rec, "dns_blocked")
	a.DNSNxdomain = num(rec, "dns_nxdomain")
	a.Packets = num(rec, "packets")
	a.BytesUp = num(rec, "bytes_up")
	a.BytesDown = num(rec, "bytes_down")
	a.ConnectionsActive = num(rec, "connections_active")
	a.ConnectionsTotal = num(rec, "connections_total")
}

// BlockedPct is the share of DNS queries that were blocked, as a percent (0 when no
// queries). Used in the selected-agent panel.
func (a Agent) BlockedPct() float64 {
	if a.DNSQueries <= 0 {
		return 0
	}
	return float64(a.DNSBlocked) / float64(a.DNSQueries) * 100
}

// --- decoding helpers (shared, liberal-in) --------------------------------------

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s := asString(v); s != "" {
				return s
			}
		}
	}
	return ""
}

func num(m map[string]any, keys ...string) int64 {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if n, ok := asInt(v); ok {
				return n
			}
		}
	}
	return 0
}

func epoch(m map[string]any, keys ...string) int64 { return num(m, keys...) }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// asString renders a decoded JSON value as a display string.
func asString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'g', -1, 64)
	case json.Number:
		return x.String()
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// asInt coerces a decoded JSON value to int64 (numbers, numeric strings).
func asInt(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n, true
		}
		if f, err := x.Float64(); err == nil {
			return int64(f), true
		}
	case string:
		if n, err := strconv.ParseInt(x, 10, 64); err == nil {
			return n, true
		}
	case int64:
		return x, true
	case int:
		return int64(x), true
	}
	return 0, false
}

// String renders a one-line summary (debug / drill-down fallback).
func (a Agent) String() string {
	return fmt.Sprintf("%s %s %s", a.Name(), a.Address, a.State)
}
