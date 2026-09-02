// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package alerts

import "time"

// document.go is the stable machine surface of `whisper alerts`. A composite command
// reads four plane streams, so there is no single envelope to echo verbatim; this is the
// shape a script may rely on instead, and its guarantees are stated rather than implied.
//
// A consumer MAY rely on: alert_version; ref being the plane's own dedupe identity spelled
// for a keyboard and stable for the life of the condition; the vocabularies being closed
// and additive, so a new token is a minor version and re-meaning one is major; a null
// score meaning never scored rather than zero; a null count meaning not read rather than
// zero; and rows being absent meaning conditions are absent ONLY when complete is true.
//
// A consumer MUST NOT rely on: severity or lane stability, because both are derived and
// will move as the graph improves - alert on a state change, never on a severity change;
// title or reason text, which is prose and will be edited, so never key, diff or parse it;
// or row order beyond the documented worst-first sort.
const AlertVersion = 1

// Document is one whole read, rendered for a machine.
type Document struct {
	AlertVersion int    `json:"alert_version"`
	ReadAt       string `json:"read_at"`
	Endpoint     string `json:"endpoint,omitempty"`
	// Complete is false when any stream did not answer. Every count below is then a
	// FLOOR, and the absence of a row proves nothing.
	Complete bool         `json:"complete"`
	Verdict  string       `json:"verdict"`
	Streams  []StreamDoc  `json:"streams"`
	Counts   Counts       `json:"counts"`
	Alerts   []Alert      `json:"alerts"`
	Muted    []Suppressed `json:"muted,omitempty"`
}

// StreamDoc is the read status of one plane surface, so a script can tell a fault from an
// answer without parsing prose.
type StreamDoc struct {
	Name string `json:"name"`
	// Status is one of: ok, empty, failed, not-applicable.
	Status string `json:"status"`
	Rows   int    `json:"rows"`
	Detail string `json:"detail,omitempty"`
}

// Counts are nullable on purpose. A nil count is "not read"; it is never rendered as 0.
type Counts struct {
	Open           *int64 `json:"open"`
	ActNow         *int64 `json:"act_now"`
	Review         *int64 `json:"review"`
	Quiet          *int64 `json:"quiet"`
	Unscored       *int64 `json:"unscored"`
	Unacknowledged *int64 `json:"unacknowledged"`
	Endpoints      *int64 `json:"endpoints"`
	HeardFrom      *int64 `json:"heard_from"`
	NetworkOnly    *int64 `json:"network_only"`
	Paging         int    `json:"paging"`
}

// Alert is one standing condition. The served cells are carried through unchanged; the
// derived ones are named as derived in their comments and are recomputable from the rest.
type Alert struct {
	Ref       string `json:"ref"`
	Agent     string `json:"agent,omitempty"`
	Address   string `json:"address,omitempty"`
	ID        string `json:"id"`
	Technique string `json:"technique,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Title     string `json:"title,omitempty"`
	Lane      string `json:"lane"`
	State     string `json:"state"`
	// Score is nullable: null means never scored, which is not the same as zero.
	Score *float64 `json:"score"`
	// Interrupt is derived: page, digest or silent. It is a SEPARATE axis from the lane.
	Interrupt string `json:"interrupt"`
	// InterruptReason is prose. Never key, diff or parse it.
	InterruptReason string `json:"interrupt_reason"`
	// Disposition is derived and takes exactly three reserved words: severed, held,
	// noticed. No rule author can write it.
	Disposition string  `json:"disposition"`
	FirstSeen   *int64  `json:"first_seen"`
	AgeMs       *int64  `json:"age_ms"`
	Confidence  float64 `json:"confidence"`
	Origin      string  `json:"origin,omitempty"`
	Exposure    string  `json:"exposure,omitempty"`
	Ack         string  `json:"ack,omitempty"`
	AckAt       *int64  `json:"ack_at"`
	Assignee    string  `json:"assignee,omitempty"`
	// NeverQuiet marks a technique on which no rule, mute or lane demotion may buy
	// silence.
	NeverQuiet bool `json:"never_quiet"`
	// Endpoint liveness, carried so a script does not need a second read to answer
	// "could this still get worse".
	Connectivity string `json:"connectivity,omitempty"`
	Sensor       string `json:"sensor,omitempty"`
}

// Suppressed is one live rule holding quiet, so a machine reading this document can see
// what a human reading the block sees.
type Suppressed struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
	ExpiresAt *int64 `json:"expires_at"`
	Scope     string `json:"scope,omitempty"`
}

// Render builds the machine document for a book.
func (b *Book) Render(opt Options) Document {
	now := opt.now()
	d := Document{
		AlertVersion: AlertVersion,
		ReadAt:       readStamp(b, now),
		Endpoint:     b.Endpoint,
		Complete:     b.Complete(),
		Verdict:      b.Verdict(opt),
	}
	for _, s := range b.Streams {
		d.Streams = append(d.Streams, streamDoc(s))
	}
	for _, r := range b.Rows {
		e := b.EndpointFor(r)
		v := Judge(r, e, b.Trail, now, opt.staleAck())
		if v.Token == InterruptPage {
			d.Counts.Paging++
		}
		a := Alert{
			Ref:             r.Ref(),
			Agent:           r.Agent,
			Address:         r.Address,
			ID:              r.ID,
			Technique:       r.Technique,
			Kind:            r.Kind,
			Title:           r.Title,
			Lane:            r.Lane,
			State:           r.State,
			Score:           r.Fused,
			Interrupt:       v.Token,
			InterruptReason: v.Reason,
			Disposition:     Disposition(r, b.Trail, now),
			AgeMs:           r.AgeMs,
			Confidence:      r.Confidence,
			Origin:          r.Origin,
			Exposure:        r.Exposure,
			Ack:             r.Ack,
			AckAt:           r.AckAt,
			Assignee:        r.Assignee,
			NeverQuiet:      NeverQuietTechnique(r.Technique),
			Connectivity:    e.Connectivity,
			Sensor:          e.Sensor,
		}
		if r.FirstSeen > 0 {
			fs := r.FirstSeen
			a.FirstSeen = &fs
		}
		d.Alerts = append(d.Alerts, a)
	}
	if d.Alerts == nil {
		d.Alerts = []Alert{}
	}
	d.Counts = b.counts(d.Counts.Paging)
	for _, s := range b.LiveSuppressions(now) {
		m := Suppressed{ID: s.ID, Name: s.Name, CreatedBy: s.CreatedBy, Scope: s.Scope}
		if s.ExpiresAt > 0 {
			e := s.ExpiresAt
			m.ExpiresAt = &e
		}
		d.Muted = append(d.Muted, m)
	}
	return d
}

func (b *Book) counts(paging int) Counts {
	c := Counts{Paging: paging}
	if !b.Coverage.Present {
		return c
	}
	cov := b.Coverage
	c.Open = i64(cov.Open)
	c.ActNow = i64(cov.ActNow)
	c.Review = i64(cov.Review)
	c.Quiet = i64(cov.Quiet)
	c.Unscored = i64(cov.Unscored)
	c.Unacknowledged = i64(cov.Unacknowledged)
	c.Endpoints = i64(cov.Endpoints)
	c.HeardFrom = i64(cov.HeardFrom())
	c.NetworkOnly = i64(cov.NetworkOnly())
	return c
}

func streamDoc(s Stream) StreamDoc {
	switch {
	case s.NotApplicable != "":
		return StreamDoc{Name: s.Name, Status: "not-applicable", Detail: s.NotApplicable}
	case s.Err != nil:
		return StreamDoc{Name: s.Name, Status: "failed", Detail: firstLine(s.Err.Error())}
	case s.Rows == 0:
		return StreamDoc{Name: s.Name, Status: "empty"}
	default:
		return StreamDoc{Name: s.Name, Status: "ok", Rows: s.Rows}
	}
}

func readStamp(b *Book, now time.Time) string {
	t := b.ReadAt
	if t.IsZero() {
		t = now
	}
	return t.UTC().Format(time.RFC3339)
}

func i64(v int64) *int64 { n := v; return &n }
