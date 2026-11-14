// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"errors"
	"time"
)

// rendezvous.go is WHEN a relayed pair punches.
//
// A pair the control plane can only relay is two nodes behind two NATs with no segment in common. Each
// NAT drops what arrives from the other until its own side has sent towards it, so a handshake gets
// through only once BOTH ends have sent at each other inside the lifetime of the mappings that sending
// opened. A node that sends whenever it likes either meets its peer by luck or sends for ever. The plane
// solves this without a message: every pair gets a repeating window whose phase is a pure function of the
// two overlay addresses and whose position is absolute UTC, so both ends compute the same instant from
// either box. The peer map hands it out on the relayed row as punch_at_ms / punch_until_ms / punch_slot,
// with the box's own clock (server_time_ms) and the period in the header.
//
// This file turns that window into one on THIS process's clock and answers the two questions the train
// asks of it: which window is in progress or next, and whether this side attends it.
//
// # Bounded, and still meeting
//
// A pair that cannot be punched must not cost more than the relay already carrying it. So after a window
// without a handshake a train backs off, attending only every second window, then every fourth, up to
// one in 2^maxWindowBackoff. The windows it keeps are the ones whose slot number is a multiple of that
// power of two. The slot is the plane's, the same at both ends, so the side that has backed off further
// attends a SUBSET of the other side's windows and the two still meet, at the slower side's cadence. A
// backoff counted from each node's own install time would let two nodes drift onto disjoint windows and
// never meet again.

const (
	// maxWindowBackoff caps the backoff: after this many windows in a row without a handshake a train
	// attends one window in 16, which at the plane's sixty-second period is one every sixteen minutes.
	maxWindowBackoff = 4

	// defaultRendezvousPeriod is the period of a row whose header states none, which is the plane's own.
	defaultRendezvousPeriod = 60 * time.Second

	// minRendezvousPeriod and maxRendezvousPeriod bound the period a row may ask for. The floor is the
	// plane's own period: the backoff counts windows, so a shorter period would make "one window in
	// sixteen" a matter of seconds, and a plane that wants one has to ship a client that agrees. A
	// longer one than an hour is a plane that has stopped meaning it.
	minRendezvousPeriod = time.Minute
	maxRendezvousPeriod = time.Hour

	// maxRendezvousWindow caps how long one window may be: the plane's six seconds and its skew
	// tolerance at each end, with a second to spare. A longer window is a licence to send for longer.
	maxRendezvousWindow = 10 * time.Second

	// defaultSkewTolerance is the clock disagreement the plane's window absorbs at each end, when the
	// header does not say. A read whose round trip leaves more uncertainty than this cannot place the
	// window well enough to meet the far side, and is not used for it.
	defaultSkewTolerance = 1500 * time.Millisecond

	// maxRendezvousSlot bounds the slot so slot*period cannot overflow for any period this accepts.
	// Real slots are about thirty million (minutes since 1970).
	maxRendezvousSlot = int64(1) << 40
)

// Rendezvous is the control plane's shared punch window for one pair, placed on this process's clock. The
// zero value means "no window": the peer is punched the untimed way, from the moment it is armed.
type Rendezvous struct {
	// At is when the window numbered Slot opens, and Until when it closes. Both carry Go's monotonic
	// reading (they are offsets from a time.Now), so a step in this host's wall clock does not move them.
	At    time.Time
	Until time.Time
	// Period is how often the window recurs. Window Slot+k opens at At + k*Period.
	Period time.Duration
	// Slot is the plane's number for the window that opens at At. Both ends of a pair get the same one,
	// which is what lets their backoffs agree on which windows to keep.
	Slot int64
	// ReadError is half the round trip of the read that placed it: how far At may be from where the plane
	// meant it. A later placement of the same schedule replaces this one only when it is no worse.
	ReadError time.Duration
}

// IsZero reports whether there is no window, or none this side could use.
func (r Rendezvous) IsZero() bool {
	return r.At.IsZero() || r.Period <= 0 || !r.Until.After(r.At)
}

// ParseRendezvous places the plane's window on this process's clock.
//
// atMs, untilMs and serverMs are the plane's UTC epoch milliseconds: the window's bounds and the box's own
// clock when it answered. periodMs and skewMs are the header's period and skew tolerance, 0 for the
// plane's sixty seconds and second and a half. sent and received bracket the read that carried them,
// taken with time.Now on this host.
//
// The clock is Cristian's method on the monotonic clock. The box read serverMs at some instant between
// sent and received, so the window opens (atMs - serverMs) after the midpoint of the two, give or take
// half the round trip. That holds whether or not this host's wall clock is right, and a read that took
// 200 ms places the window within 100 ms, well inside the second and a half of skew the plane's window is
// built to absorb. With no serverMs the local wall clock stands in for the box's, which is right on any
// host that keeps time and is what the plane asks of one that does.
//
// It refuses rather than guesses. A window that ends before it opens or is longer than
// maxRendezvousWindow, a period outside [minRendezvousPeriod, maxRendezvousPeriod], a slot out of range, a
// slot that is not the one the window's own instant falls in (the plane numbers a window by the period it
// opens in, and never lets one straddle a period boundary), a window that is neither the one in progress
// nor the next one by the plane's clock (the box hands out exactly those two), and a read too slow to
// place it within the skew tolerance all return an error, and the caller then installs nothing for the row.
// Refusing costs the pair a punch it would not have had anyway; guessing could have this node sending at
// the wrong time for ever. The slot check also pins the slot to absolute time, so two reads cannot number
// the same window differently and move a train's schedule underneath it.
func ParseRendezvous(atMs, untilMs, slot, serverMs, periodMs, skewMs int64, sent, received time.Time) (Rendezvous, error) {
	// The header may only tighten the tolerance: a plane that claims more would loosen what a slow read
	// is allowed to place.
	skew := defaultSkewTolerance
	if skewMs > 0 && skewMs < defaultSkewTolerance.Milliseconds() {
		skew = time.Duration(skewMs) * time.Millisecond
	}
	return parseRendezvous(atMs, untilMs, slot, serverMs, periodMs, skew, sent, received)
}

// maxFallbackReadError is how far a slow read may misplace a DIRECT row's window (ParseFallbackWindow): half
// a round trip of up to fifteen seconds. A relayed pair's window has to be placed within the plane's skew
// tolerance, because its two ends send in a set order a few seconds apart; a direct row's window is where a
// spent first train tries again, and its two ends only have to send within the life of what their sending
// opens, which is tens of seconds even on cheap NATs and stateful filters.
const maxFallbackReadError = 15 * time.Second

// ParseFallbackWindow is ParseRendezvous for the window a DIRECT row carries, with a read allowed to place it
// within maxFallbackReadError rather than the plane's skew tolerance. Every other refusal is the same.
func ParseFallbackWindow(atMs, untilMs, slot, serverMs, periodMs int64, sent, received time.Time) (Rendezvous, error) {
	return parseRendezvous(atMs, untilMs, slot, serverMs, periodMs, maxFallbackReadError, sent, received)
}

func parseRendezvous(atMs, untilMs, slot, serverMs, periodMs int64, skew time.Duration, sent, received time.Time) (Rendezvous, error) {
	period := defaultRendezvousPeriod
	if periodMs != 0 {
		if periodMs < minRendezvousPeriod.Milliseconds() || periodMs > maxRendezvousPeriod.Milliseconds() {
			return Rendezvous{}, errors.New("the punch window's period is out of range")
		}
		period = time.Duration(periodMs) * time.Millisecond
	}
	if atMs <= 0 || untilMs <= atMs {
		return Rendezvous{}, errors.New("the punch window is empty")
	}
	// Both bounds are known positive here, so the difference cannot overflow.
	length := untilMs - atMs
	if length > maxRendezvousWindow.Milliseconds() {
		return Rendezvous{}, errors.New("the punch window is too long")
	}
	if slot < 0 || slot > maxRendezvousSlot {
		return Rendezvous{}, errors.New("the punch window's slot is out of range")
	}
	// slot*period fits: maxRendezvousSlot times an hour in milliseconds is about 4e18.
	if off := atMs - slot*period.Milliseconds(); off < 0 || off+length > period.Milliseconds() {
		return Rendezvous{}, errors.New("the punch window's slot is not the period it opens in")
	}
	if received.Before(sent) {
		received = sent
	}
	if received.Sub(sent)/2 > skew {
		return Rendezvous{}, errors.New("the read was too slow to place the punch window")
	}
	mid := sent.Add(received.Sub(sent) / 2)
	ref := serverMs
	if ref <= 0 {
		ref = mid.UnixMilli()
	}
	// The box hands out the window in progress (it opened up to one window ago) or the next one (it opens
	// within a period). A period of slack on each side absorbs a slow read; anything further is a clock or
	// a plane this client does not understand. Checked before any arithmetic on it, so a hostile atMs can
	// never overflow the Duration below. Both operands are positive, so the subtraction cannot either.
	lead := atMs - ref
	if lead < -2*period.Milliseconds() || lead > 2*period.Milliseconds() {
		return Rendezvous{}, errors.New("the punch window is not the one in progress or the next one")
	}
	at := mid.Add(time.Duration(lead) * time.Millisecond)
	return Rendezvous{At: at, Until: at.Add(time.Duration(length) * time.Millisecond), Period: period, Slot: slot,
		ReadError: received.Sub(sent) / 2}, nil
}

// bounds is where window slot sits on this process's clock.
func (r Rendezvous) bounds(slot int64) (time.Time, time.Time) {
	start := r.At.Add(time.Duration(slot-r.Slot) * r.Period)
	return start, start.Add(r.Until.Sub(r.At))
}

// current is the slot of the window in progress at now, or of the next one to open. A node that reads
// its peer map in the middle of a window joins it rather than waiting a period.
func (r Rendezvous) current(now time.Time) int64 {
	d := now.Sub(r.At)
	k := int64(d / r.Period)
	if d < 0 && d%r.Period != 0 {
		k-- // floor, not truncation, for a now before At
	}
	slot := r.Slot + k
	if _, end := r.bounds(slot); !now.Before(end) {
		slot++
	}
	return slot
}

// attends reports whether a train that has missed `missed` windows in a row attends window slot: every
// window at first, then only slots that are a multiple of 2^missed, capped at maxWindowBackoff.
func attends(slot int64, missed int) bool {
	if missed <= 0 {
		return true
	}
	if missed > maxWindowBackoff {
		missed = maxWindowBackoff
	}
	m := int64(1) << missed
	return ((slot%m)+m)%m == 0
}
