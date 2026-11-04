// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package kel

import "fmt"

// WalkFailure names why a chain does not walk. The names are the vectors' and stable.
type WalkFailure string

// Every way a chain can fail to walk.
const (
	FailEmpty              WalkFailure = "EMPTY"
	FailNullEvent          WalkFailure = "NULL_EVENT"
	FailNotGenesis         WalkFailure = "NOT_GENESIS"
	FailIdentitySplice     WalkFailure = "IDENTITY_SPLICE"
	FailAddressSplice      WalkFailure = "ADDRESS_SPLICE"
	FailSequenceBreak      WalkFailure = "SEQUENCE_BREAK"
	FailHashChainBreak     WalkFailure = "HASH_CHAIN_BREAK"
	FailV1AfterV2          WalkFailure = "V1_AFTER_V2"
	FailAfterSealed        WalkFailure = "AFTER_SEALED"
	FailCommitmentMismatch WalkFailure = "COMMITMENT_MISMATCH"
	FailKindNotAllowed     WalkFailure = "KIND_NOT_ALLOWED"
	FailRicKeyChanged      WalkFailure = "RIC_KEY_CHANGED"
	FailMissingSPKI        WalkFailure = "MISSING_SPKI"
	FailSPKIMismatch       WalkFailure = "SPKI_MISMATCH"
	FailUnsigned           WalkFailure = "UNSIGNED"
	FailMalformedKey       WalkFailure = "MALFORMED_KEY"
	FailMalformedSignature WalkFailure = "MALFORMED_SIGNATURE"
	FailHighS              WalkFailure = "HIGH_S"
	FailBadSignature       WalkFailure = "BAD_SIGNATURE"
)

// Link is an event and the SPKI of the key it introduces (nil when not supplied).
type Link struct {
	Event *Event
	SPKI  []byte
}

// AuthorityBreak is an event whose authority is not the chain's own keys: an owner recovery, a
// reconcile record, or a legacy v1 event.
type AuthorityBreak struct {
	Sequence    int64
	What        string
	EpochMillis int64
}

// Walk is the outcome of walking a chain.
type Walk struct {
	Valid       bool
	Reason      string
	Failure     WalkFailure
	FailedIndex int
	Head        *Event
	Breaks      []AuthorityBreak
}

// KeyAuthorised reports a chain that walks and whose every move its own keys authorised.
func (w Walk) KeyAuthorised() bool { return w.Valid && len(w.Breaks) == 0 }

func walkFail(f WalkFailure, i int, format string, a ...any) Walk {
	return Walk{Failure: f, FailedIndex: i, Reason: fmt.Sprintf(format, a...)}
}

// WalkChain checks a whole chain from sequence 0: the hash chain, the sequences, every
// commitment, every signature against its SPKI, and that v1 events appear only as a prefix.
func WalkChain(links []Link) Walk {
	if len(links) == 0 {
		return walkFail(FailEmpty, -1, "empty key-event log: no inception event")
	}
	var breaks []AuthorityBreak
	var prev *Event
	seenV2 := false
	var addr *[16]byte
	for i, link := range links {
		cur := link.Event
		if cur == nil {
			return walkFail(FailNullEvent, i, "null event at index %d", i)
		}
		if prev == nil {
			if cur.Sequence != 0 || cur.Prior != Genesis {
				return walkFail(FailNotGenesis, i, "the first event is not sequence 0 with the genesis prior")
			}
		} else if w, bad := step(prev, cur, seenV2, i); bad {
			return w
		}
		if cur.IsV2() {
			if addr == nil {
				a := cur.Addr
				addr = &a
			} else if *addr != cur.Addr {
				return walkFail(FailAddressSplice, i, "event %d names another address", i)
			}
			if w, bad := signature(link, i); bad {
				return w
			}
			if cur.Kind == RCV || cur.Kind == REC {
				breaks = append(breaks, AuthorityBreak{cur.Sequence, string(cur.Kind), cur.EpochMillis})
			}
			seenV2 = true
		} else {
			if len(link.SPKI) != 0 && KeyDigest(link.SPKI) != cur.NewKey {
				return walkFail(FailSPKIMismatch, i, "the key supplied for event %d is not its key", i)
			}
			breaks = append(breaks, AuthorityBreak{cur.Sequence, "v1", cur.EpochMillis})
		}
		prev = cur
	}
	return Walk{Valid: true, Reason: "ok", FailedIndex: -1, Head: prev, Breaks: breaks}
}

func step(prev, cur *Event, seenV2 bool, i int) (Walk, bool) {
	if cur.IdentityRef != prev.IdentityRef {
		return walkFail(FailIdentitySplice, i, "identity splice at index %d: expected %s", i, prev.IdentityRef), true
	}
	if cur.Sequence != prev.Sequence+1 {
		return walkFail(FailSequenceBreak, i, "sequence break at index %d: expected %d got %d", i,
			prev.Sequence+1, cur.Sequence), true
	}
	if cur.Prior != prev.Digest() {
		return walkFail(FailHashChainBreak, i, "hash-chain break at index %d: prior digest does not match e[%d]",
			i, i-1), true
	}
	if !cur.IsV2() {
		if seenV2 {
			return walkFail(FailV1AfterV2, i, "a v1 event after a v2 event at index %d", i), true
		}
		return revealed(prev, cur, i)
	}
	switch cur.Kind {
	case ICP:
		return walkFail(FailKindNotAllowed, i, "an icp after sequence 0 at index %d", i), true
	case ROT:
		return revealed(prev, cur, i)
	case RIC:
		if !prev.Sealed() {
			return walkFail(FailKindNotAllowed, i, "a ric on a committed chain at index %d: it rotates with a rot", i), true
		}
		if cur.NewKey != prev.NewKey {
			return walkFail(FailRicKeyChanged, i, "a ric changed the key at index %d", i), true
		}
	case REC:
		if prev.IsV2() || !prev.Sealed() {
			return walkFail(FailKindNotAllowed, i, "a rec follows only a sealed v1 event, at index %d", i), true
		}
	}
	return Walk{}, false
}

func revealed(prev, cur *Event, i int) (Walk, bool) {
	if prev.Sealed() {
		return walkFail(FailAfterSealed, i, "rotation after a SEALED event at index %d: no successor was pre-committed", i), true
	}
	if sha256Hex([]byte(cur.NewKey)) != prev.Next {
		return walkFail(FailCommitmentMismatch, i, "pre-rotation violation at index %d: revealed key does not "+
			"match e[%d]'s pre-commitment", i, i-1), true
	}
	return Walk{}, false
}

func signature(link Link, i int) (Walk, bool) {
	cur := link.Event
	if !cur.Kind.Signed() {
		if len(link.SPKI) != 0 && KeyDigest(link.SPKI) != cur.NewKey {
			return walkFail(FailSPKIMismatch, i, "the key supplied for event %d is not its key", i), true
		}
		return Walk{}, false
	}
	if len(link.SPKI) == 0 {
		return walkFail(FailMissingSPKI, i, "event %d is signed but no key was supplied", i), true
	}
	if KeyDigest(link.SPKI) != cur.NewKey {
		return walkFail(FailSPKIMismatch, i, "the key supplied for event %d is not its key", i), true
	}
	if len(cur.Signature) == 0 {
		return walkFail(FailUnsigned, i, "event %d is a %s with no signature", i, cur.Kind), true
	}
	st, err := cur.Statement()
	if err != nil {
		return walkFail(FailBadSignature, i, "event %d's statement does not build: %v", i, err), true
	}
	switch VerifySignature(link.SPKI, st, cur.Signature) {
	case SigValid:
		return Walk{}, false
	case SigMalformedKey:
		return walkFail(FailMalformedKey, i, "event %d's key is not P-256 SPKI", i), true
	case SigMalformedSignature:
		return walkFail(FailMalformedSignature, i, "event %d's signature is not strict DER", i), true
	case SigHighS:
		return walkFail(FailHighS, i, "event %d's signature is not low-S", i), true
	}
	return walkFail(FailBadSignature, i, "event %d's signature does not verify over its statement", i), true
}
