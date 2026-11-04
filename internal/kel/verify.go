// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package kel

import (
	"fmt"
	"net/netip"
	"strings"
)

// BundleFailure names why a bundle is refused. The names are the vectors' and stable.
type BundleFailure string

// Every way a bundle can be refused.
const (
	BundleNoPages              BundleFailure = "NO_PAGES"
	BundleSubjectMismatch      BundleFailure = "SUBJECT_MISMATCH"
	BundlePagesOutOfOrder      BundleFailure = "PAGES_OUT_OF_ORDER"
	BundlePagesSpliced         BundleFailure = "PAGES_SPLICED"
	BundleIncomplete           BundleFailure = "INCOMPLETE"
	BundleCheckpointUnreadable BundleFailure = "CHECKPOINT_UNREADABLE"
	BundleCheckpointUnverified BundleFailure = "CHECKPOINT_UNVERIFIED"
	BundleBadInclusion         BundleFailure = "BAD_INCLUSION"
	BundleChainInvalid         BundleFailure = "CHAIN_INVALID"
	BundleKeyChainMismatch     BundleFailure = "KEY_CHAIN_MISMATCH"
	BundleHeadRejected         BundleFailure = "HEAD_REJECTED"
)

// InclusionState is what the log proves about one event.
type InclusionState string

// The proof states.
const (
	ProofProven      InclusionState = "PROVEN"      // included under the page's checkpoint, checked here
	ProofUnproven    InclusionState = "UNPROVEN"    // sequenced past the checkpoint
	ProofWithheld    InclusionState = "WITHHELD"    // inside the checkpoint, but no proof was given
	ProofUnsequenced InclusionState = "UNSEQUENCED" // not yet in the log
	ProofShredded    InclusionState = "SHREDDED"    // its salt was erased
)

// EventProof is one event's proof state.
type EventProof struct {
	Sequence int64
	Leaf     int64
	State    InclusionState
}

// Subject is the identity the caller asked about, from the caller's own knowledge: an address it
// named and the FQDN DNSSEC proved for it. Never the bundle's own fields.
type Subject struct {
	Address string
	FQDN    string
}

// VerifyOptions are the verifier's own inputs. Head is the DNSSEC-validated _whisper-kel record,
// or nil for a DNSSEC-proven absence. HeadSeenMillis is the verifier's own first observation of
// the head (or of the proven absence); no RRSIG time is a term. LogKey, when set, must sign every checkpoint a
// proof is checked against. Witnessed, when set, reports whether a checkpoint note carries
// enough independent fresh cosignatures.
type VerifyOptions struct {
	Head            *Head
	NowMillis       int64
	HeadSeenMillis  int64
	LagWindowMillis int64
	LogKey          *LogKey   // one log key, or
	LogKeys         []*LogKey // any of several (a log that rotated its key signs under either)
	Witnessed       func(note string) bool
}

func (o VerifyOptions) logKeys() []*LogKey {
	if o.LogKey == nil {
		return o.LogKeys
	}
	return append([]*LogKey{o.LogKey}, o.LogKeys...)
}

// verifyUnder returns the checkpoint a note signs under any of keys.
func verifyUnder(note string, keys []*LogKey) (*TreeHead, error) {
	var last error
	for _, k := range keys {
		cp, err := VerifyCheckpoint(note, k)
		if err == nil {
			return cp, nil
		}
		last = err
	}
	return nil, last
}

// BundleResult is the verdict on a bundle.
type BundleResult struct {
	Valid                bool
	Failure              BundleFailure
	Reason               string
	Hosted               bool
	Walk                 *Walk
	Head                 Verdict
	Proofs               []EventProof
	CheckpointsSigned    bool
	CheckpointsWitnessed bool
}

// FullyProven reports a valid bundle whose every event is proven under a log-signed checkpoint.
func (r *BundleResult) FullyProven() bool {
	if !r.Valid || !r.CheckpointsSigned {
		return false
	}
	for _, p := range r.Proofs {
		if p.State != ProofProven {
			return false
		}
	}
	return true
}

// KeyAuthorised reports a valid bundle whose chain its own keys authorised throughout.
func (r *BundleResult) KeyAuthorised() bool {
	return r.Valid && r.Walk != nil && r.Walk.KeyAuthorised()
}

// Breaks are the authority breaks of a chain that walked.
func (r *BundleResult) Breaks() []AuthorityBreak {
	if r.Walk == nil || !r.Walk.Valid {
		return nil
	}
	return r.Walk.Breaks
}

func bundleFail(f BundleFailure, hosted bool, v Verdict, proofs []EventProof, format string, a ...any) *BundleResult {
	return &BundleResult{Failure: f, Reason: fmt.Sprintf(format, a...), Hosted: hosted, Head: v, Proofs: proofs}
}

func subjectAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !a.Is6() || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a, true
}

func subjectName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// VerifyBundle runs the owner's checks over a bundle's pages, in order: every page is the
// subject's and the same chain, the pages are contiguous and complete, every proof reaches its
// (log-signed) checkpoint, the chain walks, the last page's key_chain is the chain's state, and
// the history reaches the published head.
func VerifyBundle(pages []*Page, subject Subject, o VerifyOptions) *BundleResult {
	if len(pages) == 0 {
		return bundleFail(BundleNoPages, false, "", nil, "no bundle pages")
	}
	for _, p := range pages {
		if p == nil {
			return bundleFail(BundleNoPages, false, "", nil, "no bundle pages")
		}
	}
	addr, ok := subjectAddr(subject.Address)
	if !ok {
		return bundleFail(BundleSubjectMismatch, false, "", nil, "no subject address to check the bundle against")
	}
	want16 := addr.As16()
	fqdn := subjectName(subject.FQDN)
	first := pages[0]
	hosted := first.KeyChain == "hosted"
	expectAfter := int64(-1)
	for i, p := range pages {
		pa, ok := subjectAddr(p.Address)
		if !ok || pa.As16() != want16 || subjectName(p.FQDN) != fqdn {
			return bundleFail(BundleSubjectMismatch, hosted, "", nil, "page %d is not the history of %s", i, subject.Address)
		}
		if p.IdentityRef != first.IdentityRef || (p.KeyChain == "hosted") != hosted {
			return bundleFail(BundlePagesSpliced, hosted, "", nil, "page %d is another chain's", i)
		}
		if p.AfterSeq != expectAfter {
			return bundleFail(BundlePagesOutOfOrder, hosted, "", nil, "page %d starts after sequence %d, expected %d",
				i, p.AfterSeq, expectAfter)
		}
		if p.NextAfterSeq == nil && i < len(pages)-1 {
			return bundleFail(BundlePagesOutOfOrder, hosted, "", nil, "page %d is the last page, but more follow", i)
		}
		for _, e := range p.Events {
			if e.Event.IsV2() && e.Event.Addr != want16 {
				return bundleFail(BundleSubjectMismatch, hosted, "", nil, "event %d names another address", e.Event.Sequence)
			}
		}
		if p.NextAfterSeq != nil {
			expectAfter = *p.NextAfterSeq
		}
	}
	last := pages[len(pages)-1]
	if last.NextAfterSeq != nil {
		return bundleFail(BundleIncomplete, hosted, "", nil, "the bundle stops before its last page (next_after_seq %d)",
			*last.NextAfterSeq)
	}
	if hosted {
		if o.Head == nil {
			return &BundleResult{Valid: true, Reason: "ok", Hosted: true, Head: VerdictMatch}
		}
		return bundleFail(BundleHeadRejected, true, VerdictBehind, nil,
			"a hosted identity has no chain, but DNS publishes a chain head")
	}
	var proofs []EventProof
	var links []Link
	keys := o.logKeys()
	signed := len(keys) > 0
	witnessed := o.Witnessed != nil
	anyChecked := false
	for i, p := range pages {
		var cp *TreeHead
		if p.Checkpoint != "" {
			var err error
			if len(keys) == 0 {
				cp, err = ParseCheckpointNote(p.Checkpoint)
			} else if cp, err = verifyUnder(p.Checkpoint, keys); err != nil {
				return bundleFail(BundleCheckpointUnverified, false, "", proofs,
					"page %d's checkpoint is not signed by the log key", i)
			}
			if err != nil {
				cp = nil
			}
		}
		anyProven := false
		for _, e := range p.Events {
			anyProven = anyProven || e.Proven
		}
		if anyProven && cp == nil {
			return bundleFail(BundleCheckpointUnreadable, false, "", proofs, "page %d's checkpoint is not a checkpoint note", i)
		}
		if anyProven {
			anyChecked = true
			if witnessed {
				witnessed = o.Witnessed(p.Checkpoint)
			}
		}
		for j := range p.Events {
			e := &p.Events[j]
			seq := e.Event.Sequence
			switch {
			case e.Proven:
				if !included(e, cp) {
					return bundleFail(BundleBadInclusion, false, "", proofs,
						"event %d's inclusion proof does not reach the checkpoint root", seq)
				}
				proofs = append(proofs, EventProof{seq, e.Leaf, ProofProven})
			case e.Shredded:
				proofs = append(proofs, EventProof{seq, e.Leaf, ProofShredded})
			case !e.Sequenced():
				proofs = append(proofs, EventProof{seq, -1, ProofUnsequenced})
			case cp != nil && uint64(e.Leaf) < cp.TreeSize:
				proofs = append(proofs, EventProof{seq, e.Leaf, ProofWithheld})
			default:
				proofs = append(proofs, EventProof{seq, e.Leaf, ProofUnproven})
			}
			links = append(links, e.Link())
		}
	}
	signed = signed && anyChecked
	witnessed = witnessed && signed // never "witnessed" on a log signature nobody checked
	walk := WalkChain(links)
	res := &BundleResult{Walk: &walk, Proofs: proofs, CheckpointsSigned: signed, CheckpointsWitnessed: witnessed}
	if !walk.Valid {
		res.Failure, res.Reason = BundleChainInvalid, walk.Reason
		return res
	}
	chain := "committed"
	if walk.Head.Sealed() {
		chain = "sealed"
	}
	if chain != last.KeyChain {
		res.Failure = BundleKeyChainMismatch
		res.Reason = fmt.Sprintf("the bundle says %s, but its last event is %s", last.KeyChain, chain)
		return res
	}
	var v Verdict
	if o.Head == nil {
		v = CheckAbsent(links, o.NowMillis, o.HeadSeenMillis, o.LagWindowMillis)
	} else {
		v = o.Head.Check(links, o.NowMillis, o.HeadSeenMillis, o.LagWindowMillis)
	}
	res.Head = v
	if !v.Accepted() {
		res.Failure = BundleHeadRejected
		res.Reason = "the history does not reach the published head: " + string(v)
		return res
	}
	res.Valid, res.Reason = true, "ok"
	return res
}

func included(e *BundleEvent, cp *TreeHead) bool {
	if cp == nil || e.Salt == nil || e.Leaf < 0 || uint64(e.Leaf) >= cp.TreeSize {
		return false
	}
	return VerifyInclusion(LeafHash(e.Salt, e.Event.Canonical()), uint64(e.Leaf), cp.TreeSize, e.Proof, cp.Root) == nil
}
