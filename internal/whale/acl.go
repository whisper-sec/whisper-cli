// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"errors"
	"sort"
	"strconv"
	"strings"
)

// acl.go is the pure half of `whisper whale acl`: the shape of the ACL
// document as the control plane reads it back, and the one local check that must happen
// before a document is sent anywhere.
//
// Nothing here talks to the network. The control plane is the authority on the grammar,
// and this file deliberately does not re-implement it: a document this file cannot read
// is passed on for the strict parser to judge, never refused locally. Postel, at the
// boundary between an operator's file and the wire.

// ACLSummary is the whale.acl.* half of an op:policy read, gathered into one value.
//
// Every field is a string because every cell the control plane emits is a string, and
// re-typing them here would invent a second contract that could drift from the first.
// Published is the one derived fact, and it is derived from the presence of the hash
// rather than from an empty document, because a tenant with no document at all and a
// tenant whose document failed to read back are different states.
type ACLSummary struct {
	Published   bool     `json:"published"`
	Hash        string   `json:"hash,omitempty"`
	Version     string   `json:"version,omitempty"`
	Artifact    string   `json:"artifact,omitempty"`
	Default     string   `json:"default,omitempty"`
	Nodes       string   `json:"nodes,omitempty"`
	Clauses     string   `json:"clauses,omitempty"`
	ConnectOnly string   `json:"clauses_connect_only,omitempty"`
	Refusals    string   `json:"refusals,omitempty"`
	LastRefusal string   `json:"last_refusal,omitempty"`
	Notes       []string `json:"notes,omitempty"`
	Document    string   `json:"document,omitempty"`
}

// ACLSummaryFrom reads the whale.acl.* cells out of an op:policy key/value result.
//
// It takes ORDERED pairs rather than a map because the notes are numbered
// (whale.acl.note.0, .1, .2) and an operator reading "default is deny and no grant names
// autogroup:internet" wants them in the order the compiler produced them. A map would
// shuffle that, and the numbers are not guaranteed to be dense, so the order is restored
// from the suffix rather than assumed from the iteration.
func ACLSummaryFrom(pairs [][2]string) ACLSummary {
	var s ACLSummary
	type note struct {
		idx  int
		text string
	}
	var notes []note
	for _, kv := range pairs {
		k, v := kv[0], kv[1]
		if !strings.HasPrefix(k, "whale.acl.") {
			continue
		}
		switch k {
		case "whale.acl.hash":
			s.Hash = v
			s.Published = v != ""
		case "whale.acl.version":
			s.Version = v
		case "whale.acl.artifact":
			s.Artifact = v
		case "whale.acl.default":
			s.Default = v
		case "whale.acl.nodes":
			s.Nodes = v
		case "whale.acl.clauses":
			s.Clauses = v
		case "whale.acl.clauses.connect_only":
			s.ConnectOnly = v
		case "whale.acl.refusals":
			s.Refusals = v
		case "whale.acl.last_refusal":
			s.LastRefusal = v
		case "whale.acl.document":
			s.Document = v
		default:
			if rest, ok := strings.CutPrefix(k, "whale.acl.note."); ok {
				n, err := strconv.Atoi(rest)
				if err != nil {
					n = len(notes) // an unnumbered note keeps its arrival order
				}
				notes = append(notes, note{idx: n, text: v})
			}
		}
	}
	sort.SliceStable(notes, func(i, j int) bool { return notes[i].idx < notes[j].idx })
	for _, n := range notes {
		s.Notes = append(s.Notes, n.text)
	}
	return s
}

// ErrSilentFleetWideDeny is returned by CheckACLDocument for the one document shape that
// is catastrophic and silent at the same time.
var ErrSilentFleetWideDeny = errors.New("this document has no grants and does not say what to do " +
	"with the traffic they would have covered, so publishing it would refuse EVERY flow for EVERY " +
	"node in your fleet.\n\nSay which you mean:\n" +
	"  whisper whale acl withdraw          leave the fleet ungoverned\n" +
	`  add "default": "deny"               lock it down on purpose` + "\n" +
	"  add the grants you meant to write")

// CheckACLDocument refuses, locally, the one document that reads as "no policy" and
// means "deny everything": `{}`. An empty document grants no flow, so it denies every
// flow.
//
// The control plane refuses it too, and that server-side guard is the one that counts.
// This exists beside it because a refusal that arrives before the request is a better
// refusal than one that arrives after it, and because an operator should not have to
// know which build is answering to know what will happen.
//
// It is deliberately conservative in both directions. A document with any grant at all
// is passed through untouched. A document this function cannot parse is ALSO passed
// through untouched, because the control plane's HuJSON reader is more liberal than this
// one (single quotes, unquoted keys) and a local parser that refused what the server
// would have accepted would be resistance we invented ourselves.
func CheckACLDocument(raw []byte) error {
	p, _, err := ParsePolicy(raw)
	if err != nil {
		return nil // not ours to judge: the strict parser on the box will say so, in its own words
	}
	if len(p.Grants) > 0 || len(p.ACLs) > 0 {
		return nil
	}
	if _, stated := p.Extra["default"]; stated {
		return nil // an explicit lock-down, obeyed
	}
	return ErrSilentFleetWideDeny
}

// ACLTestVerdict is one row of an ACL dry run: what the compiled artifact says about one
// (source, destination) pair, and which clause said it.
type ACLTestVerdict struct {
	Src     string `json:"src"`
	SrcName string `json:"src_name,omitempty"`
	Dst     string `json:"dst"`
	Proto   string `json:"proto,omitempty"`
	Port    string `json:"port,omitempty"`
	Verdict string `json:"verdict"`
	Why     string `json:"why,omitempty"`
}

// Denied reports whether this verdict refuses the flow. It reads the word rather than a
// boolean because the control plane emits the word, and a boolean here would be a second
// spelling of the same fact.
func (v ACLTestVerdict) Denied() bool {
	return strings.EqualFold(strings.TrimSpace(v.Verdict), "deny")
}
