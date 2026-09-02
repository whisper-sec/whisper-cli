// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// migrateplan.go is the plan file: the artifact that stands between reading their tailnet
// and writing ours.
//
// Three properties are load-bearing and each is enforced here rather than by convention.
//
// 1. It is a DRY RUN made durable. `plan` produces this file and touches nothing else,
// on either side. Everything `apply` will do is enumerated in it first, in the order
// it will happen, so a person can read the whole change before any of it happens.
//
// 2. It contains no secret. The Tailscale credential is represented by 12 hex of its
// SHA-256 and by nothing else, and Credential.MarshalJSON refuses to be written at
// all, so this is enforced by the type and not by review.
//
// 3. Its Hash covers the PLANNED half and not the applied half. Receipts and the
// widening acknowledgement are appended by `apply` to the same file, and appending
// them must not invalidate the hash, or a resumed apply could not verify the plan it
// is resuming. So the hash is taken over the body with those three fields zeroed, and
// `status` recomputes it to prove the plan was not edited underneath a half-finished
// apply.

// PlanSchemaVersion is bumped when the on-disk shape changes incompatibly. `apply` refuses
// a plan from a future schema rather than half-understanding it.
const PlanSchemaVersion = 1

// FidelityClass is what happened to one thing we read.
type FidelityClass string

const (
	// ClassExact: it carried over with no loss.
	ClassExact FidelityClass = "EXACT"
	// ClassApprox: it carried over into something that is not identical, and Detail says how.
	ClassApprox FidelityClass = "APPROX"
	// ClassWidening: what we can express is STRICTLY BROADER than what they had. This is
	// the one that needs consent, because emitting it silently would be a quiet loosening
	// of somebody's security posture.
	ClassWidening FidelityClass = "APPROX-WIDENING"
	// ClassUnmapped: it does not carry over at all, and Detail says why.
	ClassUnmapped FidelityClass = "UNMAPPED"
)

// Plane names where a rule is enforced, because the answer differs by plane and a report
// that averages them is useless. The kernel has no graph, no cache and no hostname, so a
// HOST-dimension rule is structurally unenforceable east-west whatever the document says.
const (
	PlaneEastWest = "east-west"
	PlaneEgress   = "egress"
	PlaneControl  = "control"
)

// Fidelity is one line of the report: what we read, what became of it, and why.
type Fidelity struct {
	Kind    string        `json:"kind"`
	Subject string        `json:"subject"`
	Class   FidelityClass `json:"class"`
	Plane   string        `json:"plane,omitempty"`
	Detail  string        `json:"detail"`
	Source  string        `json:"source,omitempty"`
}

// PlanNode is one of their devices, and the identity we will ask for on its behalf.
type PlanNode struct {
	TailscaleID  string   `json:"tailscale_id"`
	Hostname     string   `json:"hostname"`
	MagicDNSName string   `json:"magicdns_name,omitempty"`
	Label        string   `json:"label"`
	LabelExact   bool     `json:"label_exact"`
	TailnetAddrs []string `json:"tailnet_addresses,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Owner        string   `json:"owner,omitempty"`
	OS           string   `json:"os,omitempty"`
	SubnetRoutes []string `json:"subnet_routes,omitempty"`
	ExitNode     bool     `json:"exit_node,omitempty"`
	RoutesUnread string   `json:"routes_unread,omitempty"`
}

// PlanRule is one of their ACL or grant rules, as we would write it.
type PlanRule struct {
	Index    int      `json:"index"`
	From     string   `json:"from"` // "acls" | "grants"
	Action   string   `json:"action"`
	Src      []string `json:"src"`
	Dst      string   `json:"dst"`
	Proto    string   `json:"proto,omitempty"`
	Ports    string   `json:"ports,omitempty"`
	Plane    string   `json:"plane"`
	Widening bool     `json:"widening"`
	Note     string   `json:"note,omitempty"`
}

// PlanSSH is one of their SSH rules, mapped onto the `ssh` block the `whale ssh` reads.
type PlanSSH struct {
	Index  int      `json:"index"`
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
	Users  []string `json:"users"`
	Note   string   `json:"note,omitempty"`
}

// SourceCounts is the header line of the specimen output, kept as data.
type SourceCounts struct {
	Nodes       int `json:"nodes"`
	Users       int `json:"users"`
	AuthKeys    int `json:"auth_keys"`
	PolicyLines int `json:"policy_lines"`
	Groups      int `json:"groups"`
	Hosts       int `json:"hosts"`
	Rules       int `json:"rules"`
	SSHRules    int `json:"ssh_rules"`
}

// Undo is the exact call that reverses one applied step.
type Undo struct {
	Op   string         `json:"op"`
	Args map[string]any `json:"args,omitempty"`
	Note string         `json:"note,omitempty"`
}

// Receipt is one thing `apply` did, in the order it did it. `rollback` walks these in
// reverse. A receipt is written for a REFUSED step too, because "we tried and the control
// plane said no" is the answer a resumed run needs.
type Receipt struct {
	Seq          int    `json:"seq"`
	Step         string `json:"step"`
	Subject      string `json:"subject"`
	At           string `json:"at"`
	Result       string `json:"result"`
	Agent        string `json:"agent,omitempty"`
	Address      string `json:"address,omitempty"`
	FQDN         string `json:"fqdn,omitempty"`
	Detail       string `json:"detail,omitempty"`
	Undo         *Undo  `json:"undo,omitempty"`
	RolledBackAt string `json:"rolled_back_at,omitempty"`
}

// Applied reports whether this receipt represents a change that is live and undoable.
func (r Receipt) Applied() bool {
	return (r.Result == ResultApplied || r.Result == ResultExisting) && r.RolledBackAt == ""
}

// The receipt result vocabulary, closed on purpose.
const (
	// ResultApplied: we made the change.
	ResultApplied = "applied"
	// ResultExisting: it was already so, and we changed nothing. This is what makes a
	// second `apply` a no-op rather than a second identity.
	ResultExisting = "existing"
	// ResultRefused: the control plane refused, and Detail carries its words.
	ResultRefused = "refused"
)

// Plan is the whole artifact.
type Plan struct {
	SchemaVersion int          `json:"schema_version"`
	Tool          string       `json:"tool"`
	CreatedAt     string       `json:"created_at"`
	Tailnet       string       `json:"tailnet"`
	Source        SourceCounts `json:"source"`
	// CredentialFingerprint is the first 12 hex of the SHA-256 of the Tailscale
	// credential that produced this plan. It is here so `apply` can refuse a plan made
	// with a different credential, and it is 48 bits so it can do that and nothing else.
	CredentialFingerprint string `json:"credential_fingerprint"`

	Unreadable []string       `json:"unreadable"`
	Nodes      []PlanNode     `json:"nodes"`
	Rules      []PlanRule     `json:"rules"`
	SSH        []PlanSSH      `json:"ssh,omitempty"`
	Fidelity   []Fidelity     `json:"fidelity"`
	Summary    map[string]int `json:"summary"`

	// Hash covers everything above. Everything below is written by `apply`.
	Hash string `json:"hash"`

	AcceptedWidening   bool      `json:"accepted_widening"`
	AcceptedWideningAt string    `json:"accepted_widening_at,omitempty"`
	Receipts           []Receipt `json:"receipts,omitempty"`
}

// WideningRules counts the rules whose mapping is strictly broader than the source.
func (p *Plan) WideningRules() int {
	n := 0
	for _, r := range p.Rules {
		if r.Widening {
			n++
		}
	}
	return n
}

// HasWidening reports whether this plan cannot be applied without explicit consent.
func (p *Plan) HasWidening() bool { return p.WideningRules() > 0 }

// ComputeHash returns the SHA-256 of WHAT is planned.
//
// Four fields are excluded and each for its own reason. The three that `apply` writes
// (the widening consent, its timestamp and the receipts) are excluded so that appending a
// receipt does not invalidate the hash, which is what lets a resumed apply verify the plan
// it is resuming. CreatedAt is excluded because it records WHEN the tailnet was read, not
// what was read: with it in, two plans of an unchanged tailnet would hash differently and
// the hash could not be used to prove that replanning found nothing new.
func (p *Plan) ComputeHash() (string, error) {
	body := *p
	body.Hash = ""
	body.CreatedAt = ""
	body.AcceptedWidening = false
	body.AcceptedWideningAt = ""
	body.Receipts = nil
	b, err := json.Marshal(&body)
	if err != nil {
		return "", fmt.Errorf("hashing the plan: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Seal computes and stores the hash. `plan` calls it once, at the end.
func (p *Plan) Seal() error {
	h, err := p.ComputeHash()
	if err != nil {
		return err
	}
	p.Hash = h
	return nil
}

// VerifyHash reports whether the planned half still hashes to what it claims.
func (p *Plan) VerifyHash() error {
	if strings.TrimSpace(p.Hash) == "" {
		return fmt.Errorf("this plan carries no hash, so nothing can vouch that it is the plan that was reviewed")
	}
	h, err := p.ComputeHash()
	if err != nil {
		return err
	}
	if h != p.Hash {
		return fmt.Errorf("this plan file has been edited since it was written: it records hash %s and now hashes to %s. "+
			"Re-run `whisper whale migrate plan` rather than applying a plan nobody reviewed", short12(p.Hash), short12(h))
	}
	return nil
}

// NextSeq is the sequence number of the next receipt.
func (p *Plan) NextSeq() int {
	n := 0
	for _, r := range p.Receipts {
		if r.Seq > n {
			n = r.Seq
		}
	}
	return n + 1
}

// ReceiptFor returns the last receipt for one step and subject, which is how `apply`
// knows a step is already done and how `rollback` knows it is already undone.
func (p *Plan) ReceiptFor(step, subject string) (Receipt, bool) {
	for i := len(p.Receipts) - 1; i >= 0; i-- {
		if p.Receipts[i].Step == step && p.Receipts[i].Subject == subject {
			return p.Receipts[i], true
		}
	}
	return Receipt{}, false
}

// Record appends a receipt with the next sequence number and the current time.
func (p *Plan) Record(r Receipt) Receipt {
	r.Seq = p.NextSeq()
	if r.At == "" {
		r.At = time.Now().UTC().Format(time.RFC3339)
	}
	p.Receipts = append(p.Receipts, r)
	return r
}

// SummaryByClass counts the fidelity lines by class, for the report and for the
// `jq '.summary'` a person will reach for.
func (p *Plan) SummaryByClass() map[string]int {
	out := map[string]int{}
	for _, f := range p.Fidelity {
		out[string(f.Class)]++
	}
	return out
}

// --- file IO -----------------------------------------------------------------------

// SavePlan writes the plan atomically, mode 0600.
//
// 0600 is not because it holds a secret (it must not, and the type system says so) but
// because it holds a complete map of somebody's fleet, which is not a world-readable
// thing to leave in a working directory. The write is temp-then-rename so an interrupted
// apply can never leave a truncated plan: the file is either the old one or the new one.
func SavePlan(path string, p *Plan) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("serialising the plan: %w", err)
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".whalenet-plan-*")
	if err != nil {
		return fmt.Errorf("writing the plan next to %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // a no-op once the rename succeeded
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("setting mode 0600 on the plan: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("writing the plan: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("flushing the plan to disk: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing the plan: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("moving the plan into place at %s: %w", path, err)
	}
	return nil
}

// LoadPlan reads a plan and refuses one it cannot fully understand.
func LoadPlan(path string) (*Plan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no plan at %s: run `whisper whale migrate plan --tailnet <name> -o %s` first",
				path, filepath.Base(path))
		}
		return nil, fmt.Errorf("reading the plan at %s: %w", path, err)
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("the plan at %s is not a whalenet plan file: %w", path, err)
	}
	if p.SchemaVersion == 0 {
		return nil, fmt.Errorf("the file at %s carries no schema_version, so it is not a whalenet plan", path)
	}
	if p.SchemaVersion > PlanSchemaVersion {
		return nil, fmt.Errorf("the plan at %s is schema version %d and this build understands %d: upgrade the CLI rather than applying a plan it half-understands",
			path, p.SchemaVersion, PlanSchemaVersion)
	}
	return &p, nil
}

// short12 trims a hash for a human-readable line, without pretending it is the whole hash.
func short12(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "..."
}

// sortedKeys is the small determinism helper the mapper uses everywhere: a plan built
// twice from the same tailnet must be byte-identical, or its hash means nothing.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
