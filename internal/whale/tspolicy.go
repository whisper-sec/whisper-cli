// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// tspolicy.go is their policy document, typed, plus the two small parsers that make its
// grammar tractable: the `host:ports` destination and the `proto:ports` grant capability.
//
// It is deliberately tolerant. `acls` and `grants` coexist in real tailnets mid-migration,
// `src` may be a string or a list depending on who wrote the file, and a tailnet using an
// IdP has groups that are declared nowhere. Every one of those is accepted and reported,
// never guessed at.

// TSPolicy is the readable subset of their policy file. Anything we do not model is kept
// in Extra so the fidelity report can say "this file contains a section we do not read"
// rather than pretending the file was smaller than it is.
type TSPolicy struct {
	Groups        map[string]StringList      `json:"groups,omitempty"`
	TagOwners     map[string]StringList      `json:"tagOwners,omitempty"`
	Hosts         map[string]string          `json:"hosts,omitempty"`
	IPSets        map[string]StringList      `json:"ipsets,omitempty"`
	ACLs          []TSACL                    `json:"acls,omitempty"`
	Grants        []TSGrant                  `json:"grants,omitempty"`
	SSH           []TSSSHRule                `json:"ssh,omitempty"`
	NodeAttrs     []map[string]any           `json:"nodeAttrs,omitempty"`
	AutoApprovers map[string]any             `json:"autoApprovers,omitempty"`
	Postures      map[string]StringList      `json:"postures,omitempty"`
	Tests         []map[string]any           `json:"tests,omitempty"`
	SSHTests      []map[string]any           `json:"sshTests,omitempty"`
	Extra         map[string]json.RawMessage `json:"-"`
}

// TSACL is one classic ACL rule: the triple this whole fidelity question is about.
type TSACL struct {
	Action     string     `json:"action"`
	Src        StringList `json:"src"`
	Dst        StringList `json:"dst"`
	Proto      string     `json:"proto,omitempty"`
	SrcPosture StringList `json:"srcPosture,omitempty"`
}

// TSGrant is a grant rule, their newer spelling: src and dst as sets, with the capability
// carried in `ip` (network) and `app` (application).
type TSGrant struct {
	Src        StringList     `json:"src"`
	Dst        StringList     `json:"dst"`
	IP         StringList     `json:"ip,omitempty"`
	App        map[string]any `json:"app,omitempty"`
	Via        StringList     `json:"via,omitempty"`
	SrcPosture StringList     `json:"srcPosture,omitempty"`
}

// TSSSHRule is one Tailscale SSH rule. `action: check` is a re-authentication prompt with
// no equivalent anywhere in our stack, which is a fact the report states rather than
// rounds off to `accept`.
type TSSSHRule struct {
	Action      string     `json:"action"`
	Src         StringList `json:"src"`
	Dst         StringList `json:"dst"`
	Users       StringList `json:"users"`
	CheckPeriod string     `json:"checkPeriod,omitempty"`
	Recorder    StringList `json:"recorder,omitempty"`
}

// StringList accepts either a JSON string or a JSON array of strings, because both appear
// in files people actually have. It always emits an array.
type StringList []string

// UnmarshalJSON is the Postel half: one string, a list of strings, or null.
func (s *StringList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*s = nil
		return nil
	}
	if b[0] == '"' {
		var one string
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = StringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = StringList(many)
	return nil
}

// ParsePolicy reads a HuJSON policy file into TSPolicy, and returns the line count so the
// plan's header can report "policy 214 lines" the way the specimen output does.
func ParsePolicy(hujson []byte) (TSPolicy, int, error) {
	lines := bytes.Count(hujson, []byte("\n"))
	if len(bytes.TrimSpace(hujson)) > 0 {
		lines++ // a file with no trailing newline still has a last line
	}
	strict := HuJSONToJSON(hujson)
	var p TSPolicy
	if err := json.Unmarshal(strict, &p); err != nil {
		return TSPolicy{}, lines, fmt.Errorf("their policy file did not parse as HuJSON: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(strict, &raw); err == nil {
		known := map[string]bool{
			"groups": true, "tagOwners": true, "hosts": true, "ipsets": true, "acls": true,
			"grants": true, "ssh": true, "nodeAttrs": true, "autoApprovers": true,
			"postures": true, "tests": true, "sshTests": true,
		}
		for k, v := range raw {
			if !known[k] {
				if p.Extra == nil {
					p.Extra = map[string]json.RawMessage{}
				}
				p.Extra[k] = v
			}
		}
	}
	return p, lines, nil
}

// ExtraSections lists, sorted, the top-level policy sections this tool does not read.
func (p TSPolicy) ExtraSections() []string {
	var out []string
	for k := range p.Extra {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SplitDst splits a Tailscale destination into its target and its port spec.
//
// Their grammar puts the ports after the LAST colon, which is the only split that is
// correct for an IPv6 CIDR destination (`fd7a::/48:443`) as well as for `tag:prod:443`.
// A destination with no port spec at all (a grant `dst`, where the capability lives in
// `ip`) comes back with ports "".
func SplitDst(s string) (target, ports string) {
	v := strings.TrimSpace(s)
	i := strings.LastIndexByte(v, ':')
	if i < 0 {
		return v, ""
	}
	target, ports = v[:i], v[i+1:]
	// `tag:prod` and `group:eng` are two-part names, not a target with a port.
	if ports != "" && !isPortSpec(ports) {
		return v, ""
	}
	if target == "" {
		return v, ""
	}
	return target, ports
}

// isPortSpec recognises `*`, `443`, `80,443` and `1000-2000`, and nothing else. It is
// deliberately strict: mistaking `tag:prod` for a port spec would silently drop a rule's
// destination, which is the kind of quiet loss this whole tool exists to prevent.
func isPortSpec(s string) bool {
	if s == "*" {
		return true
	}
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ",") {
		if part == "" {
			return false
		}
		for _, bound := range strings.SplitN(part, "-", 2) {
			if bound == "" {
				return false
			}
			for _, r := range bound {
				if r < '0' || r > '9' {
					return false
				}
			}
		}
	}
	return true
}

// IsPortConstrained reports whether a port spec narrows anything. An empty spec and `*`
// are both "every port", and both are unconstrained.
func IsPortConstrained(ports string) bool {
	p := strings.TrimSpace(ports)
	return p != "" && p != "*"
}

// SplitProtoPorts splits a grant capability like `tcp:443`, `udp:*` or `443`. A
// capability with no protocol comes back with proto "" meaning every protocol.
func SplitProtoPorts(cap string) (proto, ports string) {
	v := strings.TrimSpace(cap)
	i := strings.LastIndexByte(v, ':')
	if i < 0 {
		if isPortSpec(v) {
			return "", v
		}
		return v, "*"
	}
	return v[:i], v[i+1:]
}
