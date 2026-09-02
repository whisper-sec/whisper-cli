// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// migratemap.go turns one tailnet into one plan. It is a pure function of its input, on
// purpose: BuildPlan takes no context, no client and no clock it did not receive, so the
// whole fidelity question is testable against a fixture with no network and no credential.
//
// The rule the whole file serves, stated once: WE NEVER SILENTLY DROP A RULE. Every
// element of their policy leaves a line in the fidelity report, whether it mapped
// perfectly, mapped approximately, mapped to something STRICTLY BROADER, or did not map at
// all. A reader who greps the report for their rule finds it, always.

// Expressiveness is what the target artifact can say. It exists because "does this rule
// widen?" is not a property of the rule, it is a property of the rule MEETING a target
// that cannot hold all of it, and writing that as data keeps the two apart.
//
// The values here are the corrected ones from finding B-30. The compiled WhaleACL
// artifact is `(srcSet, dstSet, proto, portRange, action)` plus a per-node predicate mask,
// so source, protocol and ports all survive. What does NOT survive is a HOST-dimension
// rule east-west: the kernel has no graph, no cache and no hostname, so it cannot evaluate
// one at all, and a hostname destination there can only be widened or dropped.
type Expressiveness struct {
	Name         string
	Source       bool
	Proto        bool
	Ports        bool
	HostEastWest bool
	Posture      bool
	AppLayer     bool
}

// WhaleReachability is the target this planner writes for: the compiled ACL.
var WhaleReachability = Expressiveness{
	Name:         "WhaleReachability",
	Source:       true,
	Proto:        true,
	Ports:        true,
	HostEastWest: false,
	Posture:      false,
	AppLayer:     false,
}

// The four things that are unreadable, stated BEFORE the run rather than discovered
// halfway through it. They are constants because they are properties of their API, not of
// any particular tailnet: no amount of scope makes an auth-key secret readable.
var alwaysUnreadable = []string{
	"auth-key secrets: their schema populates `key` only at creation time, so an existing key's secret cannot be read by anyone, including them",
	"node private keys: by design, and useless to us anyway because our tunnel needs a key our own peer manager has bound",
	"IdP/SCIM-synced group membership: a group exists in the API only when the policy file declares it, so a tailnet using Okta or Entra has membership the API never exposes",
	"per-node serve and funnel config: there is no /device/{id}/serve path in their schema at all, it is local tailscaled state, which is why `whisper whale migrate collect` exists",
}

// BuildOptions are the few decisions a person can make about a plan.
type BuildOptions struct {
	// Now is the plan's timestamp, injected so a test can assert a byte-identical plan.
	Now time.Time
	// CredentialFingerprint is the 12 hex the plan records. Never the credential.
	CredentialFingerprint string
	// Target is what the plan is written for. Zero value means WhaleReachability.
	Target Expressiveness
}

// BuildPlan maps a tailnet onto a plan. It returns an error only when the input cannot
// support a plan at all, because a plan built on an unread device list would migrate
// nothing while looking complete, and that is precisely the defect class this codebase
// keeps hitting.
func BuildPlan(t *Tailnet, opts BuildOptions) (*Plan, error) {
	if t == nil {
		return nil, fmt.Errorf("no tailnet was read")
	}
	if unread := t.UnreadLoadBearing(); len(unread) > 0 {
		var names []string
		for _, u := range unread {
			names = append(names, u.Section+" ("+u.Reason+")")
		}
		return nil, fmt.Errorf("refusing to plan: %s could not be read, and a plan built on that "+
			"would migrate nothing while looking complete", strings.Join(names, "; "))
	}
	if len(t.Devices) == 0 {
		return nil, fmt.Errorf("tailnet %s reports zero devices. That is either an empty tailnet or a "+
			"credential without device-read scope; either way there is nothing to plan, and this tool "+
			"will not write an empty plan that looks like a finished migration", t.Name)
	}
	target := opts.Target
	if target.Name == "" {
		target = WhaleReachability
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	p := &Plan{
		SchemaVersion:         PlanSchemaVersion,
		Tool:                  "whisper whale migrate",
		CreatedAt:             now.UTC().Format(time.RFC3339),
		Tailnet:               t.Name,
		CredentialFingerprint: opts.CredentialFingerprint,
		Unreadable:            append([]string{}, alwaysUnreadable...),
	}
	for _, u := range t.Unread {
		p.Unreadable = append(p.Unreadable,
			fmt.Sprintf("%s: not read this run (%s), so anything it governs is absent from this plan", u.Section, u.Reason))
	}

	mapNodes(t, p)
	hostAddrs := mapHosts(t, p)
	mapGroups(t, p)
	mapRules(t, p, target, hostAddrs)
	mapSSH(t, p)
	mapKeys(t, p)
	mapDNS(t, p)
	mapLeftovers(t, p)

	p.Source = SourceCounts{
		Nodes:       len(t.Devices),
		Users:       len(t.Users),
		AuthKeys:    len(t.Keys),
		PolicyLines: t.PolicyLines,
		Groups:      len(t.Policy.Groups),
		Hosts:       len(t.Policy.Hosts),
		Rules:       len(t.Policy.ACLs) + len(t.Policy.Grants),
		SSHRules:    len(t.Policy.SSH),
	}
	p.Summary = p.SummaryByClass()
	if err := p.Seal(); err != nil {
		return nil, err
	}
	return p, nil
}

// --- nodes ---------------------------------------------------------------------------

func mapNodes(t *Tailnet, p *Plan) {
	devs := append([]TSDevice(nil), t.Devices...)
	sort.Slice(devs, func(i, j int) bool {
		if devs[i].ShortName() != devs[j].ShortName() {
			return devs[i].ShortName() < devs[j].ShortName()
		}
		return devs[i].ID < devs[j].ID
	})
	used := map[string]string{} // label -> tailscale id that took it

	for _, d := range devs {
		label, exact := SanitiseLabel(d.ShortName())
		if owner, taken := used[label]; taken && owner != d.ID {
			// Two devices whose names collide once sanitised. Deterministic, and named
			// in the report, because a silently renamed node is a node someone cannot find.
			label = uniqueLabel(label, d.ID, used)
			exact = false
		}
		used[label] = d.ID

		n := PlanNode{
			TailscaleID:  d.ID,
			Hostname:     d.Hostname,
			MagicDNSName: strings.TrimSuffix(d.Name, "."),
			Label:        label,
			LabelExact:   exact,
			TailnetAddrs: d.Addresses,
			Tags:         d.Tags,
			Owner:        d.User,
			OS:           d.OS,
			SubnetRoutes: d.SubnetRoutes(),
			ExitNode:     d.IsExitNodeCandidate(),
			RoutesUnread: d.RoutesUnread,
		}
		p.Nodes = append(p.Nodes, n)

		class, detail := ClassExact, "the node's name carries over unchanged"
		if !exact {
			class = ClassApprox
			detail = fmt.Sprintf("their name %q is not a valid label here, so the identity is named %q", d.ShortName(), label)
		}
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "node", Subject: d.ShortName(), Class: class, Plane: PlaneControl,
			Detail: detail, Source: d.ID,
		})
		// The address never carries over, and saying so once per node is worth the lines:
		// it is the single fact that surprises people most about this migration.
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "node-address", Subject: d.ShortName(), Class: ClassApprox, Plane: PlaneControl,
			Detail: "their 100.64.0.0/10 address is a private CGNAT address that means nothing outside their coordination server. " +
				"This node gets a globally routable Whisper /128 instead, allocated at apply, and its canonical name is a pure " +
				"function of that address",
			Source: strings.Join(d.Addresses, ","),
		})
		if d.RoutesUnread != "" {
			p.Fidelity = append(p.Fidelity, Fidelity{
				Kind: "node-routes", Subject: d.ShortName(), Class: ClassUnmapped, Plane: PlaneControl,
				Detail: "this node's advertised routes could not be read (" + d.RoutesUnread + "), so this plan says nothing about them. That is not the same as it having none",
			})
			continue
		}
		if routes := d.SubnetRoutes(); len(routes) > 0 {
			p.Fidelity = append(p.Fidelity, Fidelity{
				Kind: "subnet-route", Subject: d.ShortName(), Class: ClassUnmapped, Plane: PlaneEastWest,
				Detail: fmt.Sprintf("%d advertised prefix(es) (%s). A subnet router is structurally impossible here today: "+
					"the server refuses any prefix but a /128, deliberately, because a range would let "+
					"one agent source another's address. Route peers are separate work",
					len(routes), strings.Join(routes, " ")),
				Source: strings.Join(routes, " "),
			})
		}
		if d.IsExitNodeCandidate() {
			p.Fidelity = append(p.Fidelity, Fidelity{
				Kind: "exit-node", Subject: d.ShortName(), Class: ClassApprox, Plane: PlaneEgress,
				Detail: "this node advertises a default route. Whisper's equivalent is the egress plane: an agent's traffic " +
					"sources from its own /128 through the Whisper SOCKS5/HTTP egress. Per-node exit selection is not the same " +
					"shape and is not planned here",
			})
		}
	}
}

// SanitiseLabel turns a Tailscale node name into a label this control plane accepts, and
// reports whether anything MEANINGFUL had to change. Lower case, letters digits and
// hyphens, no leading or trailing hyphen, at most 63 characters.
//
// Case folding alone does not count as a change: a DNS label is case-insensitive and
// lower case is its canonical spelling, so reporting "DB-01 was renamed to db-01" would be
// noise in a report whose whole value is that every line in it matters.
func SanitiseLabel(in string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(in))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if len(out) > maxLabelLen {
		out = strings.Trim(out[:maxLabelLen], "-")
	}
	if out == "" {
		out = "node"
	}
	return out, out == s
}

// uniqueLabel resolves a collision deterministically, by the device id rather than by a
// counter, so replanning the same tailnet produces the same names in any order.
func uniqueLabel(base, id string, used map[string]string) string {
	suffix := strings.ToLower(id)
	if len(suffix) > 6 {
		suffix = suffix[len(suffix)-6:]
	}
	san, _ := SanitiseLabel(suffix)
	cand := base + "-" + san
	if len(cand) > maxLabelLen {
		cand = cand[:maxLabelLen]
	}
	if _, taken := used[cand]; !taken {
		return cand
	}
	for i := 2; ; i++ {
		try := fmt.Sprintf("%s-%d", cand, i)
		if _, taken := used[try]; !taken {
			return try
		}
	}
}

// --- hosts, groups -------------------------------------------------------------------

// mapHosts records their `hosts` aliases and returns the alias-to-address map the rule
// mapper uses to tell a resolvable alias (an IP dimension) from a bare name (a HOST
// dimension the kernel cannot evaluate).
func mapHosts(t *Tailnet, p *Plan) map[string]netip.Addr {
	out := map[string]netip.Addr{}
	for _, alias := range sortedKeys(t.Policy.Hosts) {
		val := strings.TrimSpace(t.Policy.Hosts[alias])
		addr, err := netip.ParseAddr(val)
		if err != nil {
			if pfx, perr := netip.ParsePrefix(val); perr == nil {
				addr = pfx.Addr()
				err = nil
			}
		}
		if err != nil {
			p.Fidelity = append(p.Fidelity, Fidelity{
				Kind: "host", Subject: alias, Class: ClassUnmapped, Plane: PlaneControl,
				Detail: fmt.Sprintf("the alias points at %q, which is neither an address nor a prefix", val), Source: val,
			})
			continue
		}
		out[alias] = addr
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "host", Subject: alias, Class: ClassApprox, Plane: PlaneControl,
			Detail: "the alias carries over as a name, but the address behind it does not: it becomes this node's Whisper /128 at apply",
			Source: val,
		})
	}
	return out
}

func mapGroups(t *Tailnet, p *Plan) {
	declared := map[string]bool{}
	for _, g := range sortedKeys(t.Policy.Groups) {
		declared[g] = true
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "group", Subject: g, Class: ClassExact, Plane: PlaneControl,
			Detail: fmt.Sprintf("declared in the policy file with %d member(s), so it carries over as a parent anchor",
				len(t.Policy.Groups[g])),
		})
	}
	// A group referenced by a rule but declared nowhere is IdP or SCIM synced, and its
	// membership is the third of the four unreadable things.
	for _, g := range sortedKeys(referencedGroups(t.Policy)) {
		if declared[g] {
			continue
		}
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "group", Subject: g, Class: ClassUnmapped, Plane: PlaneControl,
			Detail: "referenced by a rule but declared nowhere in the policy file, which means its membership comes from an " +
				"IdP or SCIM sync. Their API never exposes that membership, so this group cannot be migrated: recreate it from your IdP",
		})
	}
	for _, tag := range sortedKeys(t.Policy.TagOwners) {
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "tag", Subject: tag, Class: ClassApprox, Plane: PlaneControl,
			Detail: "tags carry over as node labels. Tag OWNERSHIP (who may apply the tag) has no equivalent here yet: " +
				"who may register an identity is decided by API-key scope, not by the ACL document",
		})
	}
}

// referencedGroups collects every group: reference anywhere in the policy.
func referencedGroups(pol TSPolicy) map[string]struct{} {
	out := map[string]struct{}{}
	add := func(vals ...string) {
		for _, v := range vals {
			t, _ := SplitDst(v)
			if strings.HasPrefix(t, "group:") {
				out[t] = struct{}{}
			}
		}
	}
	for _, a := range pol.ACLs {
		add(a.Src...)
		add(a.Dst...)
	}
	for _, g := range pol.Grants {
		add(g.Src...)
		add(g.Dst...)
	}
	for _, s := range pol.SSH {
		add(s.Src...)
		add(s.Dst...)
	}
	for _, owners := range pol.TagOwners {
		add(owners...)
	}
	for _, members := range pol.Groups {
		add(members...)
	}
	return out
}

// --- rules ----------------------------------------------------------------------------

func mapRules(t *Tailnet, p *Plan, target Expressiveness, hostAddrs map[string]netip.Addr) {
	idx := 0
	for i, a := range t.Policy.ACLs {
		if len(a.Dst) == 0 {
			// A rule with no destination is the one shape the loop below cannot reach, and
			// a rule this tool never looked at must still leave a line: the report's whole
			// value is that grepping it for your rule always finds it. Liberal in what we
			// accept (this does not stop the plan), conservative in what we emit (it is
			// reported, never assumed harmless).
			idx++
			p.Rules = append(p.Rules, emptyRule(idx, "acls", orDefault(a.Action, "accept"), a.Src, a.Proto))
			p.Fidelity = append(p.Fidelity, noDestinationFidelity("acls", i, a.Src))
			continue
		}
		for _, dst := range a.Dst {
			idx++
			r := mapOneRule(ruleInput{
				Index: idx, From: "acls", SourceIndex: i, Action: orDefault(a.Action, "accept"),
				Src: a.Src, Dst: dst, Proto: a.Proto, SrcPosture: a.SrcPosture,
			}, target, hostAddrs)
			p.Rules = append(p.Rules, r.rule)
			p.Fidelity = append(p.Fidelity, r.fidelity...)
		}
	}
	for i, g := range t.Policy.Grants {
		caps := g.IP
		if len(caps) == 0 {
			caps = StringList{"*"}
		}
		if len(g.Dst) == 0 {
			idx++
			p.Rules = append(p.Rules, emptyRule(idx, "grants", "accept", g.Src, ""))
			p.Fidelity = append(p.Fidelity, noDestinationFidelity("grants", i, g.Src))
			continue
		}
		for _, dst := range g.Dst {
			for _, capability := range caps {
				idx++
				proto, ports := SplitProtoPorts(string(capability))
				dstTarget, dstPorts := SplitDst(dst)
				if dstPorts != "" {
					ports = dstPorts
				}
				r := mapOneRule(ruleInput{
					Index: idx, From: "grants", SourceIndex: i, Action: "accept",
					Src: g.Src, Dst: dstTarget, Proto: proto, Ports: ports,
					SrcPosture: g.SrcPosture, App: len(g.App) > 0, Via: g.Via,
				}, target, hostAddrs)
				p.Rules = append(p.Rules, r.rule)
				p.Fidelity = append(p.Fidelity, r.fidelity...)
			}
		}
	}
}

// noDestinationFidelity reports a rule that names no destination. It is not an error and
// it does not stop the plan: their file is theirs to write, and half a rule is still a
// statement of intent someone must decide about by hand.
func noDestinationFidelity(from string, index int, src StringList) Fidelity {
	return Fidelity{
		Kind: "rule", Subject: fmt.Sprintf("%s[%d] %s -> (no destination)", from, index, strings.Join(src, ",")),
		Class: ClassUnmapped, Plane: PlaneEastWest,
		Detail: "this rule names no destination, so there is nothing to compile it against and nothing is carried. " +
			"It is reported rather than skipped, because a rule that leaves no line in this report is a rule you " +
			"would never know had been dropped. Check it by hand",
	}
}

// noSourceFidelity is the same answer for the other missing half.
func noSourceFidelity(from string, index int, dst string) Fidelity {
	return Fidelity{
		Kind: "rule", Subject: fmt.Sprintf("%s[%d] (no source) -> %s", from, index, dst),
		Class: ClassUnmapped, Plane: planeFor(dst),
		Detail: "this rule names no source. A rule with no source set cannot be compiled into a source-matched rule here, " +
			"and inventing one would either admit everybody or nobody, so nothing is carried. Check it by hand",
	}
}

// emptyRule is the plan entry for a rule that was reported but not carried, so the plan's
// rule list stays a complete account of their policy rather than only of its usable half.
func emptyRule(index int, from, action string, src StringList, proto string) PlanRule {
	return PlanRule{
		Index: index, From: from, Action: action, Src: append([]string(nil), src...),
		Proto: proto, Plane: PlaneEastWest,
		Note: "not carried: the rule names no destination",
	}
}

type ruleInput struct {
	Index       int
	From        string
	SourceIndex int
	Action      string
	Src         StringList
	Dst         string
	Proto       string
	Ports       string
	SrcPosture  StringList
	App         bool
	Via         StringList
}

type mappedRule struct {
	rule     PlanRule
	fidelity []Fidelity
}

// mapOneRule is where the fidelity question is actually answered, one (src set, dst,
// capability) triple at a time.
func mapOneRule(in ruleInput, target Expressiveness, hostAddrs map[string]netip.Addr) mappedRule {
	dstTarget, dstPorts := SplitDst(in.Dst)
	ports := in.Ports
	if dstPorts != "" {
		ports = dstPorts
	}
	subject := fmt.Sprintf("%s[%d] %s -> %s", in.From, in.SourceIndex, strings.Join(in.Src, ","), in.Dst)
	plane := planeFor(dstTarget)
	rule := PlanRule{
		Index: in.Index, From: in.From, Action: in.Action, Src: append([]string(nil), in.Src...),
		Dst: dstTarget, Proto: in.Proto, Ports: ports, Plane: plane,
	}

	var (
		notes  []string
		widens []string
		fid    []Fidelity
	)

	// The other missing half. An empty source set is not "everyone" and it is not
	// "nobody"; either reading would be ours rather than theirs, so it is reported and
	// nothing is carried. Before every other question, because none of them applies to a
	// rule that cannot be compiled at all.
	if len(in.Src) == 0 {
		rule.Note = "not carried: the rule names no source"
		return mappedRule{rule: rule, fidelity: []Fidelity{noSourceFidelity(in.From, in.SourceIndex, in.Dst)}}
	}

	// 1) The HOST dimension east-west. This is the residue finding B-30 says does not go
	// away: the kernel has no hostname, so a name destination cannot be evaluated there
	// at all, and keeping the rule means keeping something broader than they wrote.
	if plane == PlaneEastWest && isHostDimension(dstTarget, hostAddrs) && !target.HostEastWest {
		widens = append(widens, fmt.Sprintf("the destination %q is a NAME, and east-west enforcement is in the kernel, "+
			"which has no resolver, no graph and no hostname. %s cannot express it, so the rule can only be carried as the "+
			"set of addresses behind that name at apply time, which is broader the moment the name moves", dstTarget, target.Name))
	}
	// 2) A source-posture predicate. We have no evaluator for the SOURCE's posture in an
	// east-west decision, so dropping it lets sources in that they were excluding.
	if len(in.SrcPosture) > 0 && !target.Posture {
		widens = append(widens, fmt.Sprintf("the rule carries srcPosture %s, and dropping a source-posture condition admits "+
			"sources their rule excluded", strings.Join(in.SrcPosture, ",")))
	}
	// 3) An application-layer grant. `app` capabilities are an application-layer
	// constraint with no evaluator here at all.
	if in.App && !target.AppLayer {
		widens = append(widens, "the grant carries an `app` capability, an application-layer constraint with no evaluator on this "+
			"side; carrying only its network half is broader than the grant they wrote")
	}
	// 4) `via`. Routing a rule through a named exit node is not a shape we have.
	if len(in.Via) > 0 {
		widens = append(widens, fmt.Sprintf("the grant is `via` %s, which pins the path through a specific node; we have no "+
			"equivalent, and a rule that does not pin the path is broader than one that does", strings.Join(in.Via, ",")))
	}
	// 5) Ports and protocol, which the compiled artifact DOES express. Recorded as an
	// approximation, not a widening, and the note says which target made that true.
	if IsPortConstrained(ports) {
		if target.Ports {
			notes = append(notes, fmt.Sprintf("the port constraint %s is carried by %s's portRange", ports, target.Name))
		} else {
			widens = append(widens, fmt.Sprintf("the port constraint %s is dropped: %s matches exactly one dimension per rule, "+
				"so a rule that pins both a destination and a port cannot be written", ports, target.Name))
		}
	}
	if in.Proto != "" && in.Proto != "*" && !target.Proto {
		widens = append(widens, fmt.Sprintf("the protocol constraint %s is dropped: %s has no protocol dimension", in.Proto, target.Name))
	}
	// 6) The source set. Their rule is a triple; a target with no source dimension turns
	// it into "anyone may reach this destination".
	if !target.Source && !isWildcardSet(in.Src) {
		widens = append(widens, fmt.Sprintf("the source set %s is dropped: %s has no source dimension, so the rule becomes "+
			"\"anyone\" rather than those sources", strings.Join(in.Src, ","), target.Name))
	}
	// 7) A deny rule. Their model is default-deny with accept rules; a `deny` action in a
	// first-match-wins list is order-sensitive and we do not reproduce their order.
	if strings.EqualFold(in.Action, "deny") {
		fid = append(fid, Fidelity{
			Kind: "rule", Subject: subject, Class: ClassUnmapped, Plane: plane,
			Detail: "this is a `deny` rule inside a first-match-wins list. Reproducing it correctly needs their evaluation " +
				"ORDER, which this plan does not reproduce, so it is not carried. Check it by hand",
			Source: in.Dst,
		})
		rule.Note = "not carried: a deny rule depends on their evaluation order"
		return mappedRule{rule: rule, fidelity: fid}
	}

	switch {
	case len(widens) > 0:
		rule.Widening = true
		rule.Note = strings.Join(widens, "; ")
		fid = append(fid, Fidelity{
			Kind: "rule", Subject: subject, Class: ClassWidening, Plane: plane,
			Detail: rule.Note, Source: in.Dst,
		})
	case len(notes) > 0:
		rule.Note = strings.Join(notes, "; ")
		fid = append(fid, Fidelity{
			Kind: "rule", Subject: subject, Class: ClassApprox, Plane: plane,
			Detail: rule.Note, Source: in.Dst,
		})
	default:
		fid = append(fid, Fidelity{
			Kind: "rule", Subject: subject, Class: ClassExact, Plane: plane,
			Detail: "the source set, the destination and the capability all carry over", Source: in.Dst,
		})
	}
	return mappedRule{rule: rule, fidelity: fid}
}

// planeFor decides where a rule is enforced. `autogroup:internet` is their spelling of
// "out to the internet", which is our egress plane and a different enforcement point
// entirely, so it must not be counted against east-west expressiveness.
func planeFor(dst string) string {
	switch strings.ToLower(strings.TrimSpace(dst)) {
	case "autogroup:internet", "0.0.0.0/0", "::/0":
		return PlaneEgress
	}
	return PlaneEastWest
}

// isHostDimension reports whether a destination is a NAME rather than something the
// kernel can match on. An address, a prefix, a tag, a group, an autogroup and a resolvable
// `hosts` alias all become address sets at compile time; a bare name does not.
func isHostDimension(dst string, hostAddrs map[string]netip.Addr) bool {
	v := strings.TrimSpace(dst)
	if v == "" || v == "*" {
		return false
	}
	if _, ok := hostAddrs[v]; ok {
		return false
	}
	if strings.HasPrefix(v, "tag:") || strings.HasPrefix(v, "group:") ||
		strings.HasPrefix(v, "autogroup:") || strings.HasPrefix(v, "ipset:") {
		return false
	}
	if _, err := netip.ParseAddr(v); err == nil {
		return false
	}
	if _, err := netip.ParsePrefix(v); err == nil {
		return false
	}
	if strings.Contains(v, "@") {
		return false // a user, which resolves to that user's nodes
	}
	return true
}

func isWildcardSet(src []string) bool {
	for _, s := range src {
		if strings.TrimSpace(s) != "*" {
			return false
		}
	}
	return len(src) > 0
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// --- ssh, keys, dns, leftovers -----------------------------------------------------

// mapSSH carries their SSH rules into the plan's `ssh` block, which is the document the
// `whale ssh` reads. `action: check` is the one that cannot carry: it is an interactive
// re-authentication prompt against their control plane, and rounding it to `accept` would
// remove somebody's second factor without saying so.
func mapSSH(t *Tailnet, p *Plan) {
	for i, s := range t.Policy.SSH {
		subject := fmt.Sprintf("ssh[%d] %s -> %s", i, strings.Join(s.Src, ","), strings.Join(s.Dst, ","))
		entry := PlanSSH{
			Index: i, Action: strings.ToLower(strings.TrimSpace(s.Action)),
			Src: s.Src, Dst: s.Dst, Users: s.Users,
		}
		switch entry.Action {
		case "check":
			entry.Note = "not carried: `check` is an interactive re-authentication against their control plane"
			p.Fidelity = append(p.Fidelity, Fidelity{
				Kind: "ssh", Subject: subject, Class: ClassUnmapped, Plane: PlaneControl,
				Detail: fmt.Sprintf("`action: check` with checkPeriod %q is an interactive re-authentication prompt served by "+
					"their coordination server. There is no equivalent here, and mapping it to `accept` would silently remove a "+
					"second factor. Carried into the plan as a rule to decide by hand", s.CheckPeriod),
			})
		case "accept":
			p.Fidelity = append(p.Fidelity, Fidelity{
				Kind: "ssh", Subject: subject, Class: ClassApprox, Plane: PlaneControl,
				Detail: "carried into the plan's `ssh` block, which is the document `whisper whale ssh` reads. The host key is " +
					"verified from the IANA DNSSEC root by the client rather than by a coordination server, and the principal " +
					"decision is made on the target host itself, by the AuthorizedKeysCommand the agent installs",
			})
		default:
			entry.Note = "not carried: unrecognised action"
			p.Fidelity = append(p.Fidelity, Fidelity{
				Kind: "ssh", Subject: subject, Class: ClassUnmapped, Plane: PlaneControl,
				Detail: fmt.Sprintf("unrecognised ssh action %q", s.Action),
			})
		}
		if len(s.Recorder) > 0 {
			p.Fidelity = append(p.Fidelity, Fidelity{
				Kind: "ssh-recorder", Subject: subject, Class: ClassUnmapped, Plane: PlaneControl,
				Detail: "the rule names a session recorder. Session recording is not part of this migration",
			})
		}
		p.SSH = append(p.SSH, entry)
	}
}

func mapKeys(t *Tailnet, p *Plan) {
	for _, k := range t.Keys {
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "auth-key", Subject: firstNonEmpty(k.Description, k.ID), Class: ClassUnmapped, Plane: PlaneControl,
			Detail: "auth-key SECRETS CANNOT BE MIGRATED: their schema populates `key` only at creation time, so the secret is " +
				"unreadable by anyone including them. The key's metadata is here; mint a fresh Whisper credential for whatever used it",
			Source: k.ID,
		})
	}
	// Serve and funnel, said once, up front, because it is the fourth unreadable thing and
	// the reason `migrate collect` exists at all.
	p.Fidelity = append(p.Fidelity, Fidelity{
		Kind: "serve-funnel", Subject: "all nodes", Class: ClassUnmapped, Plane: PlaneControl,
		Detail: "per-node serve and funnel configuration is not in their API at all: there is no /device/{id}/serve path in the " +
			"schema. It is local tailscaled state. Run `whisper whale migrate collect` ON each node to capture it",
	})
}

func mapDNS(t *Tailnet, p *Plan) {
	if len(t.DNS.Nameservers) > 0 {
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "dns", Subject: "nameservers", Class: ClassApprox, Plane: PlaneControl,
			Detail: "global nameservers become your tenant's resolver policy. The shapes are not identical: ours is a policy " +
				"applied per tenant and per device, not a list of servers handed to a node",
			Source: strings.Join(t.DNS.Nameservers, " "),
		})
	}
	for _, domain := range sortedKeys(t.DNS.SplitDNS) {
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "dns", Subject: "splitDNS " + domain, Class: ClassUnmapped, Plane: PlaneControl,
			Detail: "per-domain nameserver selection has no equivalent: our per-tenant resolution policy decides how a name " +
				"resolves, not which server answers it. This one is theirs on that knob",
			Source: strings.Join(t.DNS.SplitDNS[domain], " "),
		})
	}
	if len(t.DNS.SearchPaths) > 0 {
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "dns", Subject: "searchPaths", Class: ClassUnmapped, Plane: PlaneControl,
			Detail: "search domains for member names are not built here yet; a single-label name does not resolve",
			Source: strings.Join(t.DNS.SearchPaths, " "),
		})
	}
}

// mapLeftovers names every policy section we did not read, so the report's silence is
// never mistaken for a file that did not contain them.
func mapLeftovers(t *Tailnet, p *Plan) {
	if len(t.Policy.NodeAttrs) > 0 {
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "nodeAttrs", Subject: fmt.Sprintf("%d entries", len(t.Policy.NodeAttrs)), Class: ClassUnmapped,
			Plane: PlaneControl, Detail: "node attributes (funnel, exit-node, app-connector and the rest) are per-feature flags with no single equivalent",
		})
	}
	if len(t.Policy.Postures) > 0 {
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "postures", Subject: fmt.Sprintf("%d postures", len(t.Policy.Postures)), Class: ClassUnmapped,
			Plane: PlaneControl, Detail: "posture definitions have no evaluator on this side yet; any rule that used one is reported as widening",
		})
	}
	if len(t.Policy.AutoApprovers) > 0 {
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "autoApprovers", Subject: "autoApprovers", Class: ClassUnmapped, Plane: PlaneControl,
			Detail: "auto-approval of routes and exit nodes has nothing to approve here: subnet routes do not carry over",
		})
	}
	if n := len(t.Policy.Tests) + len(t.Policy.SSHTests); n > 0 {
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "tests", Subject: fmt.Sprintf("%d tests", n), Class: ClassUnmapped, Plane: PlaneControl,
			Detail: "their ACL tests do not carry over as written. The WhaleACL document has its own mandatory tests block, and " +
				"a failing test rejects the write, so re-express them there",
		})
	}
	for _, section := range t.Policy.ExtraSections() {
		p.Fidelity = append(p.Fidelity, Fidelity{
			Kind: "policy-section", Subject: section, Class: ClassUnmapped, Plane: PlaneControl,
			Detail: "their policy file contains this top-level section and this tool does not read it. It is named here so its " +
				"absence from the plan is visible rather than silent",
		})
	}
}
