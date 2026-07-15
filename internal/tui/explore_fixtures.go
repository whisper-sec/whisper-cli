// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

// Realistic FIXTURE decks for EXPLORE Phase 1: they feed the golden render tests AND the
// live tab (so the frame is beautiful and correct at every width before any network code
// exists). Every value here is invented for the prototype; nothing is fetched.

// --- small node constructors -----------------------------------------------------------

func host(value, band string) graphNode {
	return graphNode{Labels: []string{"HOSTNAME"}, Value: value, Band: band}
}

func ipv4(value, band string, id *identity) graphNode {
	return graphNode{Labels: []string{"IPV4"}, Value: value, Band: band, Ident: id}
}

func ipv6(value, band string, id *identity) graphNode {
	return graphNode{Labels: []string{"IPV6"}, Value: value, Band: band, Ident: id}
}

func node(label, value, band string) graphNode {
	return graphNode{Labels: []string{label}, Value: value, Band: band}
}

func cfIdent() *identity {
	return &identity{ASN: "AS13335", ASName: "CLOUDFLARENET", Country: "US",
		Prefix: "104.16.128.0/20", Hosts: "~1.24M"}
}

// --- SCREEN 1: land on cloudflare.com ---------------------------------------------------

func fixtureCloudflare() deckState {
	focus := graphNode{
		Labels: []string{"HOSTNAME"},
		Value:  "cloudflare.com",
		Band:   "BENIGN",
		Props: map[string]any{
			"sub":        "apex cloudflare.com · TLD .com · dnssec ✓",
			"first_seen": "2010-07-01",
			"registrar":  "MarkMonitor",
		},
		Ident: &identity{Vendor: "Cloudflare, Inc.", Roles: []string{"CDN", "DNS", "WAF"}, Coverage: 0.98, Feeds: 5},
	}
	edges := []edgeGroup{
		{Type: "RESOLVES_TO", Dir: 1, Total: 4, Sample: []graphNode{
			ipv4("104.16.132.229", "BENIGN", cfIdent()),
			ipv4("104.16.133.229", "BENIGN", cfIdent()),
			ipv6("2606:4700::6810", "BENIGN", cfIdent()),
			ipv4("172.64.32.1", "BENIGN", cfIdent()),
		}},
		{Type: "NAMESERVER_FOR", Dir: 1, Total: 2, Sample: []graphNode{
			host("ns1.cloudflare.com", "BENIGN"),
			host("ns2.cloudflare.com", "BENIGN"),
		}},
		{Type: "LINKS_TO", Dir: 1, Total: 1204881, Capped: true, Sample: []graphNode{
			host("blog.cloudflare.com", "BENIGN"),
			host("developers.cloudflare.com", "BENIGN"),
		}},
		{Type: "HAS_EMAIL", Dir: 1, Total: 1, Sample: []graphNode{
			node("EMAIL", "dns@cloudflare.com", "BENIGN"),
		}},
		{Type: "EMITS_TLS_FP", Dir: 1, Total: 4, Sample: []graphNode{
			node("TLS_FP", "ja3:cd08e31494f9…", ""),
		}},
		{Type: "HAS_ORGANIZATION", Dir: 1, Total: 1, Sample: []graphNode{
			node("ORGANIZATION", "Cloudflare, Inc.", "BENIGN"),
		}},
	}
	return deckState{focus: focus, edges: edges, edgeCur: 0}
}

// --- the DEFAULT landing: whisper.security ----------------------------------------
// The keyless EXPLORE demo opens here - our own front door, dog-fooding the graph on the
// domain that serves it. RESOLVES_TO links onto the mega fan-out deck so the guided
// Phase-1 walk (enter on the first neighbour) still tells the whole story.

func fixtureWhisperSecurity() deckState {
	focus := graphNode{
		Labels: []string{"HOSTNAME"},
		Value:  "whisper.security",
		Band:   "BENIGN",
		Props: map[string]any{
			"sub":        "apex whisper.security · TLD .security · dnssec ✓",
			"first_seen": "2025-11-14",
			"registrar":  "Gandi SAS",
		},
		Ident: &identity{Vendor: "Whisper Security (viaGraph B.V.)",
			Roles: []string{"security graph", "DNS", "agent identity"}, Coverage: 0.99, Feeds: 5},
	}
	edges := []edgeGroup{
		{Type: "RESOLVES_TO", Dir: 1, Total: 2, Sample: []graphNode{
			ipv4("104.16.132.229", "BENIGN", cfIdent()),
			ipv6("2606:4700::6810", "BENIGN", cfIdent()),
		}},
		{Type: "NAMESERVER_FOR", Dir: 1, Total: 2, Sample: []graphNode{
			host("chloe.ns.cloudflare.com", "BENIGN"),
			host("rustam.ns.cloudflare.com", "BENIGN"),
		}},
		{Type: "LINKS_TO", Dir: 1, Total: 3, Sample: []graphNode{
			host("graph.whisper.security", "BENIGN"),
			host("whisper.online", "BENIGN"),
			host("docs.whisper.online", "BENIGN"),
		}},
		{Type: "HAS_EMAIL", Dir: 1, Total: 1, Sample: []graphNode{
			node("EMAIL", "hello@whisper.security", "BENIGN"),
		}},
		{Type: "HAS_ORGANIZATION", Dir: 1, Total: 1, Sample: []graphNode{
			node("ORGANIZATION", "viaGraph B.V.", "BENIGN"),
		}},
	}
	return deckState{focus: focus, edges: edges, edgeCur: 0}
}

// --- SCREEN 2: mid-traversal onto a mega fan-out IPv4 -----------------------------------

func fixtureMegaFanout() deckState {
	focus := graphNode{
		Labels: []string{"IPV4"},
		Value:  "104.16.132.229",
		Band:   "BENIGN",
		Props: map[string]any{
			"sub":  "AS13335 CLOUDFLARENET · US · 104.16.128.0/20",
			"mega": true,
			"note": "route anycast · no-MOAS · ROA valid ✓ · Tor: no",
		},
		Ident: &identity{Vendor: "Cloudflare, Inc.", Roles: []string{"CDN"}, Coverage: 0.97, Feeds: 5,
			ASN: "AS13335", ASName: "CLOUDFLARENET", Country: "US", Prefix: "104.16.128.0/20", Hosts: "~1.24M"},
	}
	edges := []edgeGroup{
		{Type: "ANNOUNCED_BY", Dir: 1, Total: 1, Sample: []graphNode{node("ASN", "AS13335", "BENIGN")}},
		{Type: "IN_PREFIX", Dir: 1, Total: 1, Sample: []graphNode{node("PREFIX", "104.16.128.0/20", "BENIGN")}},
		{Type: "RESOLVES_TO⁻¹", Dir: -1, Total: 1240000, Capped: true, Sample: []graphNode{
			hostIdent("glitch-me.tk", "MALICIOUS", "listed urlhaus, phishtank"),
			hostIdent("promo-track.xyz", "SUSPICIOUS", "aggressive ad-tracker"),
			hostIdent("discord.com", "BENIGN", "shared CDN front: SHARED not RELATED"),
			hostIdent("patreon.com", "BENIGN", "shared CDN front: SHARED not RELATED"),
		}},
		{Type: "EMITS_TLS_FP", Dir: 1, Total: 41, Sample: []graphNode{node("TLS_FP", "ja3:7c02…", "")}},
		{Type: "GEO_LOCATED", Dir: 1, Total: 1, Sample: []graphNode{node("ORGANIZATION", "US · 37.7,-122.4", "")}},
		{Type: "HAS_PTR", Dir: 1, Total: 1, Sample: []graphNode{node("PTR", "1.1.1.1.in-addr.arpa", "")}},
	}
	return deckState{
		trail:   []graphNode{host("cloudflare.com", "BENIGN")},
		focus:   focus,
		edges:   edges,
		edgeCur: 2, // the reverse mega fan-out is the lit edge
	}
}

func hostIdent(value, band, note string) graphNode {
	return graphNode{Labels: []string{"HOSTNAME"}, Value: value, Band: band, Ident: &identity{Note: note}}
}

// --- ASN bipartite focus ---------------------------------------------------------------

func fixtureASN() deckState {
	focus := graphNode{
		Labels: []string{"ASN"},
		Value:  "AS13335",
		Band:   "BENIGN",
		Props: map[string]any{
			"sub": "CLOUDFLARENET · originates 1,512 prefixes",
		},
		Ident: &identity{Vendor: "Cloudflare, Inc.", ASN: "AS13335", ASName: "CLOUDFLARENET", Country: "US"},
	}
	edges := []edgeGroup{
		{Type: "ORIGINATES", Dir: 1, Total: 1512, Sample: []graphNode{
			node("PREFIX", "104.16.0.0/13", "BENIGN"),
			node("PREFIX", "172.64.0.0/13", "BENIGN"),
			node("PREFIX", "2606:4700::/32", "BENIGN"),
		}},
		{Type: "PEERS_WITH", Dir: 1, Total: 8231, Sample: []graphNode{
			node("ASN", "AS15169", "BENIGN"),
			node("ASN", "AS3356", "BENIGN"),
		}},
		{Type: "MEMBER_OF", Dir: 0, Total: 3, Sample: []graphNode{node("ASN", "AS-CLOUDFLARE", "BENIGN")}},
		{Type: "ANNOUNCED_BY⁻¹", Dir: -1, Total: 1240000, Capped: true, Sample: []graphNode{
			ipv4("104.16.132.229", "BENIGN", cfIdent()),
			ipv4("104.16.133.229", "BENIGN", cfIdent()),
		}},
		{Type: "GEO_LOCATED", Dir: 1, Total: 1, Sample: []graphNode{node("ORGANIZATION", "US", "")}},
	}
	return deckState{focus: focus, edges: edges, edgeCur: 0}
}

// --- SCREEN 5: a sparse / UNKNOWN node --------------------------------------------------

func fixtureSparse() deckState {
	focus := graphNode{
		Labels: []string{"IPV4"},
		Value:  "198.51.100.7",
		Band:   "UNKNOWN",
		Props: map[string]any{
			"sub":        "AS64500 EXAMPLE-DOC · no geo · Tor: unknown",
			"first_seen": "2026-05-02",
		},
	}
	edges := []edgeGroup{
		{Type: "IN_PREFIX", Dir: 1, Total: 1, Sample: []graphNode{
			node("PREFIX", "198.51.100.0/24", "UNKNOWN"),
		}},
	}
	return deckState{focus: focus, edges: edges, edgeCur: 0}
}

// --- SCREEN 3: a catalog RESULT (assess band + variants ranked table) -------------------

func fixtureCatalog() (deckState, []resultCard) {
	focus := graphNode{
		Labels: []string{"HOSTNAME"},
		Value:  "paypal.com",
		Band:   "BENIGN",
		Props:  map[string]any{"sub": "apex paypal.com · TLD .com · dnssec ✓"},
		Ident:  &identity{Vendor: "PayPal, Inc.", Roles: []string{"payments"}, Coverage: 0.94, Feeds: 4},
	}
	deck := deckState{focus: focus, edges: []edgeGroup{
		{Type: "RESOLVES_TO", Dir: 1, Total: 6, Sample: []graphNode{ipv4("151.101.0.0", "BENIGN", nil)}},
		{Type: "VARIANT_OF⁻¹", Dir: -1, Total: 47, Sample: []graphNode{host("paypa1.com", "MALICIOUS")}},
	}}
	return deck, []resultCard{fixtureAssessCard(focus.Value), fixtureVariantsCard(focus.Value)}
}

func fixtureAssessCard(target string) resultCard {
	return resultCard{
		Verb:     "whisper.assess(" + target + ")",
		Shape:    shapeBand,
		MS:       214,
		Rows:     1,
		Band:     "BENIGN",
		Coverage: 0.94,
		Label:    "benign · brand-verified",
		Evidence: "PSL-apex · 4 feeds · WHOIS 25y",
		Cypher:   "CALL whisper.assess(['" + target + "']) YIELD band, coverage",
	}
}

func fixtureVariantsCard(target string) resultCard {
	return resultCard{
		Verb:  "whisper.variants(" + target + ")",
		Shape: shapeRanked,
		MS:    47,
		Rows:  47,
		Table: []resultRow{
			{Name: "paypa1.com", Method: "homoglyph", Conf: 0.97, Reg: "●", Band: "MALICIOUS", Node: host("paypa1.com", "MALICIOUS")},
			{Name: "paypal-secure.com", Method: "combosquat", Conf: 0.89, Reg: "●", Band: "SUSPICIOUS", Node: host("paypal-secure.com", "SUSPICIOUS")},
			{Name: "paypaI.com", Method: "homoglyph", Conf: 0.85, Reg: "●", Band: "SUSPICIOUS", Node: host("paypaI.com", "SUSPICIOUS")},
			{Name: "paypal.co", Method: "tld-swap", Conf: 0.40, Reg: "●", Band: "BENIGN", Node: host("paypal.co", "BENIGN")},
			{Name: "paypall.com", Method: "insertion", Conf: 0.31, Reg: "✗", Band: "UNKNOWN", Node: host("paypall.com", "UNKNOWN")},
		},
		Note: "…42 more · ↵ WALK onto variant",
	}
}

// fixtureVerbResult returns the Phase-1 RESULT for a catalog verb run on the focus. assess
// and variants use the rich fixtures; flows + other verbs render an honest placeholder
// (Phase 3 runs the 14 direct verbs live and deep-links the 15 flows).
func fixtureVerbResult(cv catalogVerb, focus graphNode) resultCard {
	switch cv.Name {
	case "assess":
		return fixtureAssessCard(focus.Value)
	case "variants":
		return fixtureVariantsCard(focus.Value)
	}
	if cv.Flow {
		return resultCard{
			Verb:  cv.Proc + " · " + focus.Value,
			Shape: shapeVendor,
			Table: []resultRow{{Method: "flow", Name: "anchor step runs in console (honest)"}},
			Note:  "deep-link + copyable run_workflow (Phase 3)",
		}
	}
	return resultCard{
		Verb:  cv.Proc + "(" + focus.Value + ")",
		Shape: shapeVendor,
		Table: []resultRow{{Method: "verb", Name: "direct verb runs live with an API key"}},
		Note:  "this is the keyless fixture demo",
	}
}

// fixtureWalk links the fixture decks so a Phase-1 walk is a real demo: walking
// RESOLVES_TO from cloudflare.com onto 104.16.132.229 lands on the mega fan-out deck.
func fixtureWalk(value string) (deckState, bool) {
	switch value {
	case "104.16.132.229":
		return fixtureMegaFanout(), true
	case "AS13335":
		return fixtureASN(), true
	}
	return deckState{}, false
}
