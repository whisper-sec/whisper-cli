// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"sort"
	"strings"
)

// tsmodel.go is the shape of a tailnet as we read it, and nothing more. It carries no
// opinion about how any of it maps: that is migratemap.go's job, and keeping the two
// apart is what lets the mapper be tested against a fixture with no network at all.
//
// One field here is load-bearing beyond its size. Unread records, by name, every section
// we asked for and did not get. This codebase's second-most-common defect is a fault that
// renders as an empty answer: a timeout becoming "0 devices" and then a plan that
// migrates nothing while looking complete. So a read failure is a NAMED ABSENCE that
// travels with the data, BuildPlan refuses to plan a tailnet whose load-bearing sections
// are unread, and the fidelity report prints the reason.

// TSDevice is one node in their tailnet.
type TSDevice struct {
	ID                string   `json:"id"`
	NodeID            string   `json:"nodeId,omitempty"`
	Hostname          string   `json:"hostname"`
	Name              string   `json:"name"` // the MagicDNS fqdn
	Addresses         []string `json:"addresses"`
	OS                string   `json:"os,omitempty"`
	User              string   `json:"user,omitempty"`
	Tags              []string `json:"tags,omitempty"`
	Authorized        bool     `json:"authorized,omitempty"`
	KeyExpiryDisabled bool     `json:"keyExpiryDisabled,omitempty"`
	Expires           string   `json:"expires,omitempty"`
	IsExternal        bool     `json:"isExternal,omitempty"`
	LastSeen          string   `json:"lastSeen,omitempty"`
	ClientVersion     string   `json:"clientVersion,omitempty"`
	// AdvertisedRoutes and EnabledRoutes come from a separate per-device read.
	AdvertisedRoutes []string `json:"advertisedRoutes,omitempty"`
	EnabledRoutes    []string `json:"enabledRoutes,omitempty"`
	// RoutesUnread is set when the per-device route read failed, so "no routes" and
	// "we could not ask" stay different answers all the way to the report.
	RoutesUnread string `json:"routesUnread,omitempty"`
}

// ShortName is the first label of the MagicDNS name, falling back to the hostname. It is
// what a person calls the node, and what our label is planned from.
func (d TSDevice) ShortName() string {
	n := strings.TrimSuffix(strings.TrimSpace(d.Name), ".")
	if n != "" {
		if i := strings.IndexByte(n, '.'); i > 0 {
			return n[:i]
		}
		return n
	}
	return strings.TrimSpace(d.Hostname)
}

// IsExitNodeCandidate reports whether the node advertises a default route, which is how
// Tailscale spells "I am willing to be an exit node".
func (d TSDevice) IsExitNodeCandidate() bool {
	for _, r := range d.AdvertisedRoutes {
		if r == "0.0.0.0/0" || r == "::/0" {
			return true
		}
	}
	return false
}

// SubnetRoutes is the advertised set minus the two default-route prefixes, i.e. the
// prefixes that make this node a subnet router.
func (d TSDevice) SubnetRoutes() []string {
	var out []string
	for _, r := range d.AdvertisedRoutes {
		if r == "0.0.0.0/0" || r == "::/0" {
			continue
		}
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// TSKey is auth-key METADATA. The secret itself is unreadable: their schema populates
// `key` only at creation time, which is one of the four things this tool says out loud
// before it starts rather than discovering halfway through.
type TSKey struct {
	ID           string         `json:"id"`
	Description  string         `json:"description,omitempty"`
	Created      string         `json:"created,omitempty"`
	Expires      string         `json:"expires,omitempty"`
	Revoked      string         `json:"revoked,omitempty"`
	Invalid      bool           `json:"invalid,omitempty"`
	Capabilities map[string]any `json:"capabilities,omitempty"`
}

// TSUser is one member of the tailnet.
type TSUser struct {
	ID          string `json:"id"`
	LoginName   string `json:"loginName,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Type        string `json:"type,omitempty"`
	Role        string `json:"role,omitempty"`
	Status      string `json:"status,omitempty"`
}

// TSDNS is their DNS configuration: the half of it that is readable.
type TSDNS struct {
	Nameservers []string            `json:"nameservers,omitempty"`
	SearchPaths []string            `json:"searchPaths,omitempty"`
	MagicDNS    bool                `json:"magicDNS,omitempty"`
	SplitDNS    map[string][]string `json:"splitDNS,omitempty"`
}

// Tailnet is everything one plan run read.
type Tailnet struct {
	Name        string     `json:"name"`
	Devices     []TSDevice `json:"devices"`
	Policy      TSPolicy   `json:"policy"`
	PolicyLines int        `json:"policyLines"`
	DNS         TSDNS      `json:"dns"`
	Keys        []TSKey    `json:"keys"`
	Users       []TSUser   `json:"users"`

	// Unread names every section we asked for and did not get, with the reason. It is
	// never empty because a section was empty: an empty section is an answer.
	Unread []UnreadSection `json:"unread,omitempty"`
}

// UnreadSection is a named absence. A fault and an answer are different things, and this
// type is how the difference survives all the way to the operator's terminal.
type UnreadSection struct {
	Section string `json:"section"`
	Reason  string `json:"reason"`
	// LoadBearing marks a section a plan cannot be built without.
	LoadBearing bool `json:"loadBearing"`
}

// UnreadLoadBearing returns the unread sections a plan cannot be built without.
func (t *Tailnet) UnreadLoadBearing() []UnreadSection {
	var out []UnreadSection
	for _, u := range t.Unread {
		if u.LoadBearing {
			out = append(out, u)
		}
	}
	return out
}

// markUnread records a named absence exactly once per section.
func (t *Tailnet) markUnread(section, reason string, loadBearing bool) {
	for _, u := range t.Unread {
		if u.Section == section {
			return
		}
	}
	t.Unread = append(t.Unread, UnreadSection{Section: section, Reason: Scrub(reason), LoadBearing: loadBearing})
}
