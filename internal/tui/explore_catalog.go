// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"regexp"
	"strings"
	"sync"

	"github.com/whisper-sec/whisper-cli/internal/catalog"
)

// The intelligence catalog is the single vendored whisper.security query catalog
// (internal/catalog, the SSOT shared with `whisper query` / `whisper graph` and the
// `whisper mcp` server): DIRECT verbs that carry real Cypher + params and run inline
// in one keyed round-trip, and FLOWS that carry only an anchor-step note and honestly
// run in the console (never faked as one call). The explorer projects that shared
// catalog into the picker's verb shape; there is no second copy embedded here.

// nodeRefKinds are the input kinds that name a graph NODE (the thing the explorer
// stands on); every other kind (string/select/number) is an extra parameter.
var nodeRefKinds = map[string]bool{
	"any": true, "hostname": true, "domain": true, "ipv4": true, "ipv6": true,
	"ip": true, "asn": true, "prefix": true, "email": true, "org": true,
}

var procRe = regexp.MustCompile(`CALL\s+([A-Za-z0-9_.]+)`)

var (
	catalogOnce  sync.Once
	catalogVerbs []catalogVerb
)

// loadCatalog projects the shared catalog once into the verb list the picker renders.
// It reads the SSOT via catalog.All(); a broken/empty catalog degrades to an empty
// verb list (the picker states it plainly), never a panic: the deck must stay usable.
func loadCatalog() []catalogVerb {
	catalogOnce.Do(func() {
		entries := catalog.All()
		direct := make([]catalogVerb, 0, len(entries))
		flows := make([]catalogVerb, 0, len(entries))
		for _, e := range entries {
			v := verbFromEntry(e)
			if v.Flow {
				flows = append(flows, v)
			} else {
				direct = append(direct, v)
			}
		}
		// Direct verbs first, then the flows section (the picker draws its divider at
		// the first flow), preserving catalog order within each group.
		catalogVerbs = append(direct, flows...)
	})
	return catalogVerbs
}

// verbFromEntry maps one shared-catalog entry to the picker's verb shape: its
// applicable node kinds, the node-ref parameter name, and the baked defaults for any
// extra params.
func verbFromEntry(e catalog.Entry) catalogVerb {
	v := catalogVerb{
		Name:    e.ID,
		Blurb:   e.Purpose,
		Flow:    e.Exec.Mode == catalog.ModeFlow,
		Cypher:  e.Exec.Cypher,
		Note:    e.Exec.Note,
		DocPath: e.DocPath,
		Title:   e.Title,
		Write:   e.ID == "submit", // the one guarded write verb: never auto-run
		Params:  map[string]any{},
	}
	for _, in := range e.Inputs {
		if nodeRefKinds[in.Kind] {
			v.Kinds = append(v.Kinds, in.Kind)
			if v.ParamName == "" && in.ParamName != "" {
				v.ParamName = in.ParamName
			}
			continue
		}
		// An extra (non-node) input: bake its catalog default so the verb still runs
		// in one keystroke; the guarded write verb ignores these (it never auto-runs).
		if in.ParamName != "" && in.Default != nil {
			v.Params[in.ParamName] = in.Default
		}
	}
	if len(v.Kinds) == 0 {
		v.Kinds = []string{"any"} // e.g. db-schema: no node input, applies anywhere
	}
	if v.Flow {
		v.Proc = "flow:" + e.ID
	} else if m := procRe.FindStringSubmatch(e.Exec.Cypher); len(m) == 2 {
		v.Proc = m[1]
	} else {
		v.Proc = e.ID
	}
	return v
}

// catalogDocURL is the honest console deep-link for a flow (docsBase + docPath).
// It reads the base from the catalog itself, which loads once and is never empty
// (it falls back to the published docs root). It used to read a copy loadCatalog
// filled as a side effect, so a caller that had not built the verb list yet got
// "" for a pathless verb and a bare path for the rest.
func catalogDocURL(cv catalogVerb) string {
	base := catalog.DocsBase()
	if cv.DocPath == "" {
		return base
	}
	return strings.TrimSuffix(base, "/") + cv.DocPath
}
