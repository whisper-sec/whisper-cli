// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package catalog

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

// docs.go embeds the whisper.security documentation index (docs-index.json, seeded
// from the docs sitemap) and exposes it to the `read_docs` MCP tool: list the pages,
// search them by keyword, and resolve one index-relative path to its public markdown
// URL. The index is the SSOT for which pages are fetchable: a caller supplies only
// an index-relative path, never a URL, so read_docs can never be pointed off-site.

//go:embed docs-index.json
var docsIndexJSON []byte

// DocEntry is one indexed documentation page.
type DocEntry struct {
	Path    string `json:"path"`
	Title   string `json:"title"`
	Section string `json:"section"`
	Summary string `json:"summary"`
}

type docsIndex struct {
	BaseURL string     `json:"baseUrl"`
	Docs    []DocEntry `json:"docs"`
}

var (
	docsOnce  sync.Once
	docsData  docsIndex
	docsByKey map[string]int
)

func loadDocs() {
	docsOnce.Do(func() {
		_ = json.Unmarshal(docsIndexJSON, &docsData)
		if strings.TrimSpace(docsData.BaseURL) == "" {
			docsData.BaseURL = "https://www.whisper.security/docs/"
		}
		docsByKey = make(map[string]int, len(docsData.Docs))
		for i, d := range docsData.Docs {
			docsByKey[strings.ToLower(strings.Trim(d.Path, "/"))] = i
		}
	})
}

// Docs returns every indexed documentation page, in index order.
func Docs() []DocEntry {
	loadDocs()
	return docsData.Docs
}

// DocByPath resolves an index-relative doc path (case-insensitive, leading/trailing
// slashes ignored). ok=false when the path is not in the index.
func DocByPath(path string) (DocEntry, bool) {
	loadDocs()
	i, ok := docsByKey[strings.ToLower(strings.Trim(strings.TrimSpace(path), "/"))]
	if !ok {
		return DocEntry{}, false
	}
	return docsData.Docs[i], true
}

// SearchDocs ranks indexed pages by a case-insensitive keyword over path/title/
// section/summary. A blank keyword returns the whole index.
func SearchDocs(keyword string) []DocEntry {
	loadDocs()
	kw := strings.ToLower(strings.TrimSpace(keyword))
	if kw == "" {
		return docsData.Docs
	}
	var hits []DocEntry
	for _, d := range docsData.Docs {
		hay := strings.ToLower(d.Path + " " + d.Title + " " + d.Section + " " + d.Summary)
		if strings.Contains(hay, kw) {
			hits = append(hits, d)
		}
	}
	return hits
}

// DocURL is the public markdown URL for an indexed doc path (docsBase + path + ".md").
func DocURL(path string) string {
	loadDocs()
	return strings.TrimRight(docsData.BaseURL, "/") + "/" + strings.Trim(path, "/") + ".md"
}
