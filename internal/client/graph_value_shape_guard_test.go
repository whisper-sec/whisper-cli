// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// graph_value_shape_guard_test.go: no CLI source binds to ONE of the graph engine's relationship or path
// value shapes. The engine is changing them in one breaking release, rolled one node at a time:
// a relationship is {sourceId,targetId,edgeType} next to an aggregate and {type,...} as a plain
// RETURN today, {type,startNodeId,endNodeId,...} after; a path's nodes are id strings today and node maps after. On
// 2026-10-23 nothing in the CLI asks for or reads such a value (every relationship in our Cypher is reached through
// type(r), count(r) or a property, and `whisper query` and the MCP tools pass replies through), so there is no
// reader to write. This keeps it so until a first consumer arrives, and tells it what to do: read the value through
// ONE shared reader that accepts every shape, never at the call site. The same release changed what startNode(r) and
// endNode(r) report on an inbound hop (the walk's start before, the stored start after), so a direction is read from
// the arrow in the pattern, never from those two; the explore deck did, until 2026-10-30. A line carrying
// "graph-value-guard: <reason>" is a reviewed waiver; there are none today. Each rule is proven on a planted offender.

const graphValueWaiver = "graph-value-guard:"

var (
	// A quoted key, including a struct tag with options (`json:"startNodeId,omitempty"`).
	gvQuotedKey = regexp.MustCompile(`"(sourceId|targetId|edgeType|startNodeId|endNodeId)(,[^"]*)?"`)
	// An exported struct field encoding/json would bind to one of the keys with no tag (it matches names
	// case-insensitively): `StartNodeID string`, `SourceId int64`.
	gvField        = regexp.MustCompile(`(?m)^\s*([A-Z]\w*)\s+[\w\[\]*.]+(\s|$)`)
	gvFieldNames   = []string{"sourceid", "targetid", "edgetype", "startnodeid", "endnodeid"}
	gvDirectionFn  = regexp.MustCompile(`(?i)\b(startNode|endNode)\s*\(`)
	gvPathFn       = regexp.MustCompile(`(?i)\b(relationships|nodes|shortestPath|allShortestPaths)\s*\(`)
	gvPathBinding  = regexp.MustCompile(`(?i)(?:\bMATCH|,)\s*([A-Za-z_]\w*)\s*=\s*\(`)
	gvRelVar       = regexp.MustCompile(`-\s*\[\s*([A-Za-z_]\w*)\s*[:\]*{|]`)
	gvClause       = regexp.MustCompile(`(?i)\b(RETURN|WITH)\b\s*(DISTINCT\b)?`)
	gvClauseEnd    = regexp.MustCompile(`(?i)^(ORDER|SKIP|LIMIT|UNION|MATCH|OPTIONAL|WHERE|CALL|UNWIND|RETURN|WITH|MERGE|CREATE|SET|DELETE)\b`)
	gvCypher       = regexp.MustCompile(`(?i)\b(MATCH|RETURN)\b`)
	gvRealCypher   = regexp.MustCompile(`(?i)\bMATCH\s*\(|\bRETURN\s+[a-z$(\[{*]|\bCALL\s+\w+\.`)
	gvAliases      = regexp.MustCompile(`(?i)\s+AS\s+\w+`)
	gvCypherString = regexp.MustCompile(`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`)
	gvStringLit    = regexp.MustCompile("(?s)\"(?:[^\"\\\\\\n]|\\\\.)*\"|`[^`]*`")
	gvJoin         = regexp.MustCompile(`^\s*\+\s*$`)
)

// gvCypherOffence says why a Cypher text asks the graph for a relationship or path VALUE, or "".
func gvCypherOffence(cy string) string {
	if m := gvDirectionFn.FindStringSubmatch(cy); m != nil {
		return "reads a direction from " + m[1] + "(...), which the graph reports differently on an inbound hop " +
			"from one server version to the next; put the direction in the pattern's arrow"
	}
	if m := gvPathFn.FindStringSubmatch(cy); m != nil {
		return "asks the graph for " + m[1] + "(...)"
	}
	if m := gvPathBinding.FindStringSubmatch(cy); m != nil {
		return "binds a path (" + m[1] + " = ...)"
	}
	vars := map[string]bool{}
	for _, m := range gvRelVar.FindAllStringSubmatch(cy, -1) {
		vars[m[1]] = true
	}
	if len(vars) == 0 {
		return ""
	}
	for _, items := range gvProjections(cy) {
		if strings.HasPrefix(strings.TrimSpace(items), "*") {
			return "projects every variable (*), relationships included"
		}
		// A name inside a Cypher string ('r') or used as a map key ({r: 1}) is not the variable.
		bare := gvCypherString.ReplaceAllString(items, "''")
		for v := range vars {
			q := regexp.QuoteMeta(v)
			rest := regexp.MustCompile(`([{,]\s*)`+q+`\s*:`).ReplaceAllString(bare, "$1 :")
			rest = regexp.MustCompile(`(?i)\b(type|count|id|elementId|properties|keys|startNode|endNode|labels|exists)\s*\(\s*(DISTINCT\s+)?`+q+`\s*\)`).ReplaceAllString(rest, " ")
			rest = regexp.MustCompile(`\b`+q+`\s*(\.|\[\s*['"])`).ReplaceAllString(rest, " ")
			// Go's RE2 has no lookbehind: a bare use is the name not preceded by '.', '$' or a word character.
			for _, loc := range regexp.MustCompile(`\b`+q+`\b`).FindAllStringIndex(rest, -1) {
				if loc[0] > 0 {
					p := rest[loc[0]-1]
					if p == '.' || p == '$' || p == '_' || (p >= 'a' && p <= 'z') || (p >= 'A' && p <= 'Z') || (p >= '0' && p <= '9') {
						continue
					}
				}
				return "projects the relationship " + v + " as a value"
			}
		}
	}
	return ""
}

// gvProjections returns the item list of every RETURN and WITH, cut at the next clause keyword outside brackets.
func gvProjections(cy string) []string {
	var out []string
	for _, loc := range gvClause.FindAllStringIndex(cy, -1) {
		from, depth, end := loc[1], 0, len(cy)
		for i := from; i < len(cy); i++ {
			switch c := cy[i]; {
			case c == '(' || c == '[' || c == '{':
				depth++
			case c == ')' || c == ']' || c == '}':
				depth--
			case depth == 0 && (i == 0 || !isWordByte(cy[i-1])) && gvClauseEnd.MatchString(cy[i:]):
				end = i
			}
			if end != len(cy) {
				break
			}
		}
		out = append(out, gvAliases.ReplaceAllString(cy[from:end], " "))
	}
	return out
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func gvSplitTop(s string) []string {
	var out []string
	depth, from := 0, 0
	for i, c := range s {
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[from:i])
				from = i + 1
			}
		}
	}
	return append(out, s[from:])
}

// gvScanGo reports every offence in one Go source.
func gvScanGo(name, src string) []string {
	hits, _ := gvScanGoCounting(name, src)
	return hits
}

// gvScanGoCounting is gvScanGo, also returning how many real Cypher statements its Cypher rules read.
func gvScanGoCounting(name, src string) ([]string, int) {
	cypherRead := 0
	var hits []string
	lines := strings.Split(src, "\n")
	for i, l := range lines {
		if strings.Contains(l, graphValueWaiver) {
			continue
		}
		if gvQuotedKey.MatchString(l) {
			hits = append(hits, name+":"+strconv.Itoa(i+1)+" reads a graph value key")
		}
		if m := gvField.FindStringSubmatch(l); m != nil {
			for _, k := range gvFieldNames {
				if strings.EqualFold(m[1], k) {
					hits = append(hits, name+":"+strconv.Itoa(i+1)+" binds a graph value key to the field "+m[1])
				}
			}
		}
	}
	// Cypher: string literals joined by '+' are one statement.
	locs := gvStringLit.FindAllStringIndex(src, -1)
	for i := 0; i < len(locs); {
		j := i
		for j+1 < len(locs) && gvJoin.MatchString(src[locs[j][1]:locs[j+1][0]]) {
			j++
		}
		var text strings.Builder
		for k := i; k <= j; k++ {
			lit := src[locs[k][0]:locs[k][1]]
			if s, err := strconv.Unquote(lit); err == nil {
				text.WriteString(s)
			} else {
				text.WriteString(lit)
			}
			text.WriteByte(' ')
		}
		start, end := locs[i][0], locs[j][1]
		lineStart := strings.LastIndex(src[:start], "\n") + 1
		lineEnd := strings.Index(src[end:], "\n")
		if lineEnd < 0 {
			lineEnd = len(src) - end
		}
		waived := strings.Contains(src[lineStart:end+lineEnd], graphValueWaiver)
		if cy := text.String(); !waived && gvCypher.MatchString(cy) {
			if gvRealCypher.MatchString(cy) {
				cypherRead++
			}
			if why := gvCypherOffence(cy); why != "" {
				hits = append(hits, name+":"+strconv.Itoa(strings.Count(src[:start], "\n")+1)+" "+why)
			}
		}
		i = j + 1
	}
	return hits, cypherRead
}

// gvScanJSON reports every Cypher offence in an embedded JSON document (the catalog's recipes).
func gvScanJSON(name string, b []byte) []string {
	var doc any
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	var hits []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if gvQuotedKey.MatchString(`"` + k + `"`) {
					hits = append(hits, name+" carries the graph value key "+k)
				}
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case string:
			if gvCypher.MatchString(x) && !strings.Contains(x, graphValueWaiver) {
				if why := gvCypherOffence(x); why != "" {
					hits = append(hits, name+" "+why+": "+x)
				}
			}
		}
	}
	walk(doc)
	return hits
}

func gvScanTree(t *testing.T, root string) (hits []string, goFiles, cypher int) {
	t.Helper()
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".") && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		switch {
		case strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go"):
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			goFiles++
			h, n := gvScanGoCounting(rel, string(b))
			cypher += n
			hits = append(hits, h...)
		case strings.HasSuffix(p, ".json") && strings.Contains(rel, "internal"+string(filepath.Separator)):
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			hits = append(hits, gvScanJSON(rel, b)...)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hits, goFiles, cypher
}

func TestNoCLISourceBindsToOneGraphValueShape(t *testing.T) {
	hits, goFiles, cypher := gvScanTree(t, filepath.Join("..", ".."))
	if goFiles < 200 {
		t.Fatalf("the guard read %d Go files; the CLI tree has far more, so it read the wrong place", goFiles)
	}
	if cypher < 10 {
		t.Fatalf("the guard's Cypher rules read %d real Cypher statements; the CLI carries more, so they read nothing", cypher)
	}
	if len(hits) > 0 {
		t.Fatalf("a relationship or path value from the graph changes shape (one release, rolled engine node by node): "+
			"read it through ONE shared reader that accepts every shape, never at the call site, or waive one line with %q:\n%s",
			graphValueWaiver+" <reason>", strings.Join(hits, "\n"))
	}
}

func TestGraphValueGuardFiresOnEachPlantedShape(t *testing.T) {
	planted := map[string]string{
		"key.go":    "package x\ntype rel struct { Start string `json:\"startNodeId\"` }\n",
		"read.go":   "package x\nfunc f(m map[string]any) any { return m[\"sourceId\"] }\n",
		"fn.go":     "package x\nconst q = \"MATCH p=(a)-[:R]->(b) \" +\n\t\"RETURN relationships(p)\"\n",
		"bind.go":   "package x\nconst q = `MATCH p = (a)-[:R]->(b) RETURN p.x`\n",
		"bare.go":   "package x\nconst q = \"MATCH (a)-[r:R]->(b) RETURN a.name, r LIMIT 1\"\n",
		"coll.go":   "package x\nconst q = \"MATCH (a)-[r]->(b) WITH a, collect(r) AS rs RETURN a\"\n",
		"lit.go":    "package x\nconst q = \"MATCH (a)-[r]->(b) RETURN [r, a] AS l\"\n",
		"cat.json":  `{"cypher":"MATCH (a)-[r]->(b) RETURN r"}`,
		"opts.go":   "package x\ntype rel struct { Start string `json:\"startNodeId,omitempty\"` }\n",
		"field.go":  "package x\ntype rel struct {\n\tStartNodeID string\n}\n",
		"star.go":   "package x\nconst q = \"MATCH (a)-[r:R]->(b) RETURN *\"\n",
		"nest.go":   "package x\nconst q = \"MATCH (a)-[r]->(b) RETURN [x IN a.xs WHERE x > 0] AS y, r\"\n",
		"head.go":   "package x\nconst q = \"MATCH (a)-[r]->(b) RETURN head(collect(r)) AS h\"\n",
		"comp.go":   "package x\nconst q = \"MATCH (a) RETURN [(a)-[r]->(b) | r] AS rs\"\n",
		"second.go": "package x\nconst q = \"MATCH (a), p = (a)-[:R]->(b) RETURN a\"\n",
		"dir.go":    "package x\nconst q = `MATCH (n {name:$v})-[r]-(m) WITH type(r) AS et, startNode(r) = n AS outb, m RETURN et, outb, count(m) AS total`\n",
		"end.go":    "package x\nconst q = \"MATCH (a)<-[r:R]-(b) RETURN endNode(r).name AS e\"\n",
	}
	for name, src := range planted {
		var hits []string
		if strings.HasSuffix(name, ".json") {
			hits = gvScanJSON(name, []byte(src))
		} else {
			hits = gvScanGo(name, src)
		}
		if len(hits) == 0 {
			t.Fatalf("the rule for %s did not fire", name)
		}
	}
	fine := "package x\n" +
		"const a = `CALL { MATCH (n {name:$v})-[r]->(m) RETURN type(r) AS et, true AS outb, m UNION ALL MATCH (n {name:$v})<-[r]-(m) RETURN type(r) AS et, false AS outb, m } WITH et, outb, m RETURN et, outb, count(m) AS total`\n" +
		"const b = \"MATCH (n)-[r:RESOLVES_TO]->(ip) RETURN labels(ip) AS lbls, r.lastSeen AS lastSeen\"\n" +
		"func nodes() []string { return nil }\n" +
		"var edgeType string\n" +
		"type m struct {\n\tedgeType string\n}\n" +
		"const c = \"UNWIND $xs AS x MATCH (a)-[r]->(b) RETURN [x] AS l, x, r['since'] AS s\"\n" +
		"const d = \"MATCH (a)-[r]->(b) WITH a, count(r) AS n RETURN a.name, n\"\n" +
		"const e = \"MATCH (a)-[r]->(b) RETURN 'r' AS lit, {r: 1} AS m\"\n" +
		"const w = \"MATCH (a)-[r]->(b) RETURN r\" // " + graphValueWaiver + " a reviewed fixture\n"
	if hits := gvScanGo("fine.go", fine); len(hits) > 0 {
		t.Fatalf("the guard must not fire on how our Cypher really uses a relationship: %v", hits)
	}
}
