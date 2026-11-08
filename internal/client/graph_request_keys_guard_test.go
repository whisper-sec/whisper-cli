// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// graph_request_keys_guard_test.go: every request body the CLI sends to the graph's
// POST /api/query carries only the fields that endpoint documents (the QueryRequest
// schema in its /api/openapi.json). The graph ignores any other top-level field today,
// so a slip such as "params" for "parameters" drops the bound values without an error
// and the query answers empty or wrong; it will refuse such a field outright later.
//
// The builders are found, not listed: any map or struct literal with a "query" key
// that reaches json.Marshal, json.MarshalIndent or an Encode call in the same function
// is a request body, including a map variable that gains more keys by index before it
// is marshalled. A literal counts when any key is "query" in any letter case, so an
// untagged Query field (which encodes as "Query" and is no query at all) is reported.
// The scan must find at least the builders the CLI has today, and it is proven against
// planted bodies below, so a scan of the wrong tree or a matcher that can no longer
// match fails loudly instead of passing on nothing.
//
// Not reached: a body returned by a helper call rather than written as a literal, a
// const used as a map key, and a body built by string formatting. The CLI has none.

// graphRequestFields is the documented request body of POST /api/query. "q" is an
// alias of "query" that the CLI never sends.
var graphRequestFields = []string{"query", "parameters", "timeout", "projectionFull", "atGeneration", "compact", "noCache"}

func TestEveryGraphRequestBodyUsesOnlyDocumentedFields(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("expected the module root at %s: %v", root, err)
	}
	builders, offenders := scanGraphRequestBodies(t, root)
	// Client.Query (control-plane statements) and graphQuery (graph reads) today.
	if builders < 2 {
		t.Fatalf("found %d graph request builders, want at least 2: the scan is not seeing the sources", builders)
	}
	if len(offenders) > 0 {
		t.Fatalf("a graph request body may carry only %v; the graph ignores anything else today and will refuse it:\n  %s",
			graphRequestFields, strings.Join(offenders, "\n  "))
	}
}

func TestGraphRequestGuardFindsPlantedBodies(t *testing.T) {
	dir := t.TempDir()
	src := `package planted

import "encoding/json"

type body struct {
	Query  string         ` + "`json:\"query\"`" + `
	Params map[string]any ` + "`json:\"params,omitempty\"`" + `
}

func literal(q string) { _, _ = json.Marshal(map[string]any{"query": q, "apiKey": "k"}) }

func indexed(q string) {
	m := map[string]any{"query": q}
	m["params"] = map[string]any{}
	_, _ = json.Marshal(m)
}

func tagged(q string) { _, _ = json.Marshal(body{Query: q}) }

func pointer(q string) { _, _ = json.MarshalIndent(&body{Query: q}, "", " ") }

func clean(q string) {
	_, _ = json.Marshal(map[string]any{"query": q, "parameters": map[string]any{"params": 1}, "timeout": 400})
}

// Not a request: it never reaches a marshal call here.
func fields() map[string]any { return map[string]any{"query": "x", "other": 1} }
`
	// The same package name in another directory, with its own clean body type of the
	// same name: neither may be read as the other.
	two := `package planted

import "encoding/json"

type body struct {
	Query string ` + "`json:\"query\"`" + `
}

// Wire's Query field has no tag, so it encodes as "Query".
type Wire struct {
	Query  string
	Bearer string ` + "`json:\"bearer\"`" + `
}

func sameName(q string) { _, _ = json.Marshal(body{Query: q}) }
`
	three := `package other

import (
	"encoding/json"

	"example.invalid/two"
)

func fromElsewhere(q string) { _, _ = json.Marshal(two.Wire{Query: q}) }
`
	for name, text := range map[string]string{"planted.go": src, "two/two.go": two, "three/three.go": three} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	builders, offenders := scanGraphRequestBodies(t, dir)
	if builders != 7 {
		t.Errorf("found %d builders, want 7 (literal, indexed, tagged, pointer, clean, sameName, fromElsewhere)", builders)
	}
	got := strings.Join(offenders, "\n")
	for _, want := range []string{
		`planted.go:10: body carries "apiKey"`,
		`planted.go:13: body carries "params"`,
		`planted.go:18: body carries "params"`,
		`planted.go:20: body carries "params"`,
		`three/three.go:9: body carries "Query"`,
		`three/three.go:9: body carries "bearer"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing offender %q in:\n%s", want, got)
		}
	}
	if len(offenders) != 6 {
		t.Errorf("want exactly 6 offenders (a nested bound value, an unmarshalled map and the clean body of the same"+
			" name are not), got:\n%s", got)
	}
}

// scanGraphRequestBodies walks every non-test Go source under root and returns how many
// request bodies it found and one line per field outside graphRequestFields.
func scanGraphRequestBodies(t *testing.T, root string) (int, []string) {
	t.Helper()
	allowed := map[string]bool{}
	for _, f := range graphRequestFields {
		allowed[f] = true
	}
	fset := token.NewFileSet()
	var files []*ast.File
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "vendor", ".git", "target", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parsing %s: %w", path, perr)
		}
		files = append(files, f)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Named struct types, by directory and name, so a marshalled T{...} can be read; a
	// pkg.T{...} from another package is looked up by name across every directory.
	structs := typeIndex{byDir: map[string]*ast.StructType{}, byName: map[string][]*ast.StructType{}}
	for _, f := range files {
		dir := filepath.Dir(fset.Position(f.Pos()).Filename)
		ast.Inspect(f, func(n ast.Node) bool {
			if ts, ok := n.(*ast.TypeSpec); ok {
				if st, ok := ts.Type.(*ast.StructType); ok {
					structs.byDir[dir+"."+ts.Name.Name] = st
					structs.byName[ts.Name.Name] = append(structs.byName[ts.Name.Name], st)
				}
			}
			return true
		})
	}

	builders := 0
	var offenders []string
	for _, f := range files {
		dir := filepath.Dir(fset.Position(f.Pos()).Filename)
		check := func(lit *ast.CompositeLit, extra []string) {
			keys := literalKeys(lit, dir, structs)
			keys = append(keys, extra...)
			if !containsFold(keys, "query") {
				return
			}
			builders++
			pos := fset.Position(lit.Pos())
			rel, _ := filepath.Rel(root, pos.Filename)
			for _, k := range keys {
				if !allowed[k] {
					offenders = append(offenders, fmt.Sprintf("%s:%d: body carries %q", filepath.ToSlash(rel), pos.Line, k))
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			var body *ast.BlockStmt
			switch fn := n.(type) {
			case *ast.FuncDecl:
				body = fn.Body
			case *ast.FuncLit:
				body = fn.Body
			}
			if body == nil {
				return true
			}
			scanFunction(body, check)
			return true
		})
	}
	sort.Strings(offenders)
	return builders, offenders
}

// scanFunction finds the marshal calls in one function body and checks the literal
// each one encodes, directly or through a local variable.
func scanFunction(body *ast.BlockStmt, check func(*ast.CompositeLit, []string)) {
	vars := map[string]*ast.CompositeLit{}
	extra := map[string][]string{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.FuncLit:
			return false // its own function, scanned on its own
		case *ast.AssignStmt:
			for i, lhs := range s.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && i < len(s.Rhs) {
					if lit := compositeOf(s.Rhs[i]); lit != nil {
						vars[id.Name] = lit
					}
				}
				if ix, ok := lhs.(*ast.IndexExpr); ok {
					if id, ok := ix.X.(*ast.Ident); ok {
						if k, ok := stringLit(ix.Index); ok {
							extra[id.Name] = append(extra[id.Name], k)
						}
					}
				}
			}
		case *ast.ValueSpec:
			for i, name := range s.Names {
				if i < len(s.Values) {
					if lit := compositeOf(s.Values[i]); lit != nil {
						vars[name.Name] = lit
					}
				}
			}
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Marshal", "MarshalIndent", "Encode":
		default:
			return true
		}
		arg := call.Args[0]
		if lit := compositeOf(arg); lit != nil {
			check(lit, nil)
		} else if id, ok := arg.(*ast.Ident); ok && vars[id.Name] != nil {
			check(vars[id.Name], extra[id.Name])
		}
		return true
	})
}

// compositeOf unwraps T{...} and &T{...}.
func compositeOf(e ast.Expr) *ast.CompositeLit {
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = u.X
	}
	lit, _ := e.(*ast.CompositeLit)
	return lit
}

// literalKeys returns the top-level JSON field names a literal encodes: a map's string
// keys, or a struct's json names (from its tags, else the exported field name).
// typeIndex finds the struct a literal names.
type typeIndex struct {
	byDir  map[string]*ast.StructType
	byName map[string][]*ast.StructType
}

func literalKeys(lit *ast.CompositeLit, dir string, structs typeIndex) []string {
	switch typ := lit.Type.(type) {
	case *ast.MapType:
		var keys []string
		for _, el := range lit.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if k, ok := stringLit(kv.Key); ok {
					keys = append(keys, k)
				}
			}
		}
		return keys
	case *ast.StructType:
		return structKeys(typ)
	case *ast.Ident:
		if st := structs.byDir[dir+"."+typ.Name]; st != nil {
			return structKeys(st)
		}
	case *ast.SelectorExpr:
		// pkg.T{...}: every struct of that name in the module; the first that is a body wins.
		for _, st := range structs.byName[typ.Sel.Name] {
			if keys := structKeys(st); containsFold(keys, "query") {
				return keys
			}
		}
	}
	return nil
}

func structKeys(st *ast.StructType) []string {
	var keys []string
	for _, field := range st.Fields.List {
		name := ""
		if field.Tag != nil {
			if tag, err := strconv.Unquote(field.Tag.Value); err == nil {
				name = strings.Split(reflect.StructTag(tag).Get("json"), ",")[0]
			}
		}
		if name == "-" {
			continue
		}
		if name != "" {
			keys = append(keys, name)
			continue
		}
		for _, id := range field.Names {
			if id.IsExported() {
				keys = append(keys, id.Name)
			}
		}
	}
	return keys
}

func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	return s, err == nil
}

func containsFold(xs []string, x string) bool {
	for _, s := range xs {
		if strings.EqualFold(s, x) {
			return true
		}
	}
	return false
}
