// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// explore_direction_test.go: the explore deck reads an edge's direction from the arrow in
// its own pattern, never from startNode(r), whose answer on an inbound hop the graph has
// changed (walk order before, stored direction now). The replies are live captures of the
// deck's own queries; the fake graph answers ONLY the exact query that was captured, so a
// deck that asks for direction any other way gets nothing back and the test says so.

type capturedCall struct {
	Edge  string          `json:"edge"`
	Query string          `json:"query"`
	Reply json.RawMessage `json:"reply"`
}

type directionFixture struct {
	Focus        string       `json:"focus"`
	Edges        capturedCall `json:"edges"`
	InboundPage  capturedCall `json:"inbound_page"`
	OutboundPage capturedCall `json:"outbound_page"`
}

func loadDirectionFixture(t *testing.T) directionFixture {
	t.Helper()
	b, err := os.ReadFile("testdata/explore_direction.json")
	if err != nil {
		t.Fatal(err)
	}
	var f directionFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Focus == "" || f.Edges.Query == "" || f.InboundPage.Query == "" || f.OutboundPage.Query == "" {
		t.Fatalf("the direction fixture lost a capture: %+v", f)
	}
	return f
}

// capturedGraph answers each captured query with its captured reply, and anything else with
// the 400 problem the graph gives a query it will not run.
func capturedGraph(t *testing.T, focus string, calls ...capturedCall) (*client.Client, *[]string) {
	t.Helper()
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query      string         `json:"query"`
			Parameters map[string]any `json:"parameters"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		asked = append(asked, req.Query)
		for _, c := range calls {
			if req.Query == c.Query && req.Parameters["v"] == focus {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(c.Reply)
				return
			}
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"title":"Bad Request","status":400,"detail":"not a captured query"}`))
	}))
	t.Cleanup(srv.Close)
	return client.New(client.Config{
		ControlURL: srv.URL,
		Cred:       client.Credential{Value: "whisper-0000000000000000"},
		HTTPClient: srv.Client(),
	}), &asked
}

func TestExplore_DirectionComesFromThePatternNotStartNode(t *testing.T) {
	for name, q := range map[string]string{"edges": exCypherEdges} {
		if strings.Contains(q, "startNode(") || strings.Contains(q, "endNode(") {
			t.Fatalf("%s must not read direction from startNode/endNode: %s", name, q)
		}
	}
	f := loadDirectionFixture(t)
	c, asked := capturedGraph(t, f.Focus, f.Edges, f.InboundPage, f.OutboundPage)

	m := exLoadEdges(c, f.Focus, 1)().(edgesMsg)
	if m.err != nil {
		t.Fatalf("the deck must send the captured edges query; it sent %q: %v", *asked, m.err)
	}
	byBase := map[string]edgeGroup{}
	for _, e := range m.edges {
		byBase[e.Base] = e
	}
	for base, dir := range map[string]int{"RESOLVES_TO": -1, "NAMESERVER_FOR": -1, "BELONGS_TO": 1, "ANNOUNCED_BY": 1} {
		e, ok := byBase[base]
		if !ok {
			t.Fatalf("%s is missing from the deck: %+v", base, m.edges)
		}
		if e.Dir != dir {
			t.Errorf("%s must read Dir %d (stored direction, the IP is its %s), got %+v",
				base, dir, map[int]string{-1: "end", 1: "start"}[dir], e)
		}
	}
	if got := byBase["RESOLVES_TO"]; got.Type != "RESOLVES_TO⁻¹" || got.Total != 549 || len(got.Sample) == 0 ||
		got.Sample[0].Labels[0] != "HOSTNAME" {
		t.Errorf("the inbound RESOLVES_TO group is the hostnames that resolve to the IP: %+v", got)
	}

	last := func() string {
		if len(*asked) == 0 {
			return "nothing"
		}
		return (*asked)[len(*asked)-1]
	}
	in := exLoadNeighbors(c, f.Focus, byBase["RESOLVES_TO"], 0, 2)().(neighborsMsg)
	if in.err != nil || len(in.sample) != 200 {
		t.Fatalf("the inbound page must be the captured one (sent %q): err=%v rows=%d", last(), in.err, len(in.sample))
	}
	for _, n := range in.sample {
		if len(n.Labels) == 0 || n.Labels[0] != "HOSTNAME" {
			t.Fatalf("an inbound RESOLVES_TO neighbour of an IP is a hostname: %+v", n)
		}
	}
	out := exLoadNeighbors(c, f.Focus, byBase["BELONGS_TO"], 0, 3)().(neighborsMsg)
	if out.err != nil || len(out.sample) != 2 || out.sample[1].Value != "142.250.154.0/24" {
		t.Fatalf("the outbound page must be the captured one (sent %q): %+v", last(), out)
	}
	for _, q := range *asked {
		if strings.Contains(q, "startNode(") || strings.Contains(q, "endNode(") {
			t.Fatalf("no query the deck sends may read direction from startNode/endNode: %s", q)
		}
	}
}
