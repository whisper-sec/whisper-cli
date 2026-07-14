// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// graph.go is the PUBLIC graph surface of the client: arbitrary parameterised Cypher
// against POST /api/query ({"query","parameters"} -> {columns,rows,statistics}, rows
// as column-keyed objects), and catalog FLOW recipes via the console gallery/run
// endpoint ({"slug","inputs","params"} -> an SSE stream of step/graph events). Both
// are keyed (X-API-Key); both decode liberally per the Robustness Principle.

// GraphResult is the decoded {columns,rows,statistics} envelope the public graph
// endpoint returns. Rows are normalised to column-keyed maps whichever wire form
// they arrived in (objects keyed by column, or positional arrays zipped against
// columns). Raw preserves the verbatim reply for --json / MCP passthrough.
type GraphResult struct {
	Columns    []string
	Rows       []map[string]any
	Statistics map[string]any
	Raw        json.RawMessage
}

// GraphStats is the parsed statistics block, surfaced so an interactive surface (the
// TUI explorer) can show an honest latency + rowCount badge on each pane without
// re-parsing the raw Statistics map itself.
type GraphStats struct {
	Rows   int // statistics.rowCount (or rows); falls back to the decoded row count
	MS     int // statistics.executionTimeMs (or ms)
	DBHits int // statistics.dbHits when present
}

// Stats derives a GraphStats from the result's Statistics map, falling back to the
// decoded row count when the server omits an explicit rowCount. Liberal-accept: the
// documented and the shorthand spellings both count.
func (r *GraphResult) Stats() GraphStats {
	s := GraphStats{Rows: len(r.Rows)}
	if r.Statistics != nil {
		if v, ok := statInt(r.Statistics, "rowCount", "rows"); ok {
			s.Rows = v
		}
		if v, ok := statInt(r.Statistics, "executionTimeMs", "ms"); ok {
			s.MS = v
		}
		if v, ok := statInt(r.Statistics, "dbHits"); ok {
			s.DBHits = v
		}
	}
	return s
}

// statInt reads the first present numeric key from a statistics map (liberal: the
// documented and the shorthand spellings both count).
func statInt(m map[string]any, keys ...string) (int, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch n := v.(type) {
			case float64:
				return int(n), true
			case json.Number:
				if i, err := n.Int64(); err == nil {
					return int(i), true
				}
			}
		}
	}
	return 0, false
}

// GraphQueryRows is the row-and-stats convenience over GraphQuery for interactive
// callers (the TUI explorer): it returns the decoded rows plus a parsed GraphStats,
// discarding the ordered columns and the verbatim Raw the CLI/MCP passthrough needs.
// A failure surfaces the same *ProblemError GraphQuery would.
func (c *Client) GraphQueryRows(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, GraphStats, error) {
	res, err := c.GraphQuery(ctx, cypher, params)
	if err != nil {
		return nil, GraphStats{}, err
	}
	return res.Rows, res.Stats(), nil
}

// GraphQuery runs one parameterised Cypher statement against the public graph
// endpoint (the same URL the control plane rides: POST {"query","parameters"}).
// params may be nil (sent as {}). A failure comes back as a *ProblemError carrying
// the server's own detail, never an opaque error.
func (c *Client) GraphQuery(ctx context.Context, query string, params map[string]any) (*GraphResult, error) {
	if c.cred.IsZero() {
		return nil, &ProblemError{Status: 401, Title: "no key",
			Detail: "graph queries need an API key - run 'whisper login', set WHISPER_API_KEY, or pass --key"}
	}
	if params == nil {
		params = map[string]any{}
	}
	body, err := json.Marshal(map[string]any{"query": query, "parameters": params})
	if err != nil {
		return nil, fmt.Errorf("encoding the graph query: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.controlURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	c.applyAuth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graph endpoint unreachable at %s: %w", c.controlURL, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20)) // 16 MiB cap - generous, never unbounded
	if err != nil {
		return nil, fmt.Errorf("reading graph reply: %w", err)
	}
	return DecodeGraphResult(raw, resp.StatusCode)
}

// DecodeGraphResult parses a graph /api/query reply. Liberal-accept: rows may be
// column-keyed objects (the documented shape) OR positional arrays zipped against
// columns; an error reply may be an RFC-7807 problem object or a bare {"error":...}
// string. httpStatus >= 400, or an error field with no result, is surfaced as a
// *ProblemError with the server's own words.
func DecodeGraphResult(body []byte, httpStatus int) (*GraphResult, error) {
	var wire struct {
		Columns    []string          `json:"columns"`
		Rows       []json.RawMessage `json:"rows"`
		Statistics map[string]any    `json:"statistics"`
		Error      json.RawMessage   `json:"error"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		if httpStatus >= 400 {
			return nil, &ProblemError{Status: httpStatus,
				Detail: "graph endpoint returned a non-JSON error reply (HTTP " + fmt.Sprint(httpStatus) + ")"}
		}
		return nil, fmt.Errorf("graph endpoint returned a non-JSON reply: %w", err)
	}
	if httpStatus >= 400 {
		if pe := decodeProblem(wire.Error); pe != nil {
			if pe.Status == 0 {
				pe.Status = httpStatus
			}
			return nil, pe
		}
		return nil, decodeBareProblem(body, httpStatus)
	}
	if hasContent(wire.Error) && len(wire.Rows) == 0 && len(wire.Columns) == 0 {
		// A 200 whose body is only an error field is still a failure - surface it.
		if pe := decodeProblem(wire.Error); pe != nil {
			if pe.Status == 0 {
				pe.Status = httpStatus
			}
			return nil, pe
		}
	}

	res := &GraphResult{
		Columns:    wire.Columns,
		Statistics: wire.Statistics,
		Raw:        append(json.RawMessage(nil), body...),
		Rows:       make([]map[string]any, 0, len(wire.Rows)),
	}
	for _, rr := range wire.Rows {
		var obj map[string]any
		if json.Unmarshal(rr, &obj) == nil {
			res.Rows = append(res.Rows, obj)
			continue
		}
		var arr []any
		if json.Unmarshal(rr, &arr) == nil {
			obj = make(map[string]any, len(wire.Columns))
			for i, col := range wire.Columns {
				if i < len(arr) {
					obj[col] = arr[i]
				}
			}
			res.Rows = append(res.Rows, obj)
		}
		// A row that is neither object nor array is dropped, not fatal (liberal-in).
	}
	return res, nil
}

// FlowEvent is one raw Server-Sent Event from a gallery/run flow: the event name
// (step, graph, ... - whatever the run emits) and its verbatim data payload.
type FlowEvent struct {
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

// RunFlow executes a catalog FLOW recipe by slug via the console gallery/run
// endpoint and emits every streamed event on emit() until the stream ends or ctx is
// cancelled. consoleURL "" uses the default console.
//
// The console contract is {"slug","value","paramValues"}: value is the ONE primary
// entity (e.g. a domain / IP / ASN), paramValues carries every secondary input +
// tuning knob. (A workflow that omits value runs against its documented default.)
// This is the exact shape the reference MCP runner sends: sending an "inputs" map
// instead is silently ignored by the console and the flow falls back to its default.
func (c *Client) RunFlow(ctx context.Context, consoleURL, slug, value string, paramValues map[string]any, emit func(FlowEvent)) error {
	if c.cred.IsZero() {
		return &ProblemError{Status: 401, Title: "no key",
			Detail: "flow recipes need an API key - run 'whisper login', set WHISPER_API_KEY, or pass --key"}
	}
	reqBody := map[string]any{"slug": slug}
	if strings.TrimSpace(value) != "" {
		reqBody["value"] = value
	}
	if len(paramValues) > 0 {
		reqBody["paramValues"] = paramValues
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("encoding the flow request: %w", err)
	}
	runURL := consoleBase(consoleURL) + "/api/gallery/run"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, runURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", userAgent)
	c.applyAuth(req)

	// The SSE client (no overall timeout) carries the stream; ctx bounds it.
	resp, err := c.sse.Do(req)
	if err != nil {
		return fmt.Errorf("flow endpoint unreachable at %s: %w", runURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return decodeBareProblem(raw, resp.StatusCode)
	}
	return readFlowSSE(ctx, resp.Body, emit)
}

// readFlowSSE reads a gallery/run SSE stream, emitting each event VERBATIM (name +
// data) - unlike the monitor reader it imposes no event schema, because a flow's
// step/graph payloads are the result. Liberal framing per the SSE spec: multi-line
// data is joined, comments (keep-alives) are skipped, unknown fields ignored.
func readFlowSSE(ctx context.Context, r io.Reader, emit func(FlowEvent)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // a step's graph payload can be fat

	var eventName string
	var dataLines []string

	flush := func() {
		defer func() { eventName = ""; dataLines = dataLines[:0] }()
		if len(dataLines) == 0 {
			return
		}
		joined := strings.Join(dataLines, "\n")
		if strings.TrimSpace(joined) == "" {
			return
		}
		emit(FlowEvent{Event: eventName, Data: json.RawMessage(joined)})
	}

	for sc.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, ":"):
			// keep-alive comment - carries no data
		case strings.HasPrefix(line, "event:"):
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			d := strings.TrimPrefix(line, "data:")
			d = strings.TrimPrefix(d, " ")
			dataLines = append(dataLines, d)
		default:
			// id:/retry:/unknown fields - ignore (liberal-in)
		}
	}
	flush() // a final event with no trailing blank line still counts
	if err := sc.Err(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	return ctx.Err()
}
