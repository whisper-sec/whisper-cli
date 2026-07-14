// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/catalog"
	"github.com/whisper-sec/whisper-cli/internal/client"
)

// newQueryCmd is `whisper query <cypher>`: RAW parameterised Cypher against the
// public whisper.security graph (the 3.6B-node security graph the resolver consults),
// POSTed as {"query","parameters"} with the caller's API key. The named counterpart
// is `whisper graph <recipe>`; this is the power tool for everything else.
func newQueryCmd() *cobra.Command {
	var params []string
	cmd := &cobra.Command{
		Use:   "query <cypher>",
		Short: "Run raw Cypher against the whisper.security graph",
		Long: "Run one raw Cypher statement against the Whisper security graph and print the\n" +
			"result table ({columns,rows}; --json emits the verbatim reply, statistics and all).\n" +
			"Parameterise with --param k=v (repeatable): the value is decoded as JSON when it\n" +
			"parses (numbers, booleans, lists, objects), else taken as a string, and referenced\n" +
			"in the query as $k. Needs your API key (WHISPER_API_KEY, `whisper login`, or --key).\n\n" +
			"Examples:\n" +
			"  whisper query \"CALL whisper.identify(['api.openai.com'])\"\n" +
			"  whisper query 'CALL whisper.assess([$v])' --param v=8.8.8.8\n" +
			"  whisper query 'CALL db.schema()'\n\n" +
			"Named recipes for the common questions: `whisper graph list`.\n" +
			"Docs: " + catalog.RawCypherDocsURL(),
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Liberal-accept: a query pasted as several shell words still works.
			cypher := strings.TrimSpace(strings.Join(args, " "))
			if cypher == "" {
				return usageErr("query needs a Cypher statement, e.g. whisper query 'CALL db.schema()'")
			}
			p, err := parseKVParams(params)
			if err != nil {
				return err
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			res, err := c.GraphQuery(cx, cypher, p)
			if err != nil {
				return err
			}
			renderGraphResult(res)
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&params, "param", nil, "query parameter as k=v (repeatable; v parsed as JSON when it parses, else a string)")
	return cmd
}

// parseKVParams decodes repeated k=v flags into a parameters map. Each value is
// tried as JSON first (so --param n=5, --param ok=true, --param ips='[\"a\",\"b\"]'
// carry their real types) and falls back to the raw string (Postel: liberal-in).
func parseKVParams(kvs []string) (map[string]any, error) {
	if len(kvs) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(kvs))
	for _, kv := range kvs {
		k, v, ok := strings.Cut(kv, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, usageErr("bad --param %q - use k=v, e.g. --param v=8.8.8.8", kv)
		}
		out[k] = parseLooseValue(v)
	}
	return out, nil
}

// parseLooseValue decodes a flag value as JSON when it parses (number, boolean,
// null, list, object, quoted string) and falls back to the raw string.
func parseLooseValue(v string) any {
	trimmed := strings.TrimSpace(v)
	var parsed any
	if trimmed != "" && json.Unmarshal([]byte(trimmed), &parsed) == nil {
		return parsed
	}
	return v
}

// renderGraphResult prints a graph {columns,rows} result: the verbatim reply on
// --json, else an aligned table (rows are column-keyed; cells render via asString)
// with a row count on stderr so piping stdout stays clean.
func renderGraphResult(res *client.GraphResult) {
	if g.jsonOut {
		if len(res.Raw) > 0 {
			os.Stdout.Write(res.Raw)
			if res.Raw[len(res.Raw)-1] != '\n' {
				fmt.Fprintln(os.Stdout)
			}
		} else {
			fmt.Fprintln(os.Stdout, "{}")
		}
		return
	}
	if len(res.Rows) == 0 {
		fmt.Fprintln(os.Stderr, "whisper: no rows")
		return
	}
	cols := res.Columns
	if len(cols) == 0 {
		// No column list on the wire: derive a stable (sorted) one from the first row.
		for k := range res.Rows[0] {
			cols = append(cols, k)
		}
		sort.Strings(cols)
	}
	rows := make([][]string, 0, len(res.Rows))
	for _, rec := range res.Rows {
		row := make([]string, len(cols))
		for i, col := range cols {
			row[i] = asString(rec[col])
		}
		rows = append(rows, row)
	}
	printTable(cols, rows)
	fmt.Fprintf(os.Stderr, "%d row(s)\n", len(res.Rows))
}
