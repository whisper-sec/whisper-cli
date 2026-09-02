// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/catalog"
	"github.com/whisper-sec/whisper-cli/internal/client"
)

// graph.go is `whisper graph`: the NAMED recipes of the whisper.security graph
// catalog (the same catalog the console gallery and the MCP tools expose), embedded
// in the binary. Every recipe is a subcommand, so `whisper graph <recipe> --help`
// documents its inputs and links its docs page. Direct recipes run one Cypher call
// against the public graph endpoint; flow recipes stream a multi-step run from the
// console gallery/run endpoint (SSE). All keyed (the graph is a keyed surface).

// flowRunCap bounds one flow run end-to-end: generous (a deep flow walks many
// steps), never unbounded. Ctrl-C always cancels sooner.
const flowRunCap = 10 * time.Minute

func newGraphCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "graph <recipe> [inputs...]",
		Short: "Run a named recipe from the whisper.security graph catalog",
		Long: "Run a named recipe from the embedded whisper.security graph catalog: vendor\n" +
			"identification, threat assessment, typosquats, attack surface, BGP exposure, and\n" +
			"more. `whisper graph list` shows every recipe with its docs URL; each recipe is a\n" +
			"subcommand (`whisper graph identify --help` documents its inputs).\n\n" +
			"Direct recipes answer with one result table; flow recipes stream their steps as\n" +
			"NDJSON ({\"event\",\"data\"} per line). Inputs are positional (in catalog order) or\n" +
			"named k=v; a missing input falls back to the recipe's documented default.\n" +
			"Needs your API key. Raw Cypher instead: `whisper query`.\n\n" +
			"Docs: " + catalog.DocsBase() + "/docs",
	}
	cmd.AddCommand(newGraphListCmd())
	for _, e := range catalog.All() {
		cmd.AddCommand(newGraphRecipeCmd(e))
	}
	// An unrecognised verb here used to print help and exit 0, so a typo in a script
	// reported success. asParent makes it a named, non-zero usage error.
	return asParent(cmd)
}

// newGraphListCmd prints the whole catalog: id, mode, title, docs URL.
func newGraphListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every graph recipe with its docs URL",
		Args:  cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			entries := catalog.All()
			if g.jsonOut {
				out := make([]map[string]any, 0, len(entries))
				for _, e := range entries {
					out = append(out, map[string]any{
						"id":    e.ID,
						"mode":  e.Exec.Mode,
						"title": e.Title,
						"docs":  e.DocsURL(),
					})
				}
				emitJSONValue(out)
				return nil
			}
			rows := make([][]string, 0, len(entries))
			for _, e := range entries {
				rows = append(rows, []string{e.ID, e.Exec.Mode, e.Title, e.DocsURL()})
			}
			printTable([]string{"RECIPE", "MODE", "TITLE", "DOCS"}, rows)
			fmt.Fprintf(os.Stderr, "%d recipe(s) - run one: whisper graph <recipe> [inputs...]\n", len(entries))
			return nil
		},
	}
}

// newGraphRecipeCmd builds the subcommand for ONE catalog entry, its help text
// generated from the catalog (purpose, inputs with defaults/examples, docs URL).
func newGraphRecipeCmd(e catalog.Entry) *cobra.Command {
	var named []string
	var flowParams []string
	use := e.ID
	for _, in := range e.Inputs {
		if in.Optional || in.Default != nil {
			use += " [" + in.ID + "]"
		} else {
			use += " <" + in.ID + ">"
		}
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: e.Purpose,
		Long:  recipeLong(e),
		RunE: func(cmd *cobra.Command, args []string) error {
			inputs, err := buildRecipeInputs(e, args, named)
			if err != nil {
				return err
			}
			params, err := parseKVParams(flowParams)
			if err != nil {
				return err
			}
			if e.IsDirect() {
				return runDirectRecipe(e, inputs, params)
			}
			return runFlowRecipe(e, inputs, params)
		},
	}
	if camel := e.CamelID(); camel != e.ID {
		cmd.Aliases = []string{camel}
	}
	cmd.Flags().StringArrayVar(&named, "in", nil, "a named input as k=v (alternative to positional inputs; repeatable)")
	if len(e.Params) > 0 || !e.IsDirect() {
		cmd.Flags().StringArrayVar(&flowParams, "param", nil, "a tuning parameter as k=v (repeatable; see the docs page)")
	}
	return cmd
}

// recipeLong renders the generated help body for one recipe: what it answers, its
// inputs (kind, default, examples), its tuning params, and the docs URL.
func recipeLong(e catalog.Entry) string {
	var b strings.Builder
	b.WriteString(e.Title)
	b.WriteString(" (")
	b.WriteString(e.Exec.Mode)
	b.WriteString(")\n\n")
	b.WriteString(e.Purpose)
	if e.Why != "" {
		b.WriteString("\n")
		b.WriteString(e.Why)
	}
	if len(e.Inputs) > 0 {
		b.WriteString("\n\nInputs (positional in this order, or named k=v / --in k=v):\n")
		for _, in := range e.Inputs {
			b.WriteString("  ")
			b.WriteString(in.ID)
			b.WriteString("  (")
			b.WriteString(in.Kind)
			if in.Optional {
				b.WriteString(", optional")
			}
			b.WriteString(")")
			if in.Default != nil {
				fmt.Fprintf(&b, "  default: %v", in.Default)
			}
			if len(in.Options) > 0 {
				b.WriteString("  one of: ")
				b.WriteString(strings.Join(in.Options, " | "))
			}
			if len(in.Examples) > 0 {
				parts := make([]string, 0, len(in.Examples))
				for _, ex := range in.Examples {
					parts = append(parts, fmt.Sprintf("%v", ex))
				}
				b.WriteString("  e.g. ")
				b.WriteString(strings.Join(parts, ", "))
			}
			b.WriteString("\n")
		}
	}
	if len(e.Params) > 0 {
		b.WriteString("\nParams (--param k=v):\n")
		for _, p := range e.Params {
			b.WriteString("  ")
			b.WriteString(p.Name)
			if p.Default != nil {
				fmt.Fprintf(&b, "  default: %v", p.Default)
			}
			if len(p.Options) > 0 {
				b.WriteString("  one of: ")
				b.WriteString(strings.Join(p.Options, " | "))
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("\nDocs: ")
	b.WriteString(e.DocsURL())
	return b.String()
}

// buildRecipeInputs maps the command line onto the recipe's inputs, liberally:
// positional args fill inputs in catalog order, any arg (or --in) of the form k=v
// names an input by its id OR wire paramName, and anything still missing takes the
// catalog default (or is skipped when optional). A required input with no value is
// a clear usage error naming the input. Values are coerced to the input's kind.
func buildRecipeInputs(e catalog.Entry, args, named []string) (map[string]any, error) {
	byName := map[string]catalog.Input{}
	for _, in := range e.Inputs {
		byName[strings.ToLower(in.ID)] = in
		byName[strings.ToLower(in.ParamName)] = in
	}

	out := map[string]any{}
	var positional []string
	assign := func(kv string) error {
		k, v, _ := strings.Cut(kv, "=")
		in, ok := byName[strings.ToLower(strings.TrimSpace(k))]
		if !ok {
			return usageErr("%s has no input %q - see: whisper graph %s --help", e.ID, k, e.ID)
		}
		out[in.ParamName] = coerceInput(in, v)
		return nil
	}
	for _, a := range args {
		if k, _, ok := strings.Cut(a, "="); ok && byName[strings.ToLower(strings.TrimSpace(k))].ParamName != "" {
			if err := assign(a); err != nil {
				return nil, err
			}
			continue
		}
		positional = append(positional, a)
	}
	for _, kv := range named {
		if !strings.Contains(kv, "=") {
			return nil, usageErr("bad --in %q - use k=v", kv)
		}
		if err := assign(kv); err != nil {
			return nil, err
		}
	}

	// Positional args fill the not-yet-named inputs in catalog order.
	pi := 0
	for _, in := range e.Inputs {
		if _, done := out[in.ParamName]; done {
			continue
		}
		if pi < len(positional) {
			out[in.ParamName] = coerceInput(in, positional[pi])
			pi++
		}
	}
	if pi < len(positional) {
		return nil, usageErr("%s takes %d input(s), got %d - see: whisper graph %s --help",
			e.ID, len(e.Inputs), len(positional), e.ID)
	}

	// Defaults for whatever remains; a required input with no default must be given.
	for _, in := range e.Inputs {
		if _, done := out[in.ParamName]; done {
			continue
		}
		if in.Default != nil {
			out[in.ParamName] = in.Default
			continue
		}
		if !in.Optional {
			return nil, usageErr("%s needs the %q input - see: whisper graph %s --help", e.ID, in.ID, e.ID)
		}
	}
	return out, nil
}

// coerceInput converts a command-line string to the input's wire type: numbers for
// kind "number", else JSON when it parses as a list/object/bool (liberal-in), else
// the string as given. A select value is passed through verbatim (the server owns
// validation and answers with a clear error).
func coerceInput(in catalog.Input, v string) any {
	v = strings.TrimSpace(v)
	if in.Kind == "number" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
		return v // not numeric - let the server say so, clearly
	}
	if strings.HasPrefix(v, "[") || strings.HasPrefix(v, "{") || v == "true" || v == "false" {
		return parseLooseValue(v)
	}
	return v
}

// runDirectRecipe executes a direct recipe: its catalog Cypher with the mapped
// inputs (plus any extra --param values) as query parameters.
func runDirectRecipe(e catalog.Entry, inputs, extra map[string]any) error {
	params := map[string]any{}
	for k, v := range inputs {
		params[k] = v
	}
	for k, v := range extra {
		params[k] = v
	}
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	res, err := c.GraphQuery(cx, e.Exec.Cypher, params)
	if err != nil {
		return err
	}
	renderGraphResult(res)
	return nil
}

// flowValueAndParams splits a recipe's mapped inputs into the console gallery/run
// contract: the FIRST catalog input is the primary `value` (the entity a flow runs
// against), and any further inputs plus every extra tuning param become `paramValues`
// entries keyed by their wire name. This is why a flow now actually honours its input
// instead of always running its documented default.
func flowValueAndParams(e catalog.Entry, inputs, extra map[string]any) (string, map[string]any) {
	paramValues := map[string]any{}
	var value string
	for idx, in := range e.Inputs {
		v, ok := inputs[in.ParamName]
		if !ok {
			continue
		}
		if idx == 0 {
			value = fmt.Sprintf("%v", v)
		} else {
			paramValues[in.ParamName] = v
		}
	}
	for k, v := range extra {
		paramValues[k] = v
	}
	return value, paramValues
}

// runFlowRecipe executes a flow recipe via the console gallery/run endpoint and
// writes every streamed event as one NDJSON line {"event":...,"data":...} - the
// honest, scriptable rendering of a multi-step run (pipe to jq). Ctrl-C cancels
// cleanly; the run is capped at flowRunCap so it can never hang a script forever.
func runFlowRecipe(e catalog.Entry, inputs, params map[string]any) error {
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	cx, cancel := context.WithTimeout(context.Background(), flowRunCap)
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		<-sig
		cancel()
	}()

	if !g.jsonOut && !g.quiet {
		fmt.Fprintf(os.Stderr, "whisper: running flow %s (streaming; docs: %s)\n", e.ID, e.DocsURL())
	}
	value, paramValues := flowValueAndParams(e, inputs, params)
	n := 0
	err = c.RunFlow(cx, g.consoleURL, e.ID, value, paramValues, func(ev client.FlowEvent) {
		n++
		emitFlowEvent(ev)
	})
	if err == nil || err == context.Canceled {
		if n == 0 {
			fmt.Fprintln(os.Stderr, "whisper: the flow stream ended with no events")
		} else if !g.jsonOut && !g.quiet {
			fmt.Fprintf(os.Stderr, "%d event(s)\n", n)
		}
		return nil
	}
	if cx.Err() == context.DeadlineExceeded {
		return &client.ProblemError{Status: 504,
			Detail: fmt.Sprintf("the flow did not finish within %s - it may still be running server-side", flowRunCap)}
	}
	return err
}

// emitFlowEvent writes one flow event as a compact NDJSON line. Data that is not
// valid JSON (a bare text line) is carried as a JSON string - never dropped, never
// invalid output (conservative-emit).
func emitFlowEvent(ev client.FlowEvent) {
	data := ev.Data
	if !json.Valid(data) {
		quoted, _ := json.Marshal(string(data))
		data = quoted
	}
	line, err := json.Marshal(map[string]json.RawMessage{
		"event": mustJSONString(ev.Event),
		"data":  data,
	})
	if err != nil {
		return
	}
	os.Stdout.Write(line)
	fmt.Fprintln(os.Stdout)
}

// mustJSONString renders s as a JSON string literal (marshal of a string never fails).
func mustJSONString(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}
