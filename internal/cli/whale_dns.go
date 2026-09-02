// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_dns.go is `whisper whale dns`: the resolver profile in effect, and a query that
// shows the graph's view of the name beside the answer.
//
// The one design rule here, and it is a security rule, not a style one: this client does
// NOT recompute a policy verdict. Whether a name is allowed, logged or sinkholed is
// decided in exactly one place, the resolver, using the tenant's policy. If the CLI
// re-derived that decision from the tenant's block lists it would become a second place
// that could disagree with the first, and the two would drift the first time either
// changed.
//
// So the verdict shown is the resolver's own signal, read off the wire: the RCODE it
// returned and any RFC 8914 Extended DNS Error it attached (our resolver declines by
// policy with REFUSED + EDE 17 Filtered). Beside it, and clearly labelled as a different
// thing, is the graph assessment of the name: the INPUT the resolver consults, fetched
// from the same graph, never a re-run of the decision.

func newWhaleDNSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "The resolver profile in effect, queries, and the records you publish",
		Long: "Whalenet naming: which resolver this host is pointed at, what a name resolves\n" +
			"to through it, and the records your fleet publishes in its own namespace.\n\n" +
			"  status  the resolver profile in effect here, probed\n" +
			"  query   one name, with the graph's view of it beside the answer\n" +
			"  record  list, publish and remove records in your own namespace\n\n" +
			"Two things deliberately do not have a verb here, because they already have one.\n" +
			"The reverse name for an address is `whisper whale whois`, which validates it from\n" +
			"the IANA root and needs no key at all. Your resolver policy is `whisper policy`.",
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newWhaleDNSStatusCmd(), newWhaleDNSQueryCmd(), newWhaleDNSRecordCmd())
	// An unrecognised verb here used to print help and exit 0, so a typo in a script
	// reported success. asParent makes it a named, non-zero usage error.
	return asParent(cmd)
}

// --- dns status ---------------------------------------------------------------------

func newWhaleDNSStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the Whisper resolver profile this host has applied",
		Long: "Show the resolver profile `whisper resolver` applied on this host, and probe it:\n" +
			"a real query, with the round trip it took.\n\n" +
			"The DoH URL carries a device credential in its path, so it is shown with that\n" +
			"part masked. `whisper resolver --print` shows the profile in full when you need\n" +
			"to paste it somewhere.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cx, cancel := ctx()
			defer cancel()
			st := loadResolverState()
			view := map[string]any{
				"applied":     st.Mode != "" || st.ResolverIP != "" || st.DoHURL != "",
				"mode":        st.Mode,
				"os":          st.OS,
				"resolver_ip": st.ResolverIP,
				"doh_url":     maskDoHURL(st.DoHURL),
				"applied_at":  st.AppliedAt,
			}
			if st.ResolverIP != "" {
				rtt, err := probeResolver(cx, st.ResolverIP, whale.NetcheckQName, dns.TypeSOA)
				if err != nil {
					view["reachable"] = false
					view["probe_note"] = "the configured resolver did not answer: " + err.Error()
				} else {
					view["reachable"] = true
					view["rtt_ms"] = float64(rtt.Microseconds()) / 1000.0
				}
			}
			if g.jsonOut {
				emitJSONValue(view)
				return nil
			}
			if st.Mode == "" && st.ResolverIP == "" && st.DoHURL == "" {
				printTable([]string{"DNS", ""}, [][]string{{"profile", "none applied by this tool"}})
				fmt.Fprintln(os.Stdout)
				whaleNote("Point this host at Whisper DNS with `whisper resolver`. Naming is the reason to be here.")
				return nil
			}
			rows := [][]string{
				{"mode", orDash(st.Mode)},
				{"os", orDash(st.OS)},
				{"resolver", orDash(st.ResolverIP)},
				{"doh url", orDash(maskDoHURL(st.DoHURL))},
				{"applied", orDash(st.AppliedAt)},
			}
			if reachable, ok := view["reachable"].(bool); ok {
				if reachable {
					rows = append(rows, []string{"probe", "answered in " + fmtMs(view["rtt_ms"].(float64))})
				} else {
					rows = append(rows, []string{"probe", "no answer"})
				}
			}
			printTable([]string{"DNS", ""}, rows)
			if note, ok := view["probe_note"].(string); ok {
				fmt.Fprintln(os.Stdout)
				whaleNote("%s", note)
			}
			return nil
		},
	}
	return cmd
}

// maskDoHURL keeps the shape of the URL and hides the device credential in its path, so
// a status screen can be pasted into a ticket without leaking a resolve-only token.
func maskDoHURL(u string) string {
	s := strings.TrimSpace(u)
	if s == "" {
		return ""
	}
	i := strings.Index(s, "://")
	if i < 0 {
		return s
	}
	rest := s[i+3:]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return s
	}
	host, path := rest[:slash], rest[slash:]
	if path == "/dns-query" || path == "/" {
		return s
	}
	return s[:i+3] + host + "/<device-token>/dns-query"
}

// --- dns query ----------------------------------------------------------------------

func newWhaleDNSQueryCmd() *cobra.Command {
	var server string
	cmd := &cobra.Command{
		Use:   "query <name> [type]",
		Short: "Resolve a name and show the graph's view of it beside the answer",
		Long: "Resolve a name, print the answer, and show two things beside it.\n\n" +
			"The first is the resolver's OWN signal, read off the wire: the RCODE and any\n" +
			"RFC 8914 Extended DNS Error it attached. A name declined by policy comes back\n" +
			"REFUSED with EDE 17 (Filtered), and that is the verdict, straight from the only\n" +
			"place a verdict is decided.\n\n" +
			"The second is the graph's assessment of the name, which is the INPUT the resolver\n" +
			"consults, not a second opinion computed here. This client never re-derives a\n" +
			"policy decision: one decision, one place.\n\n" +
			"Type defaults to A, as tailscale's does. Any RR type name works.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, terr := whale.ParseTarget(args[0])
			if terr != nil {
				return usageErr("%s", terr.Error())
			}
			qtype := dns.TypeA
			if len(args) == 2 {
				var ok bool
				qtype, ok = dns.StringToType[strings.ToUpper(strings.TrimSpace(args[1]))]
				if !ok {
					return usageErr("%q is not a DNS record type - try A, AAAA, MX, TXT, PTR, SOA, NS", args[1])
				}
			}
			srv, srcNote := whaleResolverAddr(server)
			cx, cancel := ctx()
			defer cancel()

			view := whaleDNSQueryView{
				Name:     t.Text,
				Type:     dns.TypeToString[qtype],
				Resolver: srv,
				Via:      srcNote,
			}
			msg, rtt, err := exchangeDNS(cx, srv, dns.Fqdn(t.Text), qtype)
			if err != nil {
				view.Note = "the resolver did not answer: " + err.Error()
			} else {
				view.RTTMs = float64(rtt.Microseconds()) / 1000.0
				view.Rcode = dns.RcodeToString[msg.Rcode]
				for _, rr := range msg.Answer {
					view.Answer = append(view.Answer, strings.Join(strings.Fields(rr.String()), " "))
				}
				view.Policy, view.PolicyDetail = policySignal(msg)
			}
			view.Assessment, view.AssessNote = graphAssessment(cx, t.Text)

			if g.jsonOut {
				emitJSONValue(view)
			} else {
				renderWhaleDNSQuery(view)
			}
			if err != nil {
				return &client.ProblemError{Status: 1, Detail: view.Note}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "resolver to ask (default: the Whisper resolver this host applied, else the system resolver)")
	return cmd
}

// whaleDNSQueryView is the strict shape. Policy and Assessment are separate fields on
// purpose: one is the resolver's decision, the other is the data it decided on.
type whaleDNSQueryView struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Resolver     string   `json:"resolver"`
	Via          string   `json:"resolver_source"`
	Rcode        string   `json:"rcode,omitempty"`
	RTTMs        float64  `json:"rtt_ms,omitempty"`
	Answer       []string `json:"answer,omitempty"`
	Policy       string   `json:"policy_signal"`
	PolicyDetail string   `json:"policy_detail,omitempty"`
	Assessment   string   `json:"graph_assessment,omitempty"`
	AssessNote   string   `json:"graph_note,omitempty"`
	Note         string   `json:"note,omitempty"`
}

// policySignal reads the resolver's own verdict off the wire. Nothing is inferred: an
// answer with no EDE and a normal RCODE is reported as exactly that.
func policySignal(msg *dns.Msg) (string, string) {
	if opt := msg.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			ede, ok := o.(*dns.EDNS0_EDE)
			if !ok {
				continue
			}
			return fmt.Sprintf("EDE %d (%s)", ede.InfoCode, dns.ExtendedErrorCodeToString[ede.InfoCode]),
				strings.TrimSpace(ede.ExtraText)
		}
	}
	if msg.Rcode == dns.RcodeRefused {
		return "REFUSED", "the resolver declined the name and attached no extended error"
	}
	return "none", "the resolver answered normally and attached no policy signal"
}

// graphAssessment fetches the band the resolver consults, from the same graph, with the
// caller's key. It is labelled as the input to the decision, never as the decision. A
// keyless run simply says so: no key is not an error here.
func graphAssessment(cx context.Context, name string) (string, string) {
	c, err := resolveClient(false, false)
	if err != nil {
		c = nil
	}
	band, coverage, note := graphAssess(cx, c, name)
	switch {
	case band == "":
		return "", note
	case coverage != "":
		return band, "coverage " + coverage
	}
	return band, ""
}

// whaleResolverAddr picks the resolver to ask and says where that choice came from, so a
// surprising answer can always be traced to the server that gave it.
func whaleResolverAddr(flag string) (string, string) {
	if s := strings.TrimSpace(flag); s != "" {
		return withDNSPort(s), "--server"
	}
	if st := loadResolverState(); st.ResolverIP != "" {
		return withDNSPort(st.ResolverIP), "the Whisper resolver this host applied"
	}
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
		port := cfg.Port
		if port == "" {
			port = "53"
		}
		return net.JoinHostPort(cfg.Servers[0], port), "the system resolver, no Whisper profile applied on this host"
	}
	return "1.1.1.1:53", "a public resolver, no Whisper profile and no system resolver found"
}

func withDNSPort(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}

// exchangeDNS asks one question with EDNS0 enabled, which is what makes an Extended DNS
// Error able to ride back at all (RFC 8914 section 2: an EDE travels in the OPT record).
var exchangeDNS = func(cx context.Context, server, name string, qtype uint16) (*dns.Msg, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.SetEdns0(1232, false)
	c := &dns.Client{Timeout: whaleProbeTimeout}
	msg, rtt, err := c.ExchangeContext(cx, m, server)
	if err == nil && msg != nil && msg.Truncated {
		c.Net = "tcp"
		msg, rtt, err = c.ExchangeContext(cx, m, server)
	}
	return msg, rtt, err
}

// probeResolver is `dns status`'s liveness check: a real question, a real round trip.
func probeResolver(cx context.Context, ip, qname string, qtype uint16) (time.Duration, error) {
	_, rtt, err := exchangeDNS(cx, withDNSPort(ip), qname, qtype)
	return rtt, err
}

func renderWhaleDNSQuery(view whaleDNSQueryView) {
	rows := [][]string{
		{"question", view.Name + " " + view.Type},
		{"resolver", view.Resolver + "  via " + view.Via},
	}
	if view.Rcode != "" {
		rows = append(rows, []string{"rcode", view.Rcode + "  " + fmtMs(view.RTTMs)})
	}
	if len(view.Answer) == 0 {
		rows = append(rows, []string{"answer", "-"})
	}
	for i, a := range view.Answer {
		label := "answer"
		if i > 0 {
			label = ""
		}
		rows = append(rows, []string{label, a})
	}
	policy := view.Policy
	if view.PolicyDetail != "" {
		policy += "  " + view.PolicyDetail
	}
	rows = append(rows, []string{"policy", policy})
	if view.Assessment != "" {
		assess := view.Assessment
		if view.AssessNote != "" {
			assess += "  " + view.AssessNote
		}
		rows = append(rows, []string{"graph", assess})
	} else if view.AssessNote != "" {
		rows = append(rows, []string{"graph", view.AssessNote})
	}
	printTable([]string{"DNS QUERY", ""}, rows)
	fmt.Fprintln(os.Stdout)
	whaleNote("policy is the resolver's own signal, read off the wire. graph is the assessment the " +
		"resolver consults, not a second verdict computed here.")
	if view.Note != "" {
		whaleNote("%s", view.Note)
	}
}
