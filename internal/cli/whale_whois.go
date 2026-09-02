// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/trustverify"
)

// whale_whois.go is `whisper whale whois <ip|name>`.
//
// Tailscale's whois answers only from inside their tailnet, for their own nodes. Ours
// answers for anyone on the internet, with no account and no key, because both halves
// of the answer are public: RDAP (RFC 9083) for who holds the address, and a
// DNSSEC-validated PTR for what it is called.
//
// WHERE the validation happens matters enough to say twice. It happens HERE, in this
// process, walking the chain from the IANA root through ip6.arpa with cli/trustverify.
// It is NOT inferred from an AD bit: our own resolver rebuilds the response header with
// QR/RA/RD and never sets AD, so anyone who assumes the resolver validated for them will
// build the wrong thing. The trust anchor is the IANA root, shipped in the binary.

func newWhaleWhoisCmd() *cobra.Command {
	var resolver string
	cmd := &cobra.Command{
		Use:   "whois <address|name>",
		Short: "Who holds an address: RDAP plus a PTR validated here, keylessly",
		Long: "Look up who holds an address and what it is called. No key, no account: both\n" +
			"halves are public.\n\n" +
			"The name half is DNSSEC-validated IN THIS PROCESS, from the IANA root trust\n" +
			"anchor compiled into this binary, through ip6.arpa. It does not read an AD bit\n" +
			"and it does not trust the resolver that answered: our own resolver never sets\n" +
			"AD, so a reader who assumed otherwise would be building on nothing.\n\n" +
			"Give an address or a name, with or without a trailing dot. Unlike tailscale's\n" +
			"whois, this works for any address on the internet, not only your own nodes.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cx, cancel := ctx()
			defer cancel()
			c, _ := resolveClient(false, false) // RDAP is public; a key is neither needed nor used
			node, err := resolveWhaleNode(cx, c, args[0])
			if err != nil {
				return err
			}
			view := whaleWhois(cx, c, node, resolver)
			if g.jsonOut {
				emitJSONValue(view)
			} else {
				renderWhaleWhois(view)
			}
			if view.Address == "" && view.PTR == "" && view.RDAPHandle == "" {
				return &client.ProblemError{Status: 404, Detail: fmt.Sprintf(
					"nothing is published about %s: no validated PTR and no RDAP object", view.Target)}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&resolver, "resolver", "", "resolver to walk the DNSSEC chain through (default: the system resolvers, then public validating ones)")
	return cmd
}

// whaleWhoisView is the strict shape. Every claim carries how it was established.
type whaleWhoisView struct {
	Target       string          `json:"target"`
	Address      string          `json:"address,omitempty"`
	PTR          string          `json:"ptr,omitempty"`
	PTRValidated bool            `json:"ptr_validated"`
	PTRNote      string          `json:"ptr_note,omitempty"`
	Forward      string          `json:"forward_confirm,omitempty"`
	TrustAnchor  string          `json:"trust_anchor"`
	ValidatedBy  string          `json:"validated_by"`
	RDAPHandle   string          `json:"rdap_handle,omitempty"`
	RDAPName     string          `json:"rdap_name,omitempty"`
	RDAPRange    string          `json:"rdap_range,omitempty"`
	RDAPCountry  string          `json:"rdap_country,omitempty"`
	RDAPHolder   string          `json:"rdap_holder,omitempty"`
	RDAPStatus   string          `json:"rdap_status,omitempty"`
	RDAPNote     string          `json:"rdap_note,omitempty"`
	RDAP         json.RawMessage `json:"rdap,omitempty"`
}

const whoisAnchorLine = "IANA DNSSEC root -> ip6.arpa -> the delegation that holds this /128"

// whaleWhois runs both halves independently, so one being down never hides the other.
func whaleWhois(cx context.Context, c *client.Client, node whaleNode, resolver string) whaleWhoisView {
	view := whaleWhoisView{
		Target:      firstNonBlank(node.Target.Text, node.Addr.String()),
		TrustAnchor: whoisAnchorLine,
		ValidatedBy: "this client, in-process (our resolver never sets AD)",
	}
	if node.Addr.IsValid() {
		view.Address = node.Addr.String()
	}

	v := trustverify.NewValidator(trustverify.NewNetResolver(strings.TrimSpace(resolver)),
		trustverify.IANARootAnchors(), time.Now())
	if node.Addr.IsValid() {
		ptr, note := validatedPTR(cx, v, node.Addr)
		view.PTR, view.PTRNote = ptr, note
		view.PTRValidated = ptr != ""
		if ptr != "" {
			view.Forward = forwardConfirm(cx, v, ptr, node.Addr)
		}
	}

	if c != nil {
		kind := client.RDAPIP
		target := view.Address
		if target == "" {
			kind, target = client.RDAPDomain, node.Target.Text
		}
		body, status, err := c.RDAP(cx, kind, target, "")
		switch {
		case err != nil:
			view.RDAPNote = "RDAP did not answer: " + friendly(err)
		case status >= 400:
			view.RDAPNote = fmt.Sprintf("RDAP returned status %d for %s", status, target)
		default:
			view.RDAP = body
			fillRDAP(&view, body)
		}
	}
	return view
}

// validatedPTR walks the reverse chain in-process and returns the name only when the
// chain actually verified. A name we could not prove is never returned as if it were
// proven: the reason comes back instead.
func validatedPTR(cx context.Context, v *trustverify.Validator, addr netip.Addr) (string, string) {
	rev, err := dns.ReverseAddr(addr.String())
	if err != nil {
		return "", "cannot form the reverse name for " + addr.String()
	}
	rrs, verr := v.ValidateRRSet(cx, rev, dns.TypePTR)
	if verr != nil {
		return "", "PTR not validated: " + verr.Error()
	}
	for _, rr := range rrs {
		if p, ok := rr.(*dns.PTR); ok && p.Ptr != "" {
			return trimDot(p.Ptr), ""
		}
	}
	return "", "the reverse chain validated but carried no PTR target"
}

// forwardConfirm checks the name points back at the address, validated the same way.
// A PTR that nothing confirms is a claim by the address holder alone.
func forwardConfirm(cx context.Context, v *trustverify.Validator, fqdn string, addr netip.Addr) string {
	rrs, err := v.ValidateRRSet(cx, dns.Fqdn(fqdn), dns.TypeAAAA)
	if err != nil {
		return "not confirmed: " + err.Error()
	}
	for _, rr := range rrs {
		if aaaa, ok := rr.(*dns.AAAA); ok {
			if a, perr := netip.ParseAddr(aaaa.AAAA.String()); perr == nil && a.Unmap() == addr.Unmap() {
				return "AAAA(" + fqdn + ") contains " + addr.String()
			}
		}
	}
	return "not confirmed: AAAA(" + fqdn + ") does not contain " + addr.String()
}

// fillRDAP lifts the handful of fields a person actually reads out of the RDAP object.
// Liberal in what it accepts: a missing field is simply absent, never an error, because
// RDAP objects differ between registries and the verbatim body is emitted anyway.
func fillRDAP(view *whaleWhoisView, body json.RawMessage) {
	var obj map[string]any
	if json.Unmarshal(body, &obj) != nil {
		view.RDAPNote = "RDAP answered with something that is not a JSON object"
		return
	}
	view.RDAPHandle = jsonStr(obj["handle"])
	view.RDAPName = jsonStr(obj["name"])
	start, end := jsonStr(obj["startAddress"]), jsonStr(obj["endAddress"])
	switch {
	case start != "" && end != "" && start != end:
		view.RDAPRange = start + " - " + end
	case start != "":
		view.RDAPRange = start
	}
	view.RDAPCountry = jsonStr(obj["country"])
	if ss, ok := obj["status"].([]any); ok {
		var parts []string
		for _, s := range ss {
			if v := jsonStr(s); v != "" {
				parts = append(parts, v)
			}
		}
		view.RDAPStatus = strings.Join(parts, ", ")
	}
	view.RDAPHolder = rdapHolder(obj)
}

// rdapHolder digs the holder's name out of the first entity's vCard, which is where
// RFC 9083 puts it (jCard: ["vcard",[["fn",{},"text","Name"],...]]).
func rdapHolder(obj map[string]any) string {
	ents, ok := obj["entities"].([]any)
	if !ok {
		return ""
	}
	for _, e := range ents {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		arr, ok := em["vcardArray"].([]any)
		if !ok || len(arr) < 2 {
			continue
		}
		props, ok := arr[1].([]any)
		if !ok {
			continue
		}
		for _, p := range props {
			pa, ok := p.([]any)
			if !ok || len(pa) < 4 {
				continue
			}
			if jsonStr(pa[0]) == "fn" {
				if v := jsonStr(pa[3]); v != "" {
					return v
				}
			}
		}
	}
	return ""
}

func jsonStr(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

// renderWhaleWhois prints one calm table and the two lines that say where the proof came
// from. Anything not established is shown as such rather than left blank.
func renderWhaleWhois(view whaleWhoisView) {
	rows := [][]string{{"target", view.Target}}
	if view.Address != "" {
		rows = append(rows, []string{"address", view.Address})
	}
	switch {
	case view.PTRValidated:
		rows = append(rows,
			[]string{"name", view.PTR},
			[]string{"name proof", "DNSSEC-validated here, from the IANA root"})
		if view.Forward != "" {
			rows = append(rows, []string{"forward confirm", view.Forward})
		}
	case view.PTRNote != "":
		rows = append(rows, []string{"name", "-"}, []string{"name proof", view.PTRNote})
	}
	if view.RDAPHandle != "" {
		rows = append(rows, []string{"rdap handle", view.RDAPHandle})
	}
	if view.RDAPName != "" {
		rows = append(rows, []string{"rdap name", view.RDAPName})
	}
	if view.RDAPRange != "" {
		rows = append(rows, []string{"range", view.RDAPRange})
	}
	if view.RDAPHolder != "" {
		rows = append(rows, []string{"holder", view.RDAPHolder})
	}
	if view.RDAPCountry != "" {
		rows = append(rows, []string{"country", view.RDAPCountry})
	}
	if view.RDAPStatus != "" {
		rows = append(rows, []string{"status", view.RDAPStatus})
	}
	printTable([]string{"WHOIS", ""}, rows)
	fmt.Fprintln(os.Stdout)
	whaleNote("trust anchor: %s", view.TrustAnchor)
	whaleNote("validated by %s. Pass --json for the verbatim RDAP object.", view.ValidatedBy)
	if view.RDAPNote != "" {
		whaleNote("%s", view.RDAPNote)
	}
}
