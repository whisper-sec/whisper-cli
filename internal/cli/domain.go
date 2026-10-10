// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// domain.go is `whisper domain`: bring-your-own-domain onboarding + trust. Two-tier: the
// keyless half verifies, and a key unlocks the rest.
//
// - KEYLESS (always): `whisper domain verify <apex>` runs the public trust chain (DANE-EE +
// DNSSEC + JWS) for a name under your own domain - real value with no API key.
// - KEY-GATED: submit a domain for onboarding and read its status/list - the control half
// over op:domain.
//
// WebPKI is NOT available for a domain you bring. A browser-trusted leaf is issued today only
// for apexes we operate, and no self-serve opt-in exists, so --webpki refuses with that
// explanation rather than accepting the request. It used to send acme:true and print that a
// leaf would be issued; the control plane reads no such argument, so the sentence was the
// flag's only effect. A domain submitted without it verifies and gets its DANE-EE leaf, which
// is the trust anchor either way.
func newDomainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Bring your own domain: verify (keyless), submit, and check status",
		Long: "Onboard and govern a bring-your-own-domain (BYOD) apex whose agents get a Whisper /128\n" +
			"under YOUR name. Two-tier:\n\n" +
			"  domain verify <apex>          KEYLESS - run the public DANE-EE + DNSSEC + JWS trust chain\n" +
			"  domain submit <apex>          submit for onboarding (DANE-EE, the trust anchor)\n" +
			"  domain status <apex>          the onboarding + trust state of your domain\n" +
			"  domain list                   your submitted domains\n\n" +
			"Trust is DANE-EE (no public CA). A browser-trusted WebPKI leaf is not offered for a\n" +
			"domain you bring yet; --webpki refuses and says so.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return usageErr("pick a subcommand: verify | submit | status | list (see `whisper domain --help`)")
		},
	}
	cmd.AddCommand(newDomainVerifyCmd(), newDomainSubmitCmd(), newDomainStatusCmd(), newDomainListCmd())
	return cmd
}

// newDomainVerifyCmd is the KEYLESS half: verify a name under a BYOD apex against the public trust
// chain (reuses the same keyless VerifyIdentity path `whisper verify` uses).
func newDomainVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <apex|fqdn>",
		Short: "KEYLESS: run the public DANE-EE + DNSSEC + JWS trust chain for a BYOD name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := strings.TrimSpace(args[0])
			c, err := resolveClient(false, false) // keyless
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			v, raw, status, err := c.VerifyIdentity(cx, target)
			if err != nil {
				return err
			}
			if status == 400 {
				return &client.ProblemError{Status: 400,
					Detail: problemDetail(raw, fmt.Sprintf("verify rejected %q (HTTP 400)", target))}
			}
			if g.jsonOut {
				os.Stdout.Write(raw)
				if len(raw) == 0 || raw[len(raw)-1] != '\n' {
					fmt.Fprintln(os.Stdout)
				}
			} else {
				renderVerdict(v, target)
			}
			if status == 200 && v != nil && v.IsWhisperAgent && v.DaneOK {
				return nil
			}
			return &client.ProblemError{Status: status, Detail: notVerifiedReason(v, target)}
		},
	}
}

// newDomainSubmitCmd is the KEY-GATED submit. It calls the one control verb (op:domain,
// sub-op submit). --webpki is kept so the flag a user may already have scripted refuses
// visibly instead of disappearing, which is the same reason it no longer claims success.
func newDomainSubmitCmd() *cobra.Command {
	var webpki bool
	cmd := &cobra.Command{
		Use:   "submit <apex>",
		Short: "Submit a domain for BYOD onboarding (DANE-EE)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			apex := strings.TrimSpace(args[0])
			if apex == "" {
				return usageErr("domain submit needs an apex, e.g. `whisper domain submit example.com`")
			}
			if webpki {
				return fmt.Errorf("--webpki is not available yet: browser-trusted (WebPKI) leaves are\n" +
					"issued today only for apexes we operate, and there is no self-serve opt-in for a\n" +
					"domain you bring. Re-run without --webpki to submit the domain: verification and\n" +
					"the DANE-EE leaf both work, and the WebPKI leaf is additive when it lands")
			}
			// The selector key is `name`, with `zone` accepted as a synonym. A third spelling is
			// not refused - it is IGNORED, and op:domain then answers from the unselected listing, so
			// `domain:` returned another domain's rows with ok=true 200, for any input including one
			// that cannot exist. A wrong answer, not an error.
			wire := map[string]any{"op": "submit", "name": apex}
			return runDomainOp(wire, nil)
		},
	}
	cmd.Flags().BoolVar(&webpki, "webpki", false,
		"request a browser-trusted Let's Encrypt leaf (not available yet: refuses with an explanation)")
	return cmd
}

func newDomainStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status <apex>",
		Short: "Show the onboarding + trust state of your domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			apex := strings.TrimSpace(args[0])
			return runDomainOp(map[string]any{"op": "status", "name": apex}, nil)
		},
	}
}

func newDomainListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List your submitted domains",
		Args:  cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDomainOp(map[string]any{"op": "list"}, nil)
		},
	}
}

// runDomainOp fires one op:domain control call (key-gated) and renders it. A clear note is printed
// on success via onOK. The op:domain verb is still rolling out on the public control plane; a
// clean control-plane error (never an opaque 500) surfaces when a node has not yet enabled it.
func runDomainOp(args map[string]any, onOK func()) error {
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	env, err := c.Agents(cx, "domain", args)
	if err != nil {
		return err
	}
	handled, perr := renderEnvelope(env)
	if handled || perr != nil {
		return perr
	}
	if onOK != nil {
		onOK()
	}
	renderFleet(env.Result) // op:domain rows share the enriched item shape; reuse the fleet renderer
	return nil
}
