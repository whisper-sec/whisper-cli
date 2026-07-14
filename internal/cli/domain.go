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

// domain.go is `whisper domain`: bring-your-own-domain onboarding + trust, TWO-TIER by design.
//
//   - KEYLESS (always): `whisper domain verify <apex>` runs the public trust chain (DANE-EE +
//     DNSSEC + JWS) for a name under your own domain - real value with no API key.
//   - KEY-GATED: submit a domain for onboarding, opt it into browser-trusted (WebPKI) certs, and
//     read its status/list - the control half over op:domain.
//
// WebPKI opt-in (b): with --webpki, `submit` asks Whisper to additionally obtain a
// browser-trusted Let's Encrypt leaf (via DNS-01 in your delegated, DNSSEC-signed BYOD zone),
// served ALONGSIDE the default DANE-EE leaf. Without it, the domain stays DANE-EE-only.
func newDomainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Bring your own domain: verify (keyless), submit, opt into WebPKI, and check status",
		Long: "Onboard and govern a bring-your-own-domain (BYOD) apex whose agents get a Whisper /128\n" +
			"under YOUR name. Two-tier:\n\n" +
			"  domain verify <apex>          KEYLESS - run the public DANE-EE + DNSSEC + JWS trust chain\n" +
			"  domain submit <apex> [--webpki]  submit for onboarding; --webpki also requests a\n" +
			"                                browser-trusted Let's Encrypt leaf (additive to DANE-EE)\n" +
			"  domain status <apex>          the onboarding + trust state of your domain\n" +
			"  domain list                   your submitted domains\n\n" +
			"Trust default is DANE-EE (no public CA); --webpki ADDS a WebPKI leaf for browser clients,\n" +
			"never replacing the DANE anchor.",
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

// newDomainSubmitCmd is the KEY-GATED submit, with the b --webpki opt-in. It calls the one
// control verb (op:domain, sub-op submit); with --webpki it sets acme:true so the backend also
// pursues a browser-trusted leaf for the opted-in apex (additive to the DANE-EE default).
func newDomainSubmitCmd() *cobra.Command {
	var webpki bool
	cmd := &cobra.Command{
		Use:   "submit <apex>",
		Short: "Submit a domain for BYOD onboarding; --webpki also requests a browser-trusted leaf",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			apex := strings.TrimSpace(args[0])
			if apex == "" {
				return usageErr("domain submit needs an apex, e.g. `whisper domain submit example.com`")
			}
			wire := map[string]any{"op": "submit", "domain": apex}
			if webpki {
				wire["acme"] = true // b: opt into a browser-trusted WebPKI leaf (additive to DANE-EE)
			}
			return runDomainOp(wire, func() {
				if webpki && !g.quiet && !g.jsonOut {
					fmt.Fprintln(os.Stderr, "whisper: WebPKI requested - a browser-trusted leaf will be issued "+
						"alongside the DANE-EE leaf once the domain verifies.")
				}
			})
		},
	}
	cmd.Flags().BoolVar(&webpki, "webpki", false,
		"also request a browser-trusted Let's Encrypt leaf (additive to the DANE-EE default)")
	return cmd
}

func newDomainStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status <apex>",
		Short: "Show the onboarding + trust state of your domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			apex := strings.TrimSpace(args[0])
			return runDomainOp(map[string]any{"op": "status", "domain": apex}, nil)
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
