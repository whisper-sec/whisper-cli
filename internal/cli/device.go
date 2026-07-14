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

// endpointHost is the consumer host that serves the Apple .mobileconfig generator
// and the install landing page. The one-tap profile URL is derived from the minted token.
const endpointHost = "endpoint.whisper.online"

// newDeviceCmd is the parent for the consumer "device" verbs. `whisper device add` is the
// one-call primitive: reuse the stored login, mint a RESOLVE-ONLY device
// credential (op:register {device:true}), and hand back every form a person or an LLM
// needs to put a phone/laptop behind Whisper - the DoH URL, the Apple one-tap profile URL,
// the Android DoT host, and the /128 identity - in a single command.
func newDeviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "device",
		Short: "Provision a resolve-only DEVICE identity (encrypted DNS for a phone/laptop)",
		Long: "Consumer device identities for endpoint.whisper.online. `whisper device add`\n" +
			"mints a resolve-only device credential (it can look up names and nothing else)\n" +
			"and prints its per-device DoH URL + Apple one-tap profile URL in one call.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newDeviceAddCmd())
	return cmd
}

func newDeviceAddCmd() *cobra.Command {
	var label string
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Mint a device identity + print its DoH URL and Apple one-tap profile",
		Long: "One call: reuse the login you already have, mint a resolve-only device token\n" +
			"(op:register {device:true}) and print everything you need to put the device\n" +
			"behind Whisper - the encrypted-DNS (DoH) URL, the Apple one-tap profile URL, the\n" +
			"Android Private-DNS host, and the device's routable /128. The token is a\n" +
			"credential: it can ONLY resolve DNS - it can never touch your account.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			args := map[string]any{"device": true}
			if s := strings.TrimSpace(label); s != "" {
				args["label"] = s
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			env, err := c.Agents(cx, "register", args)
			if err != nil {
				return err
			}
			// --json ⇒ emit the VERBATIM control-plane envelope (the device shape) so an LLM
			// or a script can parse token/doh_url/dot_host/resolver_ip/address directly.
			handled, perr := renderEnvelope(env)
			if handled || perr != nil {
				return perr
			}
			return renderDeviceAdded(env.Result)
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "a friendly name for the device (e.g. \"kitchen-ipad\")")
	return cmd
}

// mobileconfigURL is the Apple one-tap profile URL for a minted device token.
func mobileconfigURL(token string) string {
	return "https://" + endpointHost + "/apple/" + token + ".mobileconfig"
}

// renderDeviceAdded prints the human summary for `whisper device add`. Under --quiet it
// emits ONLY the DoH URL (the one load-bearing value you paste into a device), mirroring
// the create path's quiet short-circuit; otherwise it prints the full set, with the token
// shown ONCE on stdout so it is capturable.
func renderDeviceAdded(res *client.Result) error {
	recs := res.Records()
	if len(recs) == 0 {
		fmt.Fprintln(os.Stderr, "whisper: no result from the control plane")
		return nil
	}
	rec := recs[0]
	token := field(rec, "token")
	doh := field(rec, "doh_url")

	if g.quiet {
		// The device's paste-able value is its encrypted-DNS URL.
		if doh != "" {
			fmt.Fprintln(os.Stdout, doh)
		} else if token != "" {
			fmt.Fprintln(os.Stdout, mobileconfigURL(token))
		}
		return nil
	}

	fmt.Fprintln(os.Stderr, "whisper: device ready - resolve-only, encrypted DNS")
	if v := field(rec, "label"); v != "" {
		fmt.Fprintf(os.Stderr, "  label     %s\n", v)
	}
	if v := field(rec, "address"); v != "" {
		fmt.Fprintf(os.Stderr, "  identity  %s\n", v)
	}
	if doh != "" {
		fmt.Fprintf(os.Stderr, "  doh url   %s\n", doh)
	}
	if token != "" {
		fmt.Fprintf(os.Stderr, "  apple     %s\n", mobileconfigURL(token))
	}
	if v := field(rec, "dot_host"); v != "" {
		fmt.Fprintf(os.Stderr, "  android   %s  (Private DNS host)\n", v)
	}
	if v := field(rec, "resolver_ip"); v != "" {
		fmt.Fprintf(os.Stderr, "  resolver  %s\n", v)
	}
	// The token is the credential - shown ONCE on stdout so it is capturable/pipeable.
	if token != "" {
		fmt.Fprintln(os.Stderr, "  TOKEN (shown once - it lives inside the DoH URL above):")
		fmt.Fprintln(os.Stdout, token)
	}
	return nil
}
