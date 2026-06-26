// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// --- login -----------------------------------------------------------------------

// deviceFlowFn is the seam the login command calls to run the browser device flow. It
// returns the issued API key. It is a package var so a test can inject a fake without a
// real browser or console (the real implementation calls the console over HTTPS). It
// MUST never return the key in an error and never log it.
var deviceFlowFn = runDeviceFlow

func newLoginCmd() *cobra.Command {
	var (
		web    bool
		manual bool
	)
	cmd := &cobra.Command{
		Use:   "login [key]",
		Short: "Sign in at console.whisper.security (or save an API key) to ~/.config/whisper-ns/key",
		Long: "Sign in to Whisper. With NO key argument on a terminal you can just press Enter to\n" +
			"open console.whisper.security in your browser and approve the login (the device\n" +
			"flow, RFC 8628) — or paste an API key instead. Pass the key as an argument to skip\n" +
			"the prompt entirely. The key is saved to the key file (mode 600) so every later\n" +
			"command uses it with no further config, then verified with a quick op:list.\n\n" +
			"  whisper login                 # press Enter to sign in via browser, or paste a key\n" +
			"  whisper login <key>           # save a key non-interactively\n" +
			"  whisper login --web           # force the browser device flow (no prompt)\n" +
			"  whisper login --manual        # force the manual key prompt",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if web && manual {
				return usageErr("choose at most one of --web / --manual")
			}

			// 1) An explicit key argument always wins (scriptable, unchanged behaviour).
			if len(args) == 1 {
				return saveAndVerify(strings.TrimSpace(args[0]))
			}

			// 2) --web forces the device flow even with no TTY (e.g. paste the URL by hand).
			if web {
				key, err := deviceFlowFn(g.consoleURL, g.timeout)
				if err != nil {
					return err
				}
				return saveAndVerify(key)
			}

			// 3) --manual forces the bare key prompt (interactive) or errors with guidance.
			if manual {
				if !isInteractive() {
					return usageErr("no key supplied — usage: whisper login <key> (get one at https://console.whisper.security/settings)")
				}
				k, err := promptForKey()
				if err != nil {
					return err
				}
				return saveAndVerify(strings.TrimSpace(k))
			}

			// 4) Default interactive path: offer the browser sign-in, accept a pasted key.
			if isInteractive() {
				k, err := promptLoginChoice()
				if err != nil {
					return err
				}
				if k == "" {
					// Empty (Enter pressed) -> the browser device flow.
					key, err := deviceFlowFn(g.consoleURL, g.timeout)
					if err != nil {
						return err
					}
					return saveAndVerify(key)
				}
				// A pasted key -> the manual save+verify path.
				return saveAndVerify(k)
			}

			// 5) No TTY and no key: a clear, helpful error (never an opaque hang).
			return usageErr("no key supplied — usage: whisper login <key>, or 'whisper login --web' to sign in via browser (get a key at https://console.whisper.security/settings)")
		},
	}
	cmd.Flags().BoolVar(&web, "web", false, "force the browser sign-in (device flow) — useful with no key on hand")
	cmd.Flags().BoolVar(&web, "device", false, "alias for --web (the RFC 8628 device flow)")
	cmd.Flags().BoolVar(&manual, "manual", false, "force the manual API-key prompt instead of the browser sign-in")
	_ = cmd.Flags().MarkHidden("device") // keep --help tidy; --web is the documented name
	return cmd
}

// promptLoginChoice asks the user to either press Enter (browser sign-in) or paste a
// key. It returns "" for the Enter case and the trimmed key otherwise. Reading from
// stdin mirrors promptForKey (the key-ladder last rung) so it behaves identically on a
// terminal.
func promptLoginChoice() (string, error) {
	fmt.Fprint(os.Stderr, "Press Enter to sign in at console.whisper.security (opens your browser), or paste your API key: ")
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		return strings.TrimSpace(sc.Text()), nil
	}
	return "", sc.Err()
}

// runDeviceFlow runs the RFC 8628 device-authorization grant against the console: start
// the authorization, show + best-effort open the verification URL, then poll for the
// issued key until approved/expired/timeout. The api_key and device_code are never
// logged. consoleURL "" => the default; timeout bounds each HTTP call (the overall flow
// lifetime comes from the console's expires_in).
func runDeviceFlow(consoleURL string, timeout time.Duration) (string, error) {
	hc := client.DeviceHTTPClient()
	if timeout > 0 {
		hc.Timeout = timeout
	}

	authCtx, cancel := context.WithTimeout(context.Background(), deviceCallTimeout(timeout))
	auth, err := client.DeviceAuthorize(authCtx, hc, consoleURL)
	cancel()
	if err != nil {
		return "", err
	}

	// Tell the user exactly what to do (on stderr — stdout stays clean), then make a
	// best-effort attempt to open the browser. A failed open is fine: the URL is printed.
	openURL := auth.OpenURL()
	fmt.Fprintf(os.Stderr, "whisper: open %s to authorize (code: %s)\n", openURL, auth.UserCode)
	if err := openBrowser(openURL); err != nil {
		fmt.Fprintln(os.Stderr, "whisper: couldn't open a browser automatically — open the URL above by hand")
	}
	fmt.Fprintln(os.Stderr, "whisper: waiting for approval…")

	// Poll until the console approves (the deadline is its expires_in, not our per-call
	// timeout). A SIGINT-style ctx cancel would abort promptly; here we use Background so
	// the poll runs for the full device-code lifetime.
	pollCtx, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	key, err := client.PollDeviceToken(pollCtx, hc, consoleURL, auth.DeviceCode, auth.PollInterval(), auth.Lifetime())
	if err != nil {
		return "", err
	}
	return key, nil
}

// deviceCallTimeout bounds the single authorize call: the global per-call timeout when
// positive, else a sane default.
func deviceCallTimeout(timeout time.Duration) time.Duration {
	if timeout > 0 {
		return timeout
	}
	return client.DeviceClientTimeout
}

// saveAndVerify writes the key to the key file (mode 600) and verifies it with a quick
// op:list. A saved-but-unverified key is still saved (fail-soft) — verification failure
// is reported but is not fatal, exactly like the prior behaviour.
func saveAndVerify(key string) error {
	if key == "" {
		return usageErr("no key supplied — usage: whisper login <key> (get one at https://console.whisper.security/settings)")
	}
	path := g.keyFile
	if path == "" {
		path = client.DefaultKeyFile()
	}
	if err := client.SaveKey(path, key); err != nil {
		return fmt.Errorf("could not save the key to %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "whisper: key saved to %s\n", path)

	// Verify (fail-soft: a saved-but-unverified key is still saved).
	c := client.New(client.Config{
		ControlURL: g.controlURL,
		Cred:       client.Credential{Value: key, Source: client.SourceFile},
		Timeout:    g.timeout,
	})
	cx, cancel := ctx()
	defer cancel()
	env, err := c.Agents(cx, "list", map[string]any{"kind": "agents"})
	if err != nil || env == nil || !env.Ok {
		fmt.Fprintln(os.Stderr, "whisper: saved — but the control plane didn't accept it yet (check the key / connectivity)")
		return nil
	}
	fmt.Fprintln(os.Stderr, "whisper: key saved and verified")
	return nil
}

// --- config ----------------------------------------------------------------------

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show the resolved configuration (endpoints + which key source is in effect)",
		Long: "Print the effective configuration: the control/monitor/RDAP endpoints and WHICH\n" +
			"rung of the key ladder is providing the credential — so an operator can see at a\n" +
			"glance what the CLI will use (zero-config clarity). The key value is NEVER printed.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := client.KeyLadderOptions{
				FlagKey:    g.key,
				FlagBearer: g.bearer,
				KeyFile:    g.keyFile,
				AllowEnv:   true,
				AllowFile:  true,
			}
			cred, _ := client.ResolveCredential(opts)
			keyFile := g.keyFile
			if keyFile == "" {
				keyFile = client.DefaultKeyFile()
			}
			cfg := map[string]any{
				"control_url": orVal(g.controlURL, client.DefaultControlURL),
				"monitor_url": orVal(g.monitorURL, client.DefaultMonitorURL),
				"rdap_url":    orVal(g.rdapURL, client.DefaultRDAPURL),
				"console_url": orVal(g.consoleURL, client.DefaultConsoleURL),
				"key_file":    keyFile,
				"key_source":  string(cred.Source),
				"key_present": !cred.IsZero(),
				"auth_scheme": authScheme(cred),
				"version":     Version,
			}
			if g.jsonOut {
				emitJSONValue(cfg)
				return nil
			}
			rows := [][]string{
				{"control_url", cfg["control_url"].(string)},
				{"monitor_url", cfg["monitor_url"].(string)},
				{"rdap_url", cfg["rdap_url"].(string)},
				{"console_url", cfg["console_url"].(string)},
				{"key_file", cfg["key_file"].(string)},
				{"key_source", cfg["key_source"].(string)},
				{"key_present", fmt.Sprintf("%v", cfg["key_present"])},
				{"auth_scheme", cfg["auth_scheme"].(string)},
				{"version", cfg["version"].(string)},
			}
			printTable([]string{"SETTING", "VALUE"}, rows)
			return nil
		},
	}
	return cmd
}

func authScheme(c client.Credential) string {
	if c.IsZero() {
		return "none"
	}
	if c.Bearer {
		return "Authorization: Bearer"
	}
	return "X-API-Key"
}
