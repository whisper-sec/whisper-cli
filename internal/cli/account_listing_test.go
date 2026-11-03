// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/projcfg"
	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// account_listing_test.go pins one rule over every reader of the account's agents: a listing
// that did not genuinely answer is never read as an account with no agents in it, and never as
// proof that a saved agent is gone. Each reader is run against the whole failure corpus, then
// against two controls: a listing that answers empty, and one that lists the agent.

// listingReadError is the sentence every reader leads with when the listing did not answer.
const listingReadError = "could not read this account's agents"

// emptyAccountWords are what a reader says about an account it has read and found empty, or a
// saved agent it has proven gone. None of them may follow a listing that did not answer.
var emptyAccountWords = []string{"no agents yet", "no longer in your account", "not found in your account",
	"no agent named", "has no agents left"}

// mustNotReadAsEmpty fails when text claims something about the account it could not know.
func mustNotReadAsEmpty(t *testing.T, text string) {
	t.Helper()
	for _, w := range emptyAccountWords {
		if strings.Contains(text, w) {
			t.Fatalf("a listing that did not answer was read as an answer (%q): %s", w, text)
		}
	}
}

// mustNotMint fails when any op that creates an identity ran.
func mustNotMint(t *testing.T, ops []string, extra ...string) {
	t.Helper()
	for _, op := range ops {
		for _, bad := range append([]string{"register", "identity"}, extra...) {
			if op == bad {
				t.Fatalf("op:%s ran although the listing did not answer; ops %v", op, ops)
			}
		}
	}
}

// answeringAccount points the globals at a stub whose listing answers with agents (nil is an
// empty account) and returns the recorded calls.
func answeringAccount(t *testing.T, agents []agentChoice) *[]recordedCall {
	t.Helper()
	var seen []recordedCall
	srv := recordingServer(t, agents, &seen)
	t.Cleanup(srv.Close)
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
	t.Cleanup(func() { g = savedG })
	return &seen
}

func globalClient(t *testing.T) *client.Client {
	t.Helper()
	c, err := resolveClient(true, false)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const savedAddr = "2a04:2a01:9::5a7e"

// runConnectSaved runs `whisper connect --tier socks5 --name box-1` with the saved agent file
// holding saved ("" for none).
func runConnectSaved(t *testing.T, saved string) (error, string) {
	t.Helper()
	t.Cleanup(stubEgressTail(t))
	af := filepath.Join(t.TempDir(), "agent")
	if saved != "" {
		if err := client.SaveAgent(af, saved); err != nil {
			t.Fatal(err)
		}
	}
	cmd := newConnectCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--agent-file", af, "--tier", "socks5", "--name", "box-1"})
	var err error
	_, stderr := captureStd(t, func() { err = cmd.Execute() })
	if err != nil {
		stderr += "\n" + friendly(err)
	}
	return err, stderr
}

func TestConnectRefusesOnAListingThatDidNotAnswer(t *testing.T) {
	for _, saved := range []string{"", "scout"} {
		for _, f := range listingFailures() {
			t.Run("saved="+saved+"/"+f.name, func(t *testing.T) {
				testenv.HermeticHome(t)
				ops := failingListing(t, f)
				err, out := runConnectSaved(t, saved)
				if err == nil || !strings.Contains(out, listingReadError) {
					t.Fatalf("connect must say it could not read the account, got %v: %s", err, out)
				}
				mustNotReadAsEmpty(t, out)
				mustNotMint(t, ops(), "connect")
			})
		}
	}
}

// A saved /128 is the person's own choice: a listing that did not answer keeps it, and never
// replaces it with a fresh identity or calls it gone.
func TestConnectKeepsASavedAddressOnAListingThatDidNotAnswer(t *testing.T) {
	for _, f := range listingFailures() {
		t.Run(f.name, func(t *testing.T) {
			testenv.HermeticHome(t)
			ops := failingListing(t, f)
			_, out := runConnectSaved(t, savedAddr)
			mustNotReadAsEmpty(t, out)
			mustNotMint(t, ops())
		})
	}
}

func TestConnectControls(t *testing.T) {
	for _, saved := range []string{"", "scout", savedAddr} {
		t.Run("empty/saved="+saved, func(t *testing.T) {
			testenv.HermeticHome(t)
			seen := answeringAccount(t, nil)
			if err, out := runConnectSaved(t, saved); err != nil {
				t.Fatalf("connect on an empty account: %v: %s", err, out)
			}
			if _, ok := bodyForOp(*seen, "identity"); !ok {
				t.Fatalf("an empty account must get its named agent created, ops %v", opsSeen(*seen))
			}
		})
		t.Run("listed/saved="+saved, func(t *testing.T) {
			testenv.HermeticHome(t)
			seen := answeringAccount(t, []agentChoice{{name: "scout", addr: savedAddr}})
			if err, out := runConnectSaved(t, saved); err != nil {
				t.Fatalf("connect with the agent listed: %v: %s", err, out)
			}
			body, ok := bodyForOp(*seen, "connect")
			if saved == "" {
				// Nothing saved and --name names no agent, so connect creates box-1 (op:register,
				// since op:identity would hand back an existing agent) and binds it. It used to let the
				// control plane pick one of the account's agents.
				reg, rok := bodyForOp(*seen, "register")
				if !rok || !strings.Contains(reg, "box-1") || containsOp(opsSeen(*seen), "identity") {
					t.Fatalf("connect must create the named agent, ops %v", opsSeen(*seen))
				}
				if !ok || !strings.Contains(body, "2a04:2a01:9::beef") || strings.Contains(body, savedAddr) {
					t.Fatalf("connect must bind the created agent, body %q", body)
				}
				return
			}
			if !ok || !strings.Contains(body, savedAddr) {
				t.Fatalf("connect must bind the saved agent, body %q ops %v", body, opsSeen(*seen))
			}
			mustNotMint(t, opsSeen(*seen))
		})
	}
}

// The egress check's follow-up question, whose answer the panel shows: is the identity gone?
func TestIdentityCheckDoesNotConcludeGoneFromAListingThatDidNotAnswer(t *testing.T) {
	cause := &egressCheckError{cause: errors.New("echo failed"), addr: savedAddr}
	for _, f := range listingFailures() {
		t.Run(f.name, func(t *testing.T) {
			testenv.HermeticHome(t)
			failingListing(t, f)
			err := proveIdentityAfterCheck(globalClient(t), cause)
			var gone *identityGoneError
			if errors.As(err, &gone) || !errors.Is(err, cause) {
				t.Fatalf("a listing that did not answer proves nothing, got %v", err)
			}
		})
	}
	t.Run("empty", func(t *testing.T) {
		answeringAccount(t, nil)
		var gone *identityGoneError
		if err := proveIdentityAfterCheck(globalClient(t), cause); !errors.As(err, &gone) {
			t.Fatalf("an answered listing without the agent proves it gone, got %v", err)
		}
	})
	t.Run("listed", func(t *testing.T) {
		answeringAccount(t, []agentChoice{{name: "scout", addr: savedAddr}})
		if err := proveIdentityAfterCheck(globalClient(t), cause); !errors.Is(err, cause) {
			t.Fatalf("the agent is listed, so the check's own error stands, got %v", err)
		}
	})
}

func TestGuidedRefusesOnAListingThatDidNotAnswer(t *testing.T) {
	for _, f := range listingFailures() {
		t.Run(f.name, func(t *testing.T) {
			testenv.HermeticHome(t)
			gio, _, errb, restore := guidedHarness(t, "", "", "")
			t.Cleanup(restore)
			ops := failingListing(t, f)
			err := runGuided(guidedOptions{name: "scout", tty: false}, gio)
			if err == nil || !strings.Contains(friendly(err), listingReadError) {
				t.Fatalf("guided setup must say it could not read the account, got %v", err)
			}
			mustNotReadAsEmpty(t, friendly(err)+errb.String())
			mustNotMint(t, ops())
		})
	}
	t.Run("empty", func(t *testing.T) {
		testenv.HermeticHome(t)
		gio, _, _, restore := guidedHarness(t, "", "", "")
		t.Cleanup(restore)
		seen := answeringAccount(t, nil)
		if err := runGuided(guidedOptions{name: "scout", tty: false}, gio); err != nil {
			t.Fatal(err)
		}
		if _, ok := bodyForOp(*seen, "identity"); !ok {
			t.Fatalf("an empty account gets its first agent, ops %v", opsSeen(*seen))
		}
	})
	t.Run("listed", func(t *testing.T) {
		testenv.HermeticHome(t)
		gio, _, errb, restore := guidedHarness(t, "", "", "")
		t.Cleanup(restore)
		seen := answeringAccount(t, []agentChoice{{name: "solo", addr: savedAddr}})
		// Headless, the only agent is used when it is this host's saved one.
		if err := client.SaveAgent("", savedAddr); err != nil {
			t.Fatal(err)
		}
		if err := runGuided(guidedOptions{tty: false}, gio); err != nil || !strings.Contains(errb.String(), "solo") {
			t.Fatalf("the only agent is used, got %v: %s", err, errb.String())
		}
		mustNotMint(t, opsSeen(*seen))
	})
}

func TestInitRefusesOnAListingThatDidNotAnswer(t *testing.T) {
	run := func(t *testing.T) (string, error) {
		sel, _, err := resolveProjectAgent(globalClient(t), initOptions{}, projcfg.Paths{},
			filepath.Join(t.TempDir(), "agent"), nil)
		return sel, err
	}
	for _, f := range listingFailures() {
		t.Run(f.name, func(t *testing.T) {
			testenv.HermeticHome(t)
			ops := failingListing(t, f)
			_, err := run(t)
			if err == nil || !strings.Contains(friendly(err), listingReadError) {
				t.Fatalf("init must say it could not read the account, got %v", err)
			}
			mustNotReadAsEmpty(t, friendly(err))
			mustNotMint(t, ops())
		})
	}
	t.Run("empty", func(t *testing.T) {
		testenv.HermeticHome(t)
		answeringAccount(t, nil)
		if _, err := run(t); err == nil || !strings.Contains(err.Error(), "no agents yet") {
			t.Fatalf("an empty account asks for a name, got %v", err)
		}
	})
	t.Run("listed", func(t *testing.T) {
		// Nothing pinned and nothing saved for this host: the project does not take whichever
		// agent the account lists first, it names the fix.
		testenv.HermeticHome(t)
		seen := answeringAccount(t, []agentChoice{{name: "scout", addr: savedAddr}})
		if sel, err := run(t); err == nil || sel != "" || !strings.Contains(err.Error(), "scout") {
			t.Fatalf("an unnamed init refuses, naming the agents, got %q %v", sel, err)
		}
		mustNotMint(t, opsSeen(*seen))
	})
	t.Run("saved for this host", func(t *testing.T) {
		testenv.HermeticHome(t)
		answeringAccount(t, []agentChoice{{name: "other", addr: "2a04:2a01:9::0e"}, {name: "scout", addr: savedAddr}})
		if err := client.SaveAgent("", savedAddr); err != nil {
			t.Fatal(err)
		}
		if sel, err := run(t); err != nil || sel != savedAddr {
			t.Fatalf("the project takes this host's saved agent, got %q %v", sel, err)
		}
	})
}

// The name lookups: connect's --agent {name} and the id lookup behind use, status, revoke and
// init --agent. A failed read is not "no agent by that name".
func TestNameLookupsRefuseOnAListingThatDidNotAnswer(t *testing.T) {
	lookups := map[string]func(c *client.Client) (string, error){
		"connect selector": func(c *client.Client) (string, error) {
			return resolveConnectAgent(c, context.Background(), "scout")
		},
		"agent address": func(c *client.Client) (string, error) { return resolveAddress(c, "scout") },
	}
	for name, lookup := range lookups {
		for _, f := range listingFailures() {
			t.Run(name+"/"+f.name, func(t *testing.T) {
				failingListing(t, f)
				_, err := lookup(globalClient(t))
				if err == nil || !strings.Contains(friendly(err), listingReadError) || isNotFoundProblem(err) {
					t.Fatalf("a failed read must say so and is not a not-found, got %v", err)
				}
				mustNotReadAsEmpty(t, friendly(err))
			})
		}
		t.Run(name+"/empty", func(t *testing.T) {
			answeringAccount(t, nil)
			if _, err := lookup(globalClient(t)); !isNotFoundProblem(err) {
				t.Fatalf("an empty account has no agent by that name, got %v", err)
			}
		})
		t.Run(name+"/listed", func(t *testing.T) {
			answeringAccount(t, []agentChoice{{name: "scout", addr: savedAddr}})
			if got, err := lookup(globalClient(t)); err != nil || got != savedAddr {
				t.Fatalf("the listed agent resolves, got %q %v", got, err)
			}
		})
	}
}

func TestWhaleFleetRefusesOnAListingThatDidNotAnswer(t *testing.T) {
	for _, f := range listingFailures() {
		t.Run(f.name, func(t *testing.T) {
			failingListing(t, f)
			cx, cancel := ctx()
			defer cancel()
			if peers, err := whaleFleet(cx, globalClient(t)); err == nil {
				t.Fatalf("a failed read must be an error, never a fleet of %d", len(peers))
			}
		})
	}
	t.Run("empty", func(t *testing.T) {
		answeringAccount(t, nil)
		if peers, err := whaleFleet(context.Background(), globalClient(t)); err != nil || len(peers) != 0 {
			t.Fatalf("an empty account is an empty fleet, got %v %v", peers, err)
		}
	})
	t.Run("listed", func(t *testing.T) {
		answeringAccount(t, []agentChoice{{name: "scout", addr: savedAddr}})
		if peers, err := whaleFleet(context.Background(), globalClient(t)); err != nil || len(peers) != 1 {
			t.Fatalf("the listed agent is the fleet, got %v %v", peers, err)
		}
	})
}

func runList(t *testing.T) (error, string) {
	t.Helper()
	cmd := newListCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{})
	var err error
	stdout, stderr := captureStd(t, func() { err = cmd.Execute() })
	if err != nil {
		stderr += "\n" + friendly(err)
	}
	return err, stdout + stderr
}

func TestListRefusesOnAListingThatDidNotAnswer(t *testing.T) {
	for _, f := range listingFailures() {
		t.Run(f.name, func(t *testing.T) {
			failingListing(t, f)
			err, out := runList(t)
			if err == nil || !strings.Contains(out, listingReadError) {
				t.Fatalf("whisper list must say it could not read the account, got %v: %s", err, out)
			}
			mustNotReadAsEmpty(t, out)
		})
	}
	t.Run("empty", func(t *testing.T) {
		answeringAccount(t, nil)
		if err, out := runList(t); err != nil || !strings.Contains(out, "no agents yet") {
			t.Fatalf("an empty account says so, got %v: %s", err, out)
		}
	})
	t.Run("listed", func(t *testing.T) {
		answeringAccount(t, []agentChoice{{name: "scout", addr: savedAddr}})
		if err, out := runList(t); err != nil || !strings.Contains(out, savedAddr) {
			t.Fatalf("the listed agent is shown, got %v: %s", err, out)
		}
	})
}

func runCreateReuse(t *testing.T) (error, string) {
	t.Helper()
	cmd := newCreateCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--register", "--reuse", "--name", "box-1"})
	var err error
	stdout, stderr := captureStd(t, func() { err = cmd.Execute() })
	if err != nil {
		stderr += "\n" + friendly(err)
	}
	return err, stdout + stderr
}

// `whisper create --register --reuse` asks the account whether the name is taken before it
// registers; a failed read is not "the name is free".
func TestCreateReuseRefusesOnAListingThatDidNotAnswer(t *testing.T) {
	for _, f := range listingFailures() {
		t.Run(f.name, func(t *testing.T) {
			testenv.HermeticHome(t)
			ops := failingListing(t, f)
			err, out := runCreateReuse(t)
			if err == nil {
				t.Fatalf("create --reuse must refuse when the listing did not answer; ops %v", ops())
			}
			for _, want := range []string{listingReadError, "Nothing was registered",
				"'whisper create --register --reuse --name box-1'"} {
				if !strings.Contains(out, want) {
					t.Fatalf("the refusal must say %q, got: %s", want, out)
				}
			}
			mustNotMint(t, ops())
		})
	}
	t.Run("empty", func(t *testing.T) {
		testenv.HermeticHome(t)
		seen := answeringAccount(t, nil)
		if err, out := runCreateReuse(t); err != nil {
			t.Fatalf("a free name registers: %v: %s", err, out)
		}
		if _, ok := bodyForOp(*seen, "register"); !ok {
			t.Fatalf("a free name registers, ops %v", opsSeen(*seen))
		}
	})
	t.Run("listed", func(t *testing.T) {
		testenv.HermeticHome(t)
		seen := answeringAccount(t, []agentChoice{{name: "box-1", addr: savedAddr}})
		if err, out := runCreateReuse(t); err != nil || !strings.Contains(out, savedAddr) {
			t.Fatalf("the listed agent is reused, got %v: %s", err, out)
		}
		mustNotMint(t, opsSeen(*seen))
	})
}

// `whisper login` checks a new key by listing the account; a reply with no listing in it does
// not verify the key.
func TestLoginDoesNotVerifyOnAListingThatDidNotAnswer(t *testing.T) {
	run := func(t *testing.T) string {
		testenv.HermeticHome(t)
		g.keyFile = filepath.Join(t.TempDir(), "key")
		g.quiet = false
		var err error
		_, stderr := captureStd(t, func() { err = saveAndVerify("whisper_live_test") })
		if err != nil {
			t.Fatalf("a saved key is saved whatever the check says: %v", err)
		}
		return stderr
	}
	for _, f := range listingFailures() {
		t.Run(f.name, func(t *testing.T) {
			failingListing(t, f)
			if out := run(t); strings.Contains(out, "verified") {
				t.Fatalf("a reply with no listing must not verify the key: %s", out)
			}
		})
	}
	for name, agents := range map[string][]agentChoice{"empty": nil, "listed": {{name: "scout", addr: savedAddr}}} {
		t.Run(name, func(t *testing.T) {
			answeringAccount(t, agents)
			if out := run(t); !strings.Contains(out, "key saved and verified") {
				t.Fatalf("an answered listing verifies the key: %s", out)
			}
		})
	}
}
