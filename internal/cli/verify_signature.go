// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/trustverify"
)

// maxSignatureBytes bounds the signature we will read. A compact ES256 JWS with a ballot-sized
// payload is a few kilobytes; a megabyte is generous and still never unbounded.
const maxSignatureBytes = 1 << 20

// runSignatureVerify answers one question for a stranger with no Whisper account and no API
// key: did THIS agent's OWN key sign THESE bytes?
//
// It resolves the signer's own verification key from the DNSSEC-signed
// _whisper-agentkey.<fqdn> TXT, validated from the IANA root in this process, and verifies the
// compact ES256 JWS against that key and no other. There is no fall-through: if the agent
// publishes no key of its own, the answer is no. The fleet key that every agent's did.json
// used to advertise is explicitly refused, because it would answer "yes" for everyone.
//
// The bound it does NOT cross: under hosted custody Whisper holds the matching
// private half, so a pass means the agent's KEY signed the bytes - the agent, or Whisper on
// its behalf. Every passing run prints trustverify.SignatureCustody saying exactly that.
//
// Exit 0 iff the signature verified under the signer's own DNSSEC-published key and nothing
// disagreed, so a script can gate on it.
func runSignatureVerify(target, sigPath, payloadOut, resolver string) error {
	if g.jsonOut && strings.TrimSpace(payloadOut) == "-" {
		return &client.ProblemError{Status: 400, Detail: "--json and --payload-out - both write to stdout;" +
			" pick one (write the payload to a file, or drop --json)"}
	}
	token, err := readSignature(sigPath)
	if err != nil {
		return &client.ProblemError{Status: 400, Detail: err.Error()}
	}

	cx, cancel := ctx()
	defer cancel()
	rep, err := trustverify.VerifyAgentSignature(cx, string(token), target, trustverify.Options{
		ResolverAddr: strings.TrimSpace(resolver),
	})
	if err != nil {
		return &client.ProblemError{Status: 400, Detail: err.Error()}
	}

	quiet := strings.TrimSpace(payloadOut) == "-"
	switch {
	case g.jsonOut:
		emitJSONValue(rep) // machine verdict -> STDOUT
	case !quiet:
		renderSignatureVerdict(rep)
	}
	if rep.Verdict && strings.TrimSpace(payloadOut) != "" {
		if err := writePayload(payloadOut, rep.Payload); err != nil {
			return &client.ProblemError{Status: 1, Detail: err.Error()}
		}
	}
	if rep.Verdict {
		fmt.Fprintf(os.Stderr, "whisper: %s's own key %s signed these bytes - proven from the"+
			" DNSSEC root, no Whisper API trusted.\n         %s\n", rep.Signer, shortKid(rep.Kid),
			trustverify.SignatureCustody)
		return nil
	}
	return &client.ProblemError{Status: 1, Detail: signatureNotProven(rep, target)}
}

// readSignature reads the compact JWS from a file, or from stdin when the path is "-".
func readSignature(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, maxSignatureBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read the signature from stdin: %w", err)
		}
	} else {
		raw, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
	}
	if len(raw) > maxSignatureBytes {
		return nil, fmt.Errorf("the signature is larger than the %d MiB limit; a compact JWS is a few"+
			" kilobytes", maxSignatureBytes>>20)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, fmt.Errorf("the signature is empty (expected a compact ES256 JWS)")
	}
	return raw, nil
}

// writePayload puts the VERIFIED payload where the caller asked ("-" is stdout). It is only
// ever reached on a passing verdict: unverified bytes are never handed on.
func writePayload(path string, payload []byte) error {
	if strings.TrimSpace(path) == "-" {
		if _, err := os.Stdout.Write(payload); err != nil {
			return fmt.Errorf("write the payload to stdout: %w", err)
		}
		if len(payload) > 0 && payload[len(payload)-1] != '\n' {
			fmt.Fprintln(os.Stdout)
		}
		return nil
	}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "whisper: verified payload -> %s\n", path)
	return nil
}

// renderSignatureVerdict prints the signer table and the per-check trust ledger to stdout, in
// the same shape as `verify --trustless`, so the two surfaces read as one.
func renderSignatureVerdict(rep *trustverify.SignatureReport) {
	rows := [][]string{}
	if rep.Signer != "" {
		rows = append(rows, []string{"signer", rep.Signer})
	}
	if rep.Address != "" {
		rows = append(rows, []string{"address", rep.Address})
	}
	if rep.KeyOwner != "" {
		rows = append(rows, []string{"key_record", rep.KeyOwner})
	}
	if rep.Kid != "" {
		rows = append(rows, []string{"signed_by_kid", rep.Kid})
	}
	if len(rep.PublishedKIDs) > 0 {
		rows = append(rows, []string{"published_kids", strings.Join(rep.PublishedKIDs, ", ")})
	}
	if rep.PayloadSHA256 != "" {
		rows = append(rows, []string{"payload_sha256", rep.PayloadSHA256})
	}
	if len(rows) > 0 {
		printTable([]string{"FIELD", "VALUE"}, rows)
		fmt.Fprintln(os.Stdout)
	}
	checks := make([][]string, 0, len(rep.Checks))
	for _, c := range rep.Checks {
		checks = append(checks, []string{c.Name, string(c.Status), trustLabel(c.TrustLevel), c.Detail})
	}
	printTable([]string{"CHECK", "RESULT", "TRUST", "DETAIL"}, checks)
}

// signatureNotProven is the one-line reason a signature did not verify, for the non-zero exit.
func signatureNotProven(rep *trustverify.SignatureReport, target string) string {
	for _, c := range rep.Checks {
		if c.Status == trustverify.StatusFail {
			return fmt.Sprintf("%s check failed: %s", c.Name, c.Detail)
		}
	}
	return fmt.Sprintf("the signature could not be attributed to %s", target)
}

// shortKid abbreviates a 64-hex kid for the human line (the full value is in the table).
func shortKid(kid string) string {
	if len(kid) > 16 {
		return kid[:16] + "..."
	}
	return kid
}
