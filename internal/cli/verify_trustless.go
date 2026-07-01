// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/trustverify"
)

// runTrustless proves an agent's identity with ZERO trust in Whisper's API (#259): it
// validates the DNSSEC chain from the IANA root IN-PROCESS, matches the served DANE-EE cert
// against the DNSSEC pin, and verifies the transparency log + identity document — then prints
// a structured verdict. Unlike the default `verify` (which trusts Whisper's /verify-identity
// endpoint to run the chain), every leg here is checked locally against public trust anchors.
//
// Human output is two tables (the identity + the per-check trust ledger) on stdout; --json
// prints the machine verdict to STDOUT (#256: machine output goes to stdout). Exit 0 iff the
// two DNSSEC-trustless legs (DNSSEC + DANE-EE) pass and no check flagged a cryptographic
// mismatch; exit 1 otherwise, so a script can gate on it.
func runTrustless(target, resolver string) error {
	cx, cancel := ctx()
	defer cancel()

	rdapBase := strings.TrimSpace(g.rdapURL)
	if rdapBase == "" {
		rdapBase = client.DefaultRDAPURL
	}
	rep, err := trustverify.Verify(cx, target, trustverify.Options{
		RDAPBase:     rdapBase,
		ResolverAddr: strings.TrimSpace(resolver),
	})
	if err != nil {
		return &client.ProblemError{Status: 400, Detail: err.Error()}
	}

	if g.jsonOut {
		emitJSONValue(rep) // machine verdict → STDOUT
	} else {
		renderTrustlessVerdict(rep, target)
	}

	if rep.Verdict {
		return nil
	}
	return &client.ProblemError{Status: 1, Detail: notTrustlesslyProven(rep, target)}
}

// renderTrustlessVerdict prints the identity table + the per-check trust ledger to stdout, and
// the one-line verdict to stderr (mirrors `verify`'s split so scripts read stdout cleanly).
func renderTrustlessVerdict(rep *trustverify.Report, target string) {
	idRows := [][]string{}
	if rep.Address != "" {
		idRows = append(idRows, []string{"address", rep.Address})
	}
	if rep.FQDN != "" {
		idRows = append(idRows, []string{"fqdn", rep.FQDN})
	}
	if rep.Agent != "" {
		idRows = append(idRows, []string{"agent", rep.Agent})
	}
	if rep.Tenant != "" {
		idRows = append(idRows, []string{"tenant", rep.Tenant})
	}
	if rep.TLSAPin != "" {
		idRows = append(idRows, []string{"tlsa_sha256", rep.TLSAPin})
	}
	if rep.ServedSPKI != "" {
		idRows = append(idRows, []string{"served_spki", rep.ServedSPKI})
	}
	if len(idRows) == 0 {
		idRows = append(idRows, []string{"target", target})
	}
	printTable([]string{"FIELD", "VALUE"}, idRows)
	fmt.Fprintln(os.Stdout)

	rows := make([][]string, 0, len(rep.Checks))
	for _, c := range rep.Checks {
		rows = append(rows, []string{c.Name, string(c.Status), trustLabel(c.TrustLevel), c.Detail})
	}
	printTable([]string{"CHECK", "RESULT", "TRUST", "DETAIL"}, rows)

	if rep.Verdict {
		fmt.Fprintf(os.Stderr, "whisper: %s is CRYPTOGRAPHICALLY PROVEN — trust anchor: %s\n",
			rep.FQDN, rep.TrustAnchor)
	} else {
		fmt.Fprintf(os.Stderr, "whisper: %s — %s\n", rep.TrustAnchor, notTrustlesslyProven(rep, target))
	}
}

// trustLabel maps a trust level to a short display token.
func trustLabel(t trustverify.TrustLevel) string {
	switch t {
	case trustverify.TrustDNSSECRoot:
		return "DNSSEC-root"
	case trustverify.TrustOnPin:
		return "trust-on-pin"
	case trustverify.TrustDNSSECBound:
		return "pin+DNSSEC"
	default:
		return string(t)
	}
}

// notTrustlesslyProven is the one-line reason a trustless verify did not fully pass.
func notTrustlesslyProven(rep *trustverify.Report, target string) string {
	for _, c := range rep.Checks {
		if c.Status == trustverify.StatusFail {
			return fmt.Sprintf("%s check failed: %s", c.Name, c.Detail)
		}
	}
	return fmt.Sprintf("%s could not be independently proven", target)
}
