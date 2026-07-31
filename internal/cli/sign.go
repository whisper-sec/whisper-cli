// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package cli - `whisper sign`: S/MIME / CMS signing anchored to your Whisper identity.
//
// Two-tier, per the Whisper integration standard:
//   - `whisper sign file <path>`  (KEYED)   issues your per-agent emailProtection cert from the
//     control plane and produces a detached S/MIME (CMS/PKCS#7) signature you can hand to anyone.
//   - `whisper sign verify …`     (KEYLESS) checks a signature against your Whisper identity with
//     NO API key: it validates the CMS signature AND matches the signer key to the DNSSEC-signed
//     SMIMEA (RFC 8162) record, validated from the IANA root IN-PROCESS. Trust is DANE-anchored
//     (the SMIMEA pins the signer's exact key), NOT a public S/MIME CA.
package cli

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/smallstep/pkcs7"
	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/trustverify"
)

// newSignCmd is the `sign` command group: issue an S/MIME signing cert anchored to your Whisper
// identity and produce/verify signatures whose trust comes from the DNSSEC-signed SMIMEA record.
func newSignCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign files with an S/MIME cert anchored to your Whisper identity (DANE/SMIMEA-verified)",
		Long: "Sign a file (or any document, e.g. a PDF) with a per-agent emailProtection certificate\n" +
			"issued from your Whisper identity, and verify such signatures with NO API key.\n\n" +
			"Trust is anchored by DANE: the DNSSEC-signed SMIMEA (RFC 8162) record pins the signer's\n" +
			"exact key, so a verifier needs no public S/MIME CA and no pre-installed trust anchor -\n" +
			"just the ability to validate DNSSEC (which `whisper sign verify` does from the IANA root).",
	}
	cmd.AddCommand(newSignFileCmd())
	cmd.AddCommand(newSignVerifyCmd())
	return cmd
}

// --- sign file (keyed) --------------------------------------------------------------------------

func newSignFileCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "file <path>",
		Short: "Produce a detached S/MIME (CMS) signature over a file, signed as your Whisper identity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			content, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read %s: %w", args[0], err)
			}
			cred, err := fetchSmimeCredential()
			if err != nil {
				return err
			}
			der, err := cmsSignDetached(content, cred)
			if err != nil {
				return fmt.Errorf("sign: %w", err)
			}
			p7pem := pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: der})
			target := out
			if strings.TrimSpace(target) == "" {
				target = args[0] + ".p7s"
			}
			if err := os.WriteFile(target, p7pem, 0o644); err != nil {
				return fmt.Errorf("write %s: %w", target, err)
			}
			fmt.Fprintf(os.Stderr,
				"whisper: signed %s as %s -> %s\n         verify (no key): whisper sign verify %s --sig %s\n",
				args[0], cred.mailbox, target, args[0], target)
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "output signature path (default <file>.p7s)")
	return cmd
}

// --- sign verify (keyless) ----------------------------------------------------------------------

func newSignVerifyCmd() *cobra.Command {
	var sigPath, resolver string
	cmd := &cobra.Command{
		Use:   "verify <file> --sig <sig.p7s>",
		Short: "Verify a detached S/MIME signature against the signer's Whisper SMIMEA (KEYLESS)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(sigPath) == "" {
				return fmt.Errorf("--sig <signature.p7s> is required")
			}
			content, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read %s: %w", args[0], err)
			}
			der, err := readPKCS7(sigPath)
			if err != nil {
				return err
			}
			return verifyDetached(content, der, resolver)
		},
	}
	cmd.Flags().StringVar(&sigPath, "sig", "", "detached signature file (.p7s) to verify")
	cmd.Flags().StringVar(&resolver, "resolver", "", "DNS resolver (host or host:port); default public DNSSEC-capable")
	return cmd
}

// verifyDetached is the DANE-pure verify: (1) the CMS signature is cryptographically valid over
// the content, and (2) the signer cert's SPKI matches a DNSSEC-validated SMIMEA 3-1-1 pin under
// the signer's mailbox. Trust comes ONLY from the DNSSEC chain (no public CA). Fails CLOSED.
func verifyDetached(content, der []byte, resolver string) error {
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}
	p7.Content = content // detached: supply the signed bytes
	signer := p7.GetOnlySigner()
	if signer == nil {
		return fmt.Errorf("signature has no single signer certificate")
	}
	// (1) verify the signature. DANE-EE trusts the exact key, so self-root at the signer leaf (the
	// public-CA chain is deliberately irrelevant here) and confirm the CMS signature validates.
	pool := x509.NewCertPool()
	pool.AddCert(signer)
	if err := p7.VerifyWithChain(pool); err != nil {
		return fmt.Errorf("CMS signature did not validate: %w", err)
	}
	// (2) the signer's mailbox (rfc822Name SAN) -> the SMIMEA owner -> DNSSEC-validated pin.
	mailbox := firstRFC822(signer)
	if mailbox == "" {
		return fmt.Errorf("signer certificate has no rfc822Name (email) SAN to anchor")
	}
	owner, err := smimeaOwner(mailbox)
	if err != nil {
		return err
	}
	pins, err := validateSmimeaPins(owner, resolver)
	if err != nil {
		return fmt.Errorf("SMIMEA (DNSSEC) for %s: %w", mailbox, err)
	}
	want := trustverify.SPKISHA256(signer)
	matched := false
	for _, p := range pins {
		if p == want {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("signer key is NOT pinned by the DNSSEC SMIMEA for %s (untrusted signer)", mailbox)
	}
	fmt.Fprintf(os.Stderr,
		"whisper: VERIFIED - signature is valid and the signer key is DANE-anchored by the DNSSEC\n"+
			"         SMIMEA for %s (spki sha256 %s). Trust: DNSSEC/SMIMEA, not a public S/MIME CA.\n",
		mailbox, hex.EncodeToString(want[:8]))
	return nil
}

// --- S/MIME credential (op:identity{smime}) -----------------------------------------------------

type smimeCred struct {
	chain   []*x509.Certificate
	key     crypto.PrivateKey
	mailbox string
}

// fetchSmimeCredential issues the per-agent emailProtection cert + key from the control plane
// (CALL whisper.agents({op:'identity', args:{smime:true}})). Requires an API key.
func fetchSmimeCredential() (*smimeCred, error) {
	c, err := resolveClient(true, false)
	if err != nil {
		return nil, err
	}
	cx, cancel := ctx()
	defer cancel()
	env, err := c.Agents(cx, "identity", map[string]any{"smime": true})
	if err != nil {
		return nil, err
	}
	if env.Err != nil {
		return nil, env.Err
	}
	certPEM := envCol(env, "smime_cert_pem")
	keyPEM := envCol(env, "smime_key_pem")
	mailbox := envCol(env, "mailbox")
	if certPEM == "" || keyPEM == "" {
		return nil, &client.ProblemError{Status: env.Status,
			Detail: "control plane did not return an S/MIME certificate (is the per-agent CA enabled?)"}
	}
	chain, err := parseCertChain(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	return &smimeCred{chain: chain, key: key, mailbox: mailbox}, nil
}

// cmsSignDetached builds a detached CMS/PKCS#7 SignedData (SHA-256) over content, signed by the
// leaf + carrying the intermediate so a verifier can see the chain (trust is still DANE/SMIMEA).
func cmsSignDetached(content []byte, cred *smimeCred) ([]byte, error) {
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, err
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	var parents []*x509.Certificate
	if len(cred.chain) > 1 {
		parents = cred.chain[1:]
	}
	if err := sd.AddSignerChain(cred.chain[0], cred.key, parents, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}
	sd.Detach()
	return sd.Finish()
}

// --- SMIMEA (RFC 8162) --------------------------------------------------------------------------

// smimeaOwner computes the RFC 8162 §3 SMIMEA owner for a mailbox: the lowercase hex of the
// leftmost 28 octets of SHA-256(local-part), then `_smimecert`, then the domain.
func smimeaOwner(mailbox string) (string, error) {
	at := strings.LastIndex(mailbox, "@")
	if at <= 0 || at == len(mailbox)-1 {
		return "", fmt.Errorf("not a mailbox addr-spec: %q", mailbox)
	}
	local := strings.ToLower(mailbox[:at])
	domain := strings.TrimSuffix(mailbox[at+1:], ".")
	sum := sha256.Sum256([]byte(local))
	label := hex.EncodeToString(sum[:28])
	return label + "._smimecert." + domain + ".", nil
}

// validateSmimeaPins DNSSEC-validates the SMIMEA RRset at owner from the IANA root IN-PROCESS and
// returns every DANE-EE (3 1 1) pin (the 32-byte SHA-256 of the signer's SPKI).
func validateSmimeaPins(owner, resolver string) ([][32]byte, error) {
	res := trustverify.NewNetResolver(strings.TrimSpace(resolver))
	v := trustverify.NewValidator(res, trustverify.IANARootAnchors(), time.Now())
	cx, cancel := ctx()
	defer cancel()
	rrs, err := v.ValidateRRSet(cx, owner, dns.TypeSMIMEA)
	if err != nil {
		return nil, err
	}
	var pins [][32]byte
	for _, rr := range rrs {
		s, ok := rr.(*dns.SMIMEA)
		if !ok {
			continue
		}
		if s.Usage == 3 && s.Selector == 1 && s.MatchingType == 1 {
			b, err := hex.DecodeString(s.Certificate)
			if err != nil || len(b) != 32 {
				continue
			}
			var p [32]byte
			copy(p[:], b)
			pins = append(pins, p)
		}
	}
	if len(pins) == 0 {
		return nil, fmt.Errorf("no DANE-EE (3 1 1) SMIMEA pin published at %s", owner)
	}
	return pins, nil
}

// --- small helpers ------------------------------------------------------------------------------

func envCol(env *client.Envelope, name string) string {
	if env == nil || env.Result == nil {
		return ""
	}
	idx := -1
	for i, c := range env.Result.Columns {
		if c == name {
			idx = i
			break
		}
	}
	if idx < 0 || len(env.Result.Rows) == 0 || idx >= len(env.Result.Rows[0]) {
		return ""
	}
	if s, ok := env.Result.Rows[0][idx].(string); ok {
		return s
	}
	return ""
}

func firstRFC822(cert *x509.Certificate) string {
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}
	return ""
}

func parseCertChain(pemStr string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(pemStr)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificate in PEM")
	}
	return out, nil
}

func parsePrivateKey(pemStr string) (crypto.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(pemStr))
	if blk == nil {
		return nil, fmt.Errorf("no private key in PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported private key encoding")
}

func readPKCS7(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if blk, _ := pem.Decode(raw); blk != nil && strings.Contains(blk.Type, "PKCS7") {
		return blk.Bytes, nil
	}
	return raw, nil // assume raw DER
}
