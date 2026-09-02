// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package cli - `whisper encrypt` / `whisper decrypt`: hybrid public-key encryption TO a Whisper
// agent identity, the mirror image of `whisper sign`.
//
// Two-tier, per the Whisper integration standard:
// - `whisper encrypt --to <agent-fqdn> <file>` (KEYLESS) encrypts a file (or stdin) FOR an
// agent using that agent's DNSSEC-published public key. No API key is needed: the recipient's
// key is discovered from the OPENPGPKEY (RFC 7929) record, DNSSEC-validated from the IANA root
// IN-PROCESS, so anyone can encrypt to an agent and trust comes ONLY from the DNSSEC chain.
// - `whisper decrypt <file.wenc>` (KEYED) the agent, authenticated, decrypts. It
// fetches its own per-agent private key from the control plane (or you supply it with --key for
// the sole-control / agent-held case) and opens the message.
//
// Crypto: HPKE (RFC 9180) base mode with DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM,
// over the SAME per-agent EC P-256 identity key that the TLSA/SMIMEA/OPENPGPKEY records pin. The
// implementation is the vetted github.com/cloudflare/circl/hpke; we never hand-roll the KEM/DEM.
package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/secfile"
	"github.com/whisper-sec/whisper-cli/internal/trustverify"
)

// Aliases for the HPKE KEM key types (github.com/cloudflare/circl/kem), for readable signatures.
type (
	kemPub  = kem.PublicKey
	kemPriv = kem.PrivateKey
)

// The one HPKE ciphersuite we emit (conservative in what we produce). DHKEM(P-256, HKDF-SHA256)
// is chosen so the KEM key IS the per-agent P-256 identity key the OPENPGPKEY already publishes.
const (
	wencKEM  = hpke.KEM_P256_HKDF_SHA256
	wencKDF  = hpke.KDF_HKDF_SHA256
	wencAEAD = hpke.AEAD_AES256GCM
)

const (
	wencMagic   = "WENC"
	wencVersion = 1
	// wencArmorType is the PEM header for the portable, copy-pasteable armored form.
	wencArmorType = "WHISPER ENCRYPTED MESSAGE"
	// wencMaxInput caps a single encrypt/decrypt payload (generous; never unbounded).
	wencMaxInput = 64 << 20 // 64 MiB
)

// newEncryptCmd / newDecryptCmd are registered on the root command (see root.go).

func newEncryptCmd() *cobra.Command {
	var to, out, resolver string
	cmd := &cobra.Command{
		Use:   "encrypt --to <agent-fqdn> [file]",
		Short: "Encrypt a file (or stdin) FOR a Whisper agent identity (KEYLESS, DANE-discovered key)",
		Long: "Encrypt data so that ONLY the named Whisper agent can decrypt it. The recipient's public\n" +
			"key is discovered from its DNSSEC-signed OPENPGPKEY record (validated from the IANA root in\n" +
			"process), so NO API key is needed and trust comes only from DNSSEC - not from any PKI you\n" +
			"have to configure. Uses HPKE (RFC 9180): DHKEM(P-256) + HKDF-SHA256 + AES-256-GCM.\n\n" +
			"The agent decrypts with `whisper decrypt` using its Whisper identity.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			recipient := canonicalAgentFqdn(to)
			if recipient == "" {
				return fmt.Errorf("--to <agent-fqdn> is required (the recipient agent's identity name)")
			}
			plaintext, srcName, err := readInput(args)
			if err != nil {
				return err
			}
			pkR, err := recipientPublicKey(recipient, resolver)
			if err != nil {
				return fmt.Errorf("recipient key for %s: %w", recipient, err)
			}
			blob, err := hpkeSeal(recipient, pkR, plaintext)
			if err != nil {
				return fmt.Errorf("encrypt: %w", err)
			}
			armored := pem.EncodeToMemory(&pem.Block{Type: wencArmorType, Bytes: blob})
			target := chooseOutput(out, srcName, ".wenc")
			if err := writeOutput(target, armored); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "whisper: encrypted for %s -> %s\n         decrypt: whisper decrypt %s\n",
				recipient, describeTarget(target), describeTarget(target))
			return nil
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "recipient agent identity (fqdn), e.g. a1b2c3.agents.whisper.online")
	cmd.Flags().StringVarP(&out, "out", "o", "", "output path (default <file>.wenc; '-' for stdout)")
	cmd.Flags().StringVar(&resolver, "resolver", "", "DNS resolver (host or host:port); default public DNSSEC-capable")
	return cmd
}

func newDecryptCmd() *cobra.Command {
	var out, keyPath string
	cmd := &cobra.Command{
		Use:   "decrypt [file.wenc]",
		Short: "Decrypt a message encrypted for your Whisper agent identity (KEYED)",
		Long: "Decrypt data that was encrypted for your Whisper identity with `whisper encrypt`. By default\n" +
			"your per-agent private key is fetched from the control plane (needs your API key); if your\n" +
			"identity holds its own key (sole-control / agent-held), supply it with --key <pem>.\n\n" +
			"Note: encryption gives confidentiality, not sender authentication - a clean decrypt proves\n" +
			"the message was sealed to your key, NOT who sent it. When the sender's identity matters,\n" +
			"pair it with `whisper sign` (sign-then-encrypt).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, srcName, err := readInput(args)
			if err != nil {
				return err
			}
			blob, err := dearmorWenc(raw)
			if err != nil {
				return err
			}
			hdr, err := parseWenc(blob)
			if err != nil {
				return err
			}
			skR, mine, err := decryptionKey(keyPath, hdr.recipient)
			if err != nil {
				return err
			}
			if mine != "" && !sameFqdn(mine, hdr.recipient) {
				return fmt.Errorf("this message was encrypted for %s, but your identity is %s", hdr.recipient, mine)
			}
			plaintext, err := hpkeOpen(hdr, skR)
			if err != nil {
				return fmt.Errorf("decrypt: %w (is this message encrypted for you?)", err)
			}
			target := chooseOutput(out, strings.TrimSuffix(srcName, ".wenc"), "")
			if target == srcName { // never clobber the ciphertext in place
				target = "-"
			}
			if err := writeSecretOutput(target, plaintext); err != nil {
				return err
			}
			if target != "-" {
				fmt.Fprintf(os.Stderr, "whisper: decrypted %s -> %s (encrypted for %s)\n",
					describeTarget(srcName), describeTarget(target), hdr.recipient)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "output path (default strips .wenc; '-' for stdout)")
	cmd.Flags().StringVar(&keyPath, "key", "", "your per-agent private key PEM (for a sole-control/agent-held identity)")
	return cmd
}

// --- recipient key discovery (keyless, DNSSEC) --------------------------------------------------

// recipientPublicKey DNSSEC-validates the OPENPGPKEY at _openpgpkey.<fqdn> from the IANA root and
// returns the agent's per-agent P-256 key as an HPKE KEM public key. The OPENPGPKEY carries the
// SAME key the TLSA/SMIMEA pin, so the encrypted message can only be opened by that identity.
func recipientPublicKey(fqdn, resolver string) (kemPub, error) {
	owner := dns.Fqdn("_openpgpkey." + fqdn)
	res := trustverify.NewNetResolver(strings.TrimSpace(resolver))
	v := trustverify.NewValidator(res, trustverify.IANARootAnchors(), time.Now())
	cx, cancel := ctx()
	defer cancel()
	rrs, err := v.ValidateRRSet(cx, owner, dns.TypeOPENPGPKEY)
	if err != nil {
		return nil, fmt.Errorf("OPENPGPKEY (DNSSEC) at %s: %w", owner, err)
	}
	for _, rr := range rrs {
		k, ok := rr.(*dns.OPENPGPKEY)
		if !ok {
			continue
		}
		rdata, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil {
			continue
		}
		point, err := openpgpP256Point(rdata)
		if err != nil {
			continue
		}
		pk, err := wencKEM.Scheme().UnmarshalBinaryPublicKey(point)
		if err != nil {
			continue
		}
		return pk, nil
	}
	return nil, fmt.Errorf("no usable P-256 OPENPGPKEY published at %s", owner)
}

// openpgpP256Point extracts the 65-octet uncompressed EC point (0x04||X||Y) from a v4 ECDSA-over-
// P-256 OpenPGP transferable public-key packet as published in the OPENPGPKEY record (RFC 4880 /
// RFC 7929): new-format tag-6 header, [version 4][creation 4][algo 19][oidlen 8][OID][MPI of Q].
func openpgpP256Point(rdata []byte) ([]byte, error) {
	if len(rdata) < 3 || rdata[0] != 0xC6 {
		return nil, fmt.Errorf("not a new-format OpenPGP public-key packet")
	}
	// New-format packet length (RFC 4880 §4.2.2): 1- or 2-octet form is all we ever emit.
	off := 2
	first := int(rdata[1])
	declaredLen := first
	if first >= 192 && first < 224 {
		if len(rdata) < 3 {
			return nil, fmt.Errorf("truncated packet length")
		}
		declaredLen = ((first - 192) << 8) + int(rdata[2]) + 192
		off = 3
	} else if first >= 224 {
		return nil, fmt.Errorf("unsupported packet length form")
	}
	body := rdata[off:]
	if declaredLen != len(body) { // the encoded length must cover exactly the packet body
		return nil, fmt.Errorf("packet length mismatch")
	}
	// [0]=version(4) [1..4]=creation [5]=algo(19 ECDSA) [6]=oidlen(8) [7..7+oidlen]=OID, then the MPI.
	if len(body) < 7 || body[0] != 0x04 || body[5] != 19 {
		return nil, fmt.Errorf("not a v4 ECDSA key packet")
	}
	oidLen := int(body[6])
	mpiStart := 7 + oidLen
	if len(body) < mpiStart+2 {
		return nil, fmt.Errorf("truncated before MPI")
	}
	bits := int(body[mpiStart])<<8 | int(body[mpiStart+1])
	n := (bits + 7) / 8
	pt := body[mpiStart+2:]
	if n != len(pt) || n != 65 || pt[0] != 0x04 {
		return nil, fmt.Errorf("not a 65-octet uncompressed P-256 point")
	}
	out := make([]byte, 65)
	copy(out, pt)
	return out, nil
}

// --- decryption key (keyed, or --key) -----------------------------------------------------------

// decryptionKey returns the agent's HPKE KEM private key. With --key it parses the supplied PEM
// (sole-control / agent-held identity). Otherwise it fetches the deterministic per-agent key
// from the control plane via op:identity{clientCert} and also returns the caller's canonical fqdn
// so decrypt can give a clear "not encrypted for you" error instead of an opaque AEAD failure.
func decryptionKey(keyPath, wantRecipient string) (kemPriv, string, error) {
	if strings.TrimSpace(keyPath) != "" {
		pemBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, "", fmt.Errorf("read key %s: %w", keyPath, err)
		}
		sk, err := ecPrivToKem(pemBytes)
		return sk, "", err
	}
	c, err := resolveClient(true, false)
	if err != nil {
		return nil, "", err
	}
	cx, cancel := ctx()
	defer cancel()
	env, err := c.Agents(cx, "identity", map[string]any{"clientCert": true})
	if err != nil {
		return nil, "", err
	}
	if env.Err != nil {
		return nil, "", env.Err
	}
	keyPEM := envCol(env, "client_key_pem")
	fqdn := envCol(env, "fqdn")
	if keyPEM == "" {
		return nil, "", &client.ProblemError{Status: env.Status,
			Detail: "control plane did not return your identity key; if your key is agent-held, decrypt with --key <pem>"}
	}
	sk, err := ecPrivToKem([]byte(keyPEM))
	return sk, canonicalAgentFqdn(fqdn), err
}

// ecPrivToKem parses an EC P-256 private key PEM and marshals it as the HPKE KEM private key (the
// 32-octet big-endian scalar).
func ecPrivToKem(pemBytes []byte) (kemPriv, error) {
	key, err := parsePrivateKey(string(pemBytes))
	if err != nil {
		return nil, err
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve.Params().BitSize != 256 {
		return nil, fmt.Errorf("identity key is not an EC P-256 key")
	}
	scalar := make([]byte, 32)
	ec.D.FillBytes(scalar)
	return wencKEM.Scheme().UnmarshalBinaryPrivateKey(scalar)
}

// --- HPKE seal / open + the .wenc container -----------------------------------------------------

type wencMsg struct {
	recipient string
	enc       []byte
	ct        []byte
	header    []byte // the serialized header, used verbatim as the AEAD aad
}

func hpkeInfo(recipient string) []byte { return []byte("whisper-encrypt:v1:" + recipient) }

// hpkeSeal encapsulates to pkR and seals plaintext, returning the serialized .wenc container. The
// header (magic, version, suite ids, recipient, enc) is bound to the ciphertext as the AEAD aad,
// so any tamper with the recipient or suite fails the open.
func hpkeSeal(recipient string, pkR kemPub, plaintext []byte) ([]byte, error) {
	suite := hpke.NewSuite(wencKEM, wencKDF, wencAEAD)
	sender, err := suite.NewSender(pkR, hpkeInfo(recipient))
	if err != nil {
		return nil, err
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, err
	}
	header := marshalWencHeader(recipient, enc)
	ct, err := sealer.Seal(plaintext, header)
	if err != nil {
		return nil, err
	}
	return append(header, ct...), nil
}

func hpkeOpen(m *wencMsg, skR kemPriv) ([]byte, error) {
	suite := hpke.NewSuite(wencKEM, wencKDF, wencAEAD)
	recv, err := suite.NewReceiver(skR, hpkeInfo(m.recipient))
	if err != nil {
		return nil, err
	}
	opener, err := recv.Setup(m.enc)
	if err != nil {
		return nil, err
	}
	return opener.Open(m.ct, m.header)
}

func marshalWencHeader(recipient string, enc []byte) []byte {
	var b bytes.Buffer
	b.WriteString(wencMagic)
	b.WriteByte(wencVersion)
	_ = binary.Write(&b, binary.BigEndian, uint16(wencKEM))
	_ = binary.Write(&b, binary.BigEndian, uint16(wencKDF))
	_ = binary.Write(&b, binary.BigEndian, uint16(wencAEAD))
	r := []byte(recipient)
	_ = binary.Write(&b, binary.BigEndian, uint16(len(r)))
	b.Write(r)
	_ = binary.Write(&b, binary.BigEndian, uint16(len(enc)))
	b.Write(enc)
	return b.Bytes()
}

// parseWenc splits a serialized container into its header (aad), recipient, enc and ciphertext,
// validating the magic, version and suite ids (Postel: a clear error, never an opaque failure).
func parseWenc(blob []byte) (*wencMsg, error) {
	r := bytes.NewReader(blob)
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != wencMagic {
		return nil, fmt.Errorf("not a Whisper encrypted message (bad magic)")
	}
	ver, err := r.ReadByte()
	if err != nil || ver != wencVersion {
		return nil, fmt.Errorf("unsupported Whisper encrypted-message version")
	}
	var kemID, kdfID, aeadID, rlen uint16
	for _, p := range []*uint16{&kemID, &kdfID, &aeadID, &rlen} {
		if err := binary.Read(r, binary.BigEndian, p); err != nil {
			return nil, fmt.Errorf("truncated header")
		}
	}
	if kemID != uint16(wencKEM) || kdfID != uint16(wencKDF) || aeadID != uint16(wencAEAD) {
		return nil, fmt.Errorf("unsupported ciphersuite (kem=%d kdf=%d aead=%d)", kemID, kdfID, aeadID)
	}
	recipient := make([]byte, rlen)
	if _, err := io.ReadFull(r, recipient); err != nil {
		return nil, fmt.Errorf("truncated recipient")
	}
	var elen uint16
	if err := binary.Read(r, binary.BigEndian, &elen); err != nil {
		return nil, fmt.Errorf("truncated enc length")
	}
	enc := make([]byte, elen)
	if _, err := io.ReadFull(r, enc); err != nil {
		return nil, fmt.Errorf("truncated enc")
	}
	headerLen := len(blob) - r.Len()
	ct, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return &wencMsg{recipient: string(recipient), enc: enc, ct: ct, header: blob[:headerLen]}, nil
}

// dearmorWenc accepts either the PEM-armored form or the raw binary container (liberal in what we
// accept). It returns the raw container bytes.
func dearmorWenc(raw []byte) ([]byte, error) {
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("-----BEGIN")) {
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != wencArmorType {
			return nil, fmt.Errorf("not a %s PEM block", wencArmorType)
		}
		return block.Bytes, nil
	}
	if bytes.HasPrefix(raw, []byte(wencMagic)) {
		return raw, nil
	}
	return nil, fmt.Errorf("input is neither an armored nor a raw Whisper encrypted message")
}

// --- small I/O helpers --------------------------------------------------------------------------

func readInput(args []string) (data []byte, name string, err error) {
	if len(args) == 0 || args[0] == "-" {
		// Read one past the limit so an oversized stream ERRORS instead of being silently
		// truncated (symmetric with the file path below).
		data, err = io.ReadAll(io.LimitReader(os.Stdin, wencMaxInput+1))
		if err == nil && len(data) > wencMaxInput {
			return nil, "", fmt.Errorf("stdin exceeds the %d MiB limit", wencMaxInput>>20)
		}
		return data, "", err
	}
	data, err = os.ReadFile(args[0])
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", args[0], err)
	}
	if len(data) > wencMaxInput {
		return nil, "", fmt.Errorf("%s is larger than the %d MiB limit", args[0], wencMaxInput>>20)
	}
	return data, args[0], nil
}

// chooseOutput picks the output path: an explicit --out wins; otherwise derive from the source name
// (append suffix on encrypt, or the stripped name on decrypt); with no source, stdout.
func chooseOutput(out, srcName, suffix string) string {
	if s := strings.TrimSpace(out); s != "" {
		return s
	}
	if srcName == "" {
		return "-"
	}
	return srcName + suffix
}

func writeOutput(target string, data []byte) error {
	if target == "-" || target == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(target, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	return nil
}

// writeSecretOutput writes recovered plaintext owner-only and create-exclusive (O_EXCL), so a
// decrypted secret is never left world-readable, never silently clobbers an existing file, and
// cannot be redirected through a symlink planted at the output path.
// O_EXCL is portable (Windows too); ciphertext keeps writeOutput (0o644) - it is not secret.
//
// Owner-only through secfile, not through a 0o600 mode argument. O_EXCL was portable;
// the permission was not, and on Windows a decrypted secret took the output directory's DACL.
func writeSecretOutput(target string, data []byte) error {
	if target == "-" || target == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	f, err := secfile.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("refusing to overwrite existing %s (use -o <path> or -o - for stdout)", target)
		}
		return fmt.Errorf("write %s: %w", target, err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	return nil
}

func describeTarget(t string) string {
	if t == "-" || t == "" {
		return "(stdout)"
	}
	return t
}

// canonicalAgentFqdn lowercases and strips a trailing dot from an agent identity name.
func canonicalAgentFqdn(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

func sameFqdn(a, b string) bool { return canonicalAgentFqdn(a) == canonicalAgentFqdn(b) }
