// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// deepencli_ledger_test.go: the KEYLESS transparency-ledger verify surface, end to end
// against a locally-minted, cryptographically REAL fixture (Ed25519 + SHA-256 +
// RFC 6962) - no live ledger, no faked verdicts. The fixture is a one-leaf tree whose
// root IS the leaf hash, signed as a C2SP note, so every check the CLI performs
// (signature, key-id, leaf recompute, inclusion fold, witness cosignature) runs for
// real and would catch a mutated verifier.

// deepencliSigPrefix is the C2SP signed-note signature-line prefix: the em-dash rune
// plus a space, per the protocol (c2sp.org/signed-note). Written as an escape so the
// PROSE ban on em-dash characters stays intact while the wire bytes stay honest.
const deepencliSigPrefix = "\u2014 "

type deepencliLedgerFixture struct {
	origin   string
	addr     string
	salt     []byte
	event    []byte
	leafHex  string
	note     string // the signed C2SP note (no witness cosignature)
	keyJSON  string // the /checkpoint/key reply
	witPub   ed25519.PublicKey
	noteWit  string // the note + one witness cosignature line
	witKeys  string // the /witness/keys reply (one independent witness)
	saltHex  string
	eventHex string
}

func deepencli_mintLedgerFixture(t *testing.T) *deepencliLedgerFixture {
	t.Helper()
	f := &deepencliLedgerFixture{
		origin: "whisper.ledger/deepencli",
		addr:   "2a04:2a01:9::1",
		salt:   make([]byte, 32),
		event:  []byte(`{"kind":"identity.minted","address":"2a04:2a01:9::1"}`),
	}
	if _, err := rand.Read(f.salt); err != nil {
		t.Fatal(err)
	}
	f.saltHex = hex.EncodeToString(f.salt)
	f.eventHex = hex.EncodeToString(f.event)

	leaf := client.LeafHashFromDisclosure(f.salt, f.event)
	f.leafHex = hex.EncodeToString(leaf)

	// One-leaf tree: the RFC 6962 root IS the leaf hash; the inclusion proof is empty.
	body := f.origin + "\n1\n" + base64.StdEncoding.EncodeToString(leaf) + "\n"

	logPub, logPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := uint32(0x01020304)
	blob := make([]byte, 4, 4+ed25519.SignatureSize)
	binary.BigEndian.PutUint32(blob, keyID)
	blob = append(blob, ed25519.Sign(logPriv, []byte(body))...)
	f.note = body + "\n" + deepencliSigPrefix + f.origin + " " + base64.StdEncoding.EncodeToString(blob) + "\n"

	kj, err := json.Marshal(client.LedgerKey{
		Origin: f.origin, Alg: "ed25519", KeyID: fmt.Sprintf("%08x", keyID),
		PublicKey: base64.StdEncoding.EncodeToString(logPub),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.keyJSON = string(kj)

	// An INDEPENDENT witness cosignature over the same note body (C2SP cosignature/v1).
	witPub, witPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.witPub = witPub
	ts := uint64(time.Now().Unix())
	msg := append([]byte("cosignature/v1\ntime "+fmt.Sprintf("%d", ts)+"\n"), []byte(body)...)
	wblob := make([]byte, 12, 12+ed25519.SignatureSize)
	binary.BigEndian.PutUint32(wblob[:4], 0x0a0b0c0d)
	binary.BigEndian.PutUint64(wblob[4:12], ts)
	wblob = append(wblob, ed25519.Sign(witPriv, msg)...)
	f.noteWit = f.note + deepencliSigPrefix + "witness.example " + base64.StdEncoding.EncodeToString(wblob) + "\n"

	wk, err := json.Marshal(map[string]any{
		"object": "witness-keys", "threshold": 1,
		"publicly_verifiable_max_age_seconds": 86400,
		"witnesses": []map[string]any{{
			"name": "witness.example", "key_id": "0a0b0c0d",
			"public_key":  base64.StdEncoding.EncodeToString(witPub),
			"independent": true, "role": "witness",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.witKeys = string(wk)
	return f
}

// deepencli_ledgerServer serves the four keyless ledger endpoints from the fixture.
// withWitness selects the cosigned note + a published witness policy.
func deepencli_ledgerServer(t *testing.T, f *deepencliLedgerFixture, withWitness bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/checkpoint":
			note := f.note
			if withWitness {
				note = f.noteWit
			}
			_, _ = w.Write([]byte(note))
		case r.URL.Path == "/checkpoint/key":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(f.keyJSON))
		case r.URL.Path == "/witness/keys":
			if !withWitness {
				http.NotFound(w, r) // witnessing off: the CLI must fail OPEN to tamper-evident
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(f.witKeys))
		case strings.HasPrefix(r.URL.Path, "/ip/") && strings.HasSuffix(r.URL.Path, "/transparency"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ledger":{"checkpoint":"","leaves":[` +
				`{"index":0,"leaf_hash":"` + f.leafHex + `","inclusion_proof":[]}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestDeepenCLI_LedgerVerify_IncludedDisclosureVerifies(t *testing.T) {
	f := deepencli_mintLedgerFixture(t)
	srv := deepencli_ledgerServer(t, f, false)
	defer srv.Close()
	deepencli_globals(t, globalFlags{rdapURL: srv.URL, timeout: 5 * time.Second})

	stdout, stderr := captureStd(t, func() {
		err := deepencli_exec(t, newLedgerVerifyCmd(), f.addr,
			"--salt", f.saltHex, "--event-hex", f.eventHex)
		if err != nil {
			t.Errorf("a genuinely included disclosure must verify, got %v", err)
		}
	})
	if !strings.Contains(stderr, "VERIFIED") || !strings.Contains(stderr, "leaf 0 of 1") {
		t.Fatalf("the verified line must name the leaf position: %q", stderr)
	}
	if !strings.Contains(stdout, f.leafHex) {
		t.Fatalf("the table must carry the recomputed leaf hash: %q", stdout)
	}
}

func TestDeepenCLI_LedgerVerify_WrongSaltIsNotIncluded(t *testing.T) {
	f := deepencli_mintLedgerFixture(t)
	srv := deepencli_ledgerServer(t, f, false)
	defer srv.Close()
	deepencli_globals(t, globalFlags{rdapURL: srv.URL, timeout: 5 * time.Second})

	wrongSalt := strings.Repeat("ab", 32)
	var err error
	captureStd(t, func() {
		err = deepencli_exec(t, newLedgerVerifyCmd(), f.addr,
			"--salt", wrongSalt, "--event-hex", f.eventHex)
	})
	var pe *client.ProblemError
	if err == nil || !asProblem(err, &pe) || pe.Title != "not included" {
		t.Fatalf("a wrong salt must yield NOT INCLUDED (never a false verify), got %v", err)
	}
	if !strings.Contains(pe.Detail, "salt/event") {
		t.Fatalf("the failure must tell the verifier what to re-check: %q", pe.Detail)
	}
}

func TestDeepenCLI_LedgerVerify_ArgErrorsBeforeAnyNetwork(t *testing.T) {
	// rdapURL points at a dead port: reaching the network would fail loudly, so a pass
	// here proves the argument errors fire FIRST.
	deepencli_globals(t, globalFlags{rdapURL: "http://127.0.0.1:1", timeout: time.Second})

	err := deepencli_exec(t, newLedgerVerifyCmd(), "2a04:2a01:9::1", "--event-hex", "0a")
	var pe *client.ProblemError
	if err == nil || !asProblem(err, &pe) || pe.Status != 400 || !strings.Contains(pe.Detail, "--salt") {
		t.Fatalf("missing salt must 400 before any fetch, got %v", err)
	}
	err = deepencli_exec(t, newLedgerVerifyCmd(), "2a04:2a01:9::1", "--salt", strings.Repeat("00", 32))
	if err == nil || !asProblem(err, &pe) || pe.Status != 400 || !strings.Contains(pe.Detail, "--event-file") {
		t.Fatalf("missing event must 400 with both options named, got %v", err)
	}
}

func TestDeepenCLI_LedgerCheckpoint_NoWitnessIsHonestTamperEvident(t *testing.T) {
	f := deepencli_mintLedgerFixture(t)
	srv := deepencli_ledgerServer(t, f, false)
	defer srv.Close()
	deepencli_globals(t, globalFlags{rdapURL: srv.URL, timeout: 5 * time.Second})

	stdout, stderr := captureStd(t, func() {
		if err := deepencli_exec(t, newLedgerCheckpointCmd()); err != nil {
			t.Errorf("a validly signed checkpoint must verify, got %v", err)
		}
	})
	if !strings.Contains(stderr, "tamper-evident, signed tree of 1 leaves") {
		t.Fatalf("without a witness the claim must stay tamper-evident (never over-claim): %q", stderr)
	}
	if strings.Contains(stderr, "publicly verifiable") {
		t.Fatalf("no cosignature must never yield the strong claim: %q", stderr)
	}
	if !strings.Contains(stdout, f.origin) || !strings.Contains(stdout, "VERIFIED (Ed25519)") {
		t.Fatalf("the table must carry origin + signature state: %q", stdout)
	}
}

func TestDeepenCLI_LedgerCheckpoint_JSONEmitsTheVerbatimNote(t *testing.T) {
	f := deepencli_mintLedgerFixture(t)
	srv := deepencli_ledgerServer(t, f, false)
	defer srv.Close()
	deepencli_globals(t, globalFlags{rdapURL: srv.URL, jsonOut: true, timeout: 5 * time.Second})

	stdout, _ := captureStd(t, func() {
		if err := deepencli_exec(t, newLedgerCheckpointCmd()); err != nil {
			t.Errorf("checkpoint --json errored: %v", err)
		}
	})
	if stdout != f.note {
		t.Fatalf("--json must emit the note verbatim:\n got %q\nwant %q", stdout, f.note)
	}
}

func TestDeepenCLI_LedgerCheckpoint_WitnessedPerServerPolicy(t *testing.T) {
	f := deepencli_mintLedgerFixture(t)
	srv := deepencli_ledgerServer(t, f, true)
	defer srv.Close()
	deepencli_globals(t, globalFlags{rdapURL: srv.URL, timeout: 5 * time.Second})

	stdout, stderr := captureStd(t, func() {
		if err := deepencli_exec(t, newLedgerCheckpointCmd()); err != nil {
			t.Errorf("witnessed checkpoint errored: %v", err)
		}
	})
	if !strings.Contains(stderr, "SERVER-PUBLISHED witness policy") {
		t.Fatalf("unpinned mode must qualify the claim with the policy source: %q", stderr)
	}
	if !strings.Contains(stdout, "1 independent (VERIFIED)") {
		t.Fatalf("the cosignature count must be the CLI's own recompute: %q", stdout)
	}
	if !strings.Contains(stdout, "per server-published witness policy") {
		t.Fatalf("the claim row itself must carry the qualifier: %q", stdout)
	}
}

func TestDeepenCLI_LedgerCheckpoint_PinnedWitnessIsFullyTrustless(t *testing.T) {
	f := deepencli_mintLedgerFixture(t)
	srv := deepencli_ledgerServer(t, f, true)
	defer srv.Close()
	deepencli_globals(t, globalFlags{rdapURL: srv.URL, timeout: 5 * time.Second})

	pin := base64.StdEncoding.EncodeToString(f.witPub)
	stdout, stderr := captureStd(t, func() {
		if err := deepencli_exec(t, newLedgerCheckpointCmd(), "--witness-key", pin); err != nil {
			t.Errorf("pinned witnessed checkpoint errored: %v", err)
		}
	})
	if !strings.Contains(stderr, "PUBLICLY VERIFIABLE") || !strings.Contains(stderr, "pinned") {
		t.Fatalf("pinned mode must state the out-of-band trust: %q", stderr)
	}
	if !strings.Contains(stdout, "publicly verifiable / split-view-resistant") ||
		strings.Contains(stdout, "per server-published") {
		t.Fatalf("the pinned claim row stands on its own, no qualifier: %q", stdout)
	}
}

func TestDeepenCLI_LedgerCheckpoint_WrongPinNeverCounts(t *testing.T) {
	f := deepencli_mintLedgerFixture(t)
	srv := deepencli_ledgerServer(t, f, true)
	defer srv.Close()
	deepencli_globals(t, globalFlags{rdapURL: srv.URL, timeout: 5 * time.Second})

	// A pin for a DIFFERENT key: the served cosignature must not verify under it, so
	// the verdict must drop to tamper-evident even though the origin claims a witness.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin := base64.StdEncoding.EncodeToString(otherPub)
	_, stderr := captureStd(t, func() {
		if err := deepencli_exec(t, newLedgerCheckpointCmd(), "--witness-key", pin); err != nil {
			t.Errorf("checkpoint with a non-matching pin still verifies the log signature: %v", err)
		}
	})
	if !strings.Contains(stderr, "no fresh cosignature from a pinned witness key") {
		t.Fatalf("a non-matching pin must be reported honestly: %q", stderr)
	}
	if strings.Contains(stderr, "PUBLICLY VERIFIABLE") {
		t.Fatal("a compromised origin listing its own witness gains nothing against a real pin")
	}
}

func TestDeepenCLI_LedgerCheckpoint_MalformedPinIsARealError(t *testing.T) {
	deepencli_globals(t, globalFlags{rdapURL: "http://127.0.0.1:1", timeout: time.Second})
	err := deepencli_exec(t, newLedgerCheckpointCmd(), "--witness-key", "!!!not-a-key!!!")
	var pe *client.ProblemError
	if err == nil || !asProblem(err, &pe) || pe.Status != 400 || pe.Title != "bad --witness-key" {
		t.Fatalf("a malformed pin must be a 400 (never silently unpinned), got %v", err)
	}
}

func TestDeepenCLI_LedgerCheckpoint_TamperedRootFailsClosed(t *testing.T) {
	f := deepencli_mintLedgerFixture(t)
	// Serve a note whose tree_size was tampered after signing: the Ed25519 check over
	// the body MUST fail (this is the whole point of the signed note).
	tampered := strings.Replace(f.note, "\n1\n", "\n2\n", 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/checkpoint":
			_, _ = w.Write([]byte(tampered))
		case "/checkpoint/key":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(f.keyJSON))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	deepencli_globals(t, globalFlags{rdapURL: srv.URL, timeout: 5 * time.Second})

	err := deepencli_exec(t, newLedgerCheckpointCmd())
	var pe *client.ProblemError
	if err == nil || !asProblem(err, &pe) || pe.Title != "checkpoint did not verify" {
		t.Fatalf("a tampered note must fail the signature check CLOSED, got %v", err)
	}
}
