// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// tscredential.go holds the Tailscale credential for exactly as long as one command runs.
//
// The rule is absolute: the credential is never written into the plan,
// never logged, never echoed. So this type is built to make the wrong thing impossible
// rather than merely discouraged:
//
// - The secret is unexported, so no reflective encoder can reach it.
// - MarshalJSON returns an ERROR. Anything that tries to serialise a Credential fails
// loudly at the moment of the mistake instead of writing a key into a file someone
// later pastes into an issue.
// - String and GoString render the fingerprint, so a %v, a %s, a %#v or a panic dump
// prints a hash rather than a key.
// - Scrub runs over every byte of upstream error text before it reaches a terminal,
// because Tailscale's own OAuth error bodies can quote the request back at you.
//
// What the plan records is Fingerprint: the first 12 hex of the SHA-256 of the secret.
// Twelve hex is 48 bits, which is plenty to catch "you ran apply with a different
// credential than you planned with" and far too little to attack the key with.

// CredentialKind names how the credential authenticates.
type CredentialKind string

const (
	// CredentialOAuth is a read-only OAuth client (client id + secret), the shape the
	// story asks for because it can be scoped read-only and rotated independently.
	CredentialOAuth CredentialKind = "oauth"
	// CredentialAPIKey is a personal API access token (tskey-api-...).
	CredentialAPIKey CredentialKind = "apikey"
)

// fingerprintHexLen is the 12 hex digits the plan file records. Named, because two
// places (the writer and the apply-time comparison) must agree exactly.
const fingerprintHexLen = 12

// Credential is a Tailscale API credential. The zero value is "none", and IsZero is the
// only way to ask.
type Credential struct {
	kind     CredentialKind
	clientID string // OAuth client id: an identifier, not a secret
	secret   string
}

// NewAPIKeyCredential wraps a personal API access token.
func NewAPIKeyCredential(secret string) Credential {
	return Credential{kind: CredentialAPIKey, secret: strings.TrimSpace(secret)}
}

// NewOAuthCredential wraps a read-only OAuth client's id and secret.
func NewOAuthCredential(clientID, secret string) Credential {
	return Credential{kind: CredentialOAuth, clientID: strings.TrimSpace(clientID), secret: strings.TrimSpace(secret)}
}

// IsZero reports whether no credential was supplied.
func (c Credential) IsZero() bool { return strings.TrimSpace(c.secret) == "" }

// Kind reports how this credential authenticates.
func (c Credential) Kind() CredentialKind { return c.kind }

// ClientID is the OAuth client id, which is an identifier and not a secret. It is empty
// for an API key.
func (c Credential) ClientID() string { return c.clientID }

// secretValue is the ONLY reader of the secret, and it is unexported so the set of
// callers is exactly the transport in this package. Nothing outside can lift the key
// back out of the struct.
func (c Credential) secretValue() string { return c.secret }

// Fingerprint is the first 12 hex of the SHA-256 of the secret, or "" for the zero
// value. This is what goes in the plan file and what apply compares against.
func (c Credential) Fingerprint() string {
	if c.IsZero() {
		return ""
	}
	sum := sha256.Sum256([]byte(c.secret))
	return hex.EncodeToString(sum[:])[:fingerprintHexLen]
}

// String renders a credential for humans without rendering the credential.
func (c Credential) String() string {
	if c.IsZero() {
		return "no tailscale credential"
	}
	return fmt.Sprintf("tailscale %s credential (sha256:%s)", c.kind, c.Fingerprint())
}

// GoString covers %#v, which is what a struct dump and most panic traces reach for.
func (c Credential) GoString() string { return c.String() }

// errCredentialNotSerialisable is returned rather than a value, on purpose.
var errCredentialNotSerialisable = errors.New(
	"a tailscale credential must never be serialised: the plan file records only the first 12 hex " +
		"of its SHA-256, and that is written explicitly")

// MarshalJSON refuses. A Credential reachable from any struct that is being written to
// disk is a bug, and this turns that bug into a failed write instead of a leaked key.
func (c Credential) MarshalJSON() ([]byte, error) { return nil, errCredentialNotSerialisable }

var _ json.Marshaler = Credential{}

// secretPattern matches every Tailscale secret spelling we know of: node auth keys
// (tskey-auth-, tskey-client-, tskey-scim-, tskey-api-) and the bare tskey- prefix, plus
// the OAuth secret spelling. The trailing class is deliberately greedy over the
// characters Tailscale uses so a partial match cannot leave a usable tail behind.
var secretPattern = regexp.MustCompile(`(?i)tskey-[a-z0-9]*-?[A-Za-z0-9]{6,}`)

// Scrub removes anything that looks like a Tailscale secret from text bound for a
// terminal, a log or a file. It is applied to every upstream error body in this package.
// Being liberal in what we accept means reading their error text; being conservative in
// what we emit means never repeating a key out of it.
func Scrub(s string) string {
	return secretPattern.ReplaceAllString(s, "tskey-REDACTED")
}

// LooksLikeTailscaleAuthKey reports whether s is a NODE auth key rather than an API
// credential. Postel, literally: someone will paste `tskey-auth-...` into a flag that
// wants an API credential, and the right answer is the sentence that unblocks them, not
// a 401 from an API that was never going to accept it.
func LooksLikeTailscaleAuthKey(s string) bool {
	t := strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(t, "tskey-api-") || strings.HasPrefix(t, "tskey-client-") {
		return false // an API credential: the right key for this command
	}
	return strings.HasPrefix(t, "tskey-")
}
