// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// device.go implements the CLIENT half of the OAuth 2.0 Device Authorization Grant
// (RFC 8628) against the Whisper console:
//
//	POST <console>/api/device/authorize  (no auth) -> DeviceAuth
//	POST <console>/api/device/token      (no auth) -> DeviceToken (polled)
//
// It carries NO API key — that is the whole point: the device flow is how a user with
// only a browser obtains a key. Neither the device_code nor the issued api_key is ever
// logged. Errors are returned as helpful, secret-free messages, never a panic
// (Postel: a clear, helpful error, never an opaque failure).

// DeviceClientTimeout bounds a single device HTTP call (authorize / one token poll). The
// overall flow lifetime is governed by the server-supplied expires_in deadline, not this.
const DeviceClientTimeout = 20 * time.Second

// DeviceAuth is the response of POST /api/device/authorize. The fields mirror RFC 8628
// §3.2 plus the console's verification_uri_complete convenience field.
type DeviceAuth struct {
	// DeviceCode is the secret the client polls with. NEVER log it.
	DeviceCode string `json:"device_code"`
	// UserCode is the short code the human confirms in the browser (safe to display).
	UserCode string `json:"user_code"`
	// VerificationURI is where the user signs in.
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete embeds the user_code so a single click/open authorizes.
	VerificationURIComplete string `json:"verification_uri_complete"`
	// Interval is the minimum seconds to wait between token polls.
	Interval int `json:"interval"`
	// ExpiresIn is the total seconds the device_code remains valid.
	ExpiresIn int `json:"expires_in"`
}

// PollInterval returns a sane poll cadence: the server value when positive, else the
// RFC 8628 default of 5 seconds (liberal-accept: a missing/0 interval must still work).
func (d DeviceAuth) PollInterval() time.Duration {
	if d.Interval > 0 {
		return time.Duration(d.Interval) * time.Second
	}
	return 5 * time.Second
}

// Lifetime returns how long the device_code is valid: the server value when positive,
// else a conservative 10-minute default so the flow can never poll forever.
func (d DeviceAuth) Lifetime() time.Duration {
	if d.ExpiresIn > 0 {
		return time.Duration(d.ExpiresIn) * time.Second
	}
	return 10 * time.Minute
}

// OpenURL returns the best URL to send the user to: the complete (code-embedded) one
// when present, otherwise the plain verification URI.
func (d DeviceAuth) OpenURL() string {
	if u := strings.TrimSpace(d.VerificationURIComplete); u != "" {
		return u
	}
	return strings.TrimSpace(d.VerificationURI)
}

// DeviceTokenStatus is the discriminator of POST /api/device/token.
type DeviceTokenStatus string

const (
	DeviceStatusPending  DeviceTokenStatus = "pending"  // keep polling
	DeviceStatusApproved DeviceTokenStatus = "approved" // APIKey is set
	DeviceStatusExpired  DeviceTokenStatus = "expired"  // give up, restart the flow
)

// DeviceToken is one POST /api/device/token reply.
type DeviceToken struct {
	Status DeviceTokenStatus `json:"status"`
	// APIKey is set ONLY when Status == approved. NEVER log it.
	APIKey string `json:"api_key"`
}

// DeviceHTTPClient builds an HTTP client wired with the embedded-CA TLS config and a
// per-call timeout suitable for the device flow. It is used when a caller does not
// supply its own client (e.g. the real `whisper login`); tests inject httptest's client.
func DeviceHTTPClient() *http.Client {
	return &http.Client{
		Timeout: DeviceClientTimeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSClientConfig:       TLSConfig(),
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// DeviceAuthorize starts the device-authorization flow: POST <consoleURL>/api/device/
// authorize (no auth, empty JSON body) and decode the DeviceAuth. consoleURL is trimmed
// of a trailing slash; an empty consoleURL falls back to DefaultConsoleURL. hc may be
// nil, in which case a default embedded-CA client is built. ctx cancellation aborts the
// call. A non-2xx or malformed reply yields a clear *ProblemError, never a panic.
func DeviceAuthorize(ctx context.Context, hc *http.Client, consoleURL string) (*DeviceAuth, error) {
	base := consoleBase(consoleURL)
	if hc == nil {
		hc = DeviceHTTPClient()
	}
	body, err := devicePostJSON(ctx, hc, base+"/api/device/authorize", map[string]any{})
	if err != nil {
		return nil, err
	}
	var da DeviceAuth
	if err := json.Unmarshal(body, &da); err != nil {
		return nil, &ProblemError{Status: 502, Title: "bad device-authorize reply",
			Detail: "the console returned a device-authorize reply we couldn't parse"}
	}
	if strings.TrimSpace(da.DeviceCode) == "" || da.OpenURL() == "" {
		return nil, &ProblemError{Status: 502, Title: "incomplete device-authorize reply",
			Detail: "the console's device-authorize reply was missing a device_code or verification URL"}
	}
	return &da, nil
}

// PollDeviceToken polls POST <consoleURL>/api/device/token with {device_code} every
// interval until the console returns approved (-> the api_key), expired, the deadline
// passes, or ctx is cancelled. It honours the RFC 8628 minimum cadence (a 0/negative
// interval falls back to 5s). On approval it returns the api_key; on expiry/deadline it
// returns a clear *ProblemError. The api_key and device_code are NEVER logged.
//
// hc may be nil (a default embedded-CA client is built). deviceCode is the secret from
// DeviceAuthorize. A transient pending-poll transport error is tolerated (we keep
// polling until the deadline) so a momentary blip never aborts an otherwise-fine login.
func PollDeviceToken(ctx context.Context, hc *http.Client, consoleURL, deviceCode string, interval, deadline time.Duration) (string, error) {
	base := consoleBase(consoleURL)
	if hc == nil {
		hc = DeviceHTTPClient()
	}
	if strings.TrimSpace(deviceCode) == "" {
		return "", &ProblemError{Status: 400, Title: "no device_code", Detail: "cannot poll for a token without a device_code"}
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if deadline <= 0 {
		deadline = 10 * time.Minute
	}

	// Bound the whole poll loop by the deadline AND the parent ctx (whichever fires
	// first). A cancelled parent ctx (Ctrl-C) must abort promptly.
	loopCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	timer := time.NewTimer(0) // first poll fires immediately
	defer timer.Stop()

	for {
		select {
		case <-loopCtx.Done():
			// Distinguish a user cancel (parent ctx) from the deadline elapsing.
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			// The deadline elapsed: ALWAYS a clean, deterministic 408 timeout. We deliberately
			// do NOT surface the last poll's error: if the deadline cancelled a poll that was
			// mid-flight, that in-flight cancel produces an opaque "context canceled" transport
			// error, and returning it would both leak that noise and make this path racy. A
			// timeout is a timeout.
			return "", &ProblemError{Status: 408, Title: "login timed out",
				Detail: "the sign-in wasn't approved in time — run 'whisper login' again to retry"}
		case <-timer.C:
		}

		tok, err := pollOnce(loopCtx, hc, base, deviceCode)
		if err != nil {
			// A transient transport error during polling is non-fatal: keep trying until the
			// deadline (Postel: a momentary blip must not abort). A definitive cancel/deadline
			// is caught by the select above, which always yields the clean 408/cancel result.
			timer.Reset(interval)
			continue
		}
		switch tok.Status {
		case DeviceStatusApproved:
			key := strings.TrimSpace(tok.APIKey)
			if key == "" {
				return "", &ProblemError{Status: 502, Title: "approved without a key",
					Detail: "the console approved the sign-in but returned no api_key — try again"}
			}
			return key, nil
		case DeviceStatusExpired:
			return "", &ProblemError{Status: 410, Title: "login code expired",
				Detail: "the sign-in code expired before approval — run 'whisper login' again to retry"}
		case DeviceStatusPending:
			timer.Reset(interval)
		default:
			// An unknown status is treated as pending (liberal-accept): keep polling
			// rather than aborting on a status we don't recognise.
			timer.Reset(interval)
		}
	}
}

// pollOnce performs a single POST /api/device/token and decodes the status reply.
func pollOnce(ctx context.Context, hc *http.Client, base, deviceCode string) (*DeviceToken, error) {
	body, err := devicePostJSON(ctx, hc, base+"/api/device/token", map[string]any{"device_code": deviceCode})
	if err != nil {
		return nil, err
	}
	var tok DeviceToken
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, &ProblemError{Status: 502, Title: "bad device-token reply",
			Detail: "the console returned a device-token reply we couldn't parse"}
	}
	return &tok, nil
}

// devicePostJSON POSTs a small JSON body (no auth header — the device endpoints are
// keyless) and returns the response body for a 2xx, or a helpful *ProblemError. The
// read is capped so a hostile/huge body can never exhaust memory.
func devicePostJSON(ctx context.Context, hc *http.Client, url string, payload map[string]any) ([]byte, error) {
	buf, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(buf)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	// Deliberately NO auth header: the device endpoints are keyless (RFC 8628).

	resp, err := hc.Do(req)
	if err != nil {
		// A cancelled/expired context surfaces here; pass it through unwrapped so the
		// caller can distinguish ctx cancellation from a real transport fault.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("console unreachable at %s: %w", url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap — these replies are tiny
	if err != nil {
		return nil, fmt.Errorf("reading the console reply: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &ProblemError{Status: resp.StatusCode, Title: "device login rejected",
			Detail: fmt.Sprintf("the console returned HTTP %d for the device login request", resp.StatusCode)}
	}
	return raw, nil
}

// consoleBase normalises the console URL: trim a trailing slash; empty -> the default.
func consoleBase(consoleURL string) string {
	u := strings.TrimSpace(consoleURL)
	if u == "" {
		u = DefaultConsoleURL
	}
	return strings.TrimRight(u, "/")
}
