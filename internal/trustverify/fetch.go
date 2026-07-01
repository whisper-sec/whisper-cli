// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Fetcher retrieves HTTP resources for the transparency + identity-doc steps.
//
//   - Get fetches over ordinary WebPKI (the transparency object, JWKS and /checkpoint/key are
//     served by the gateway under a publicly-trusted cert) -- this is the trust-on-pin surface.
//   - GetPinned fetches over a DANE-EE-pinned connection: it dials the exact validated /128
//     and verifies the served leaf against the DNSSEC TLSA pin (no WebPKI). The identity_doc,
//     served by the agent itself, is fetched this way so its transport is DNSSEC-trustless.
type Fetcher interface {
	Get(ctx context.Context, url string) (body []byte, status int, err error)
	GetPinned(ctx context.Context, hostport, sni, path string, pin TLSAPin) (body []byte, status int, err error)
}

const maxFetchBytes = 8 << 20 // 8 MiB -- generous, never unbounded

// httpFetcher is the production Fetcher.
type httpFetcher struct{ client *http.Client }

// NewHTTPFetcher returns the production Fetcher.
//
// Keep-alive and HTTP/2 are disabled deliberately: the fleet serves ONE signing key per node
// behind a load-balanced JWKS URL, so a pinned (kept-alive / multiplexed) connection would
// always hit the same node and only ever see one kid. A fresh TCP connection per request lets
// the balancer spread the aggregation across nodes so every published kid is collectable.
func NewHTTPFetcher() Fetcher {
	return &httpFetcher{client: &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     false,
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		},
	}}
}

func (f *httpFetcher) Get(ctx context.Context, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "whisper-cli/trustverify")
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading %s: %w", url, err)
	}
	return body, resp.StatusCode, nil
}

// GetPinned fetches https://<sni><path> but forces the TCP connection to hostport and
// verifies the served leaf SPKI against pin (DANE-EE). WebPKI is deliberately skipped.
func (f *httpFetcher) GetPinned(ctx context.Context, hostport, sni, path string, pin TLSAPin) ([]byte, int, error) {
	dialTLS := func(dctx context.Context, network, _ string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 10 * time.Second}
		raw, err := d.DialContext(dctx, "tcp", hostport)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(raw, &tls.Config{
			ServerName:         strings.TrimSuffix(sni, "."),
			InsecureSkipVerify: true, //nolint:gosec // DANE-EE: verified against the DNSSEC pin below
			MinVersion:         tls.VersionTLS12,
		})
		if err := conn.HandshakeContext(dctx); err != nil {
			raw.Close()
			return nil, err
		}
		certs := conn.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			conn.Close()
			return nil, fmt.Errorf("identity_doc: no certificate served")
		}
		got := SPKISHA256(certs[0])
		if !constEq(got[:], pin.SHA256) {
			conn.Close()
			return nil, fmt.Errorf("identity_doc: served SPKI does not match the DANE pin (refusing to fetch)")
		}
		return conn, nil
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{DialTLSContext: dialTLS, DisableKeepAlives: true},
	}
	url := "https://" + strings.TrimSuffix(sni, ".") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "whisper-cli/trustverify")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch identity_doc %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading identity_doc: %w", err)
	}
	return body, resp.StatusCode, nil
}

// aggregateJWKS fetches every jwks URL up to `rounds` times each, merging keys by kid. The
// fleet serves ONE ES256 key per node behind a shared JWKS URL, so aggregating a few fetches
// collects the kid a given signature was made under (Postel: liberal in what we accept).
func aggregateJWKS(ctx context.Context, f Fetcher, urls []string, rounds int, wantKid string) (JWKSet, error) {
	set := JWKSet{}
	var lastErr error
	for _, u := range urls {
		for i := 0; i < rounds; i++ {
			body, status, err := f.Get(ctx, u)
			if err != nil {
				lastErr = err
				continue
			}
			if status != http.StatusOK {
				lastErr = fmt.Errorf("jwks %s: HTTP %d", u, status)
				continue
			}
			part, err := ParseJWKS(body)
			if err != nil {
				lastErr = err
				continue
			}
			set.merge(part)
			if wantKid != "" {
				if _, ok := set[wantKid]; ok {
					return set, nil
				}
			}
		}
	}
	if len(set) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return set, nil
}
