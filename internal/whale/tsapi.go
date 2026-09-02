// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// tsapi.go is the READ-ONLY half of the migration: everything it can do is a GET.
//
// There is no write method on this type and no code path that could construct one. That
// is the acceptance criterion "changes nothing on either side" made structural rather
// than promised: `plan` cannot mutate their tailnet because the only client it has cannot
// express a mutation.
//
// Every read is behind APIReader so the mapper and the plan writer are testable against a
// fixture with no network and no credential at all.

// DefaultTailscaleAPIBase is their v2 API root.
const DefaultTailscaleAPIBase = "https://api.tailscale.com/api/v2"

// APIReader performs one authenticated GET against the Tailscale API and returns the body
// and the HTTP status. It returns an error only for a transport failure: a 4xx or 5xx is
// an ANSWER, and the caller decides what it means (a 403 on `keys` is a scope note, not a
// reason to abandon the run).
type APIReader interface {
	Get(ctx context.Context, path string) (body []byte, status int, err error)
}

// HTTPReader is the real reader. It holds the credential for the life of the command and
// hands it to nothing else.
type HTTPReader struct {
	Base   string
	Client *http.Client
	cred   Credential

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// NewHTTPReader builds a reader over cred. base may be empty for the real API.
func NewHTTPReader(cred Credential, base string, timeout time.Duration) *HTTPReader {
	if strings.TrimSpace(base) == "" {
		base = DefaultTailscaleAPIBase
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &HTTPReader{Base: strings.TrimSuffix(base, "/"), Client: &http.Client{Timeout: timeout}, cred: cred}
}

// Get performs one GET. The credential goes into the Authorization header and nowhere
// else: not into the URL, not into an error, not into a log line.
func (r *HTTPReader) Get(ctx context.Context, path string) ([]byte, int, error) {
	if r.cred.IsZero() {
		return nil, 0, fmt.Errorf("no tailscale credential: set TS_API_KEY, or TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET")
	}
	auth, err := r.authorization(ctx)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.Base+path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("building the request for %s: %w", path, err)
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("reading %s: %s", path, Scrub(err.Error()))
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if rerr != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading %s: %s", path, Scrub(rerr.Error()))
	}
	return body, resp.StatusCode, nil
}

// authorization returns the header value, minting an OAuth access token on first use.
func (r *HTTPReader) authorization(ctx context.Context) (string, error) {
	if r.cred.Kind() == CredentialAPIKey {
		return "Bearer " + r.cred.secretValue(), nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.token != "" && time.Now().Before(r.tokenExp) {
		return "Bearer " + r.token, nil
	}
	form := url.Values{
		"client_id":     {r.cred.ClientID()},
		"client_secret": {r.cred.secretValue()},
		"grant_type":    {"client_credentials"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Base+"/oauth/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("building the oauth token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := r.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("exchanging the oauth client for a token: %s", Scrub(err.Error()))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("tailscale refused the oauth client (status %d): %s",
			resp.StatusCode, Scrub(strings.TrimSpace(string(body))))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("tailscale's oauth response carried no access token")
	}
	r.token = tok.AccessToken
	ttl := time.Duration(tok.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	r.tokenExp = time.Now().Add(ttl - 30*time.Second)
	return "Bearer " + r.token, nil
}

// --- the read ---------------------------------------------------------------------

// ReadTailnet reads everything one plan needs.
//
// It returns an error ONLY when a load-bearing section cannot be read, because a plan
// built on a tailnet whose device list timed out would migrate nothing while looking
// complete. Everything else is recorded as a named absence on Tailnet.Unread and carried
// into the fidelity report.
func ReadTailnet(ctx context.Context, r APIReader, tailnet string) (*Tailnet, error) {
	name := strings.TrimSpace(tailnet)
	if name == "" {
		name = "-" // their API's alias for "the tailnet this credential belongs to"
	}
	t := &Tailnet{Name: name}
	esc := url.PathEscape(name)

	// 1) Devices. Load-bearing: no devices, no plan.
	body, status, err := r.Get(ctx, "/tailnet/"+esc+"/devices?fields=all")
	switch {
	case err != nil:
		return nil, fmt.Errorf("reading the device list of tailnet %s: %s", name, Scrub(err.Error()))
	case status != http.StatusOK:
		return nil, fmt.Errorf("reading the device list of tailnet %s returned status %d: %s",
			name, status, apiErrorText(body))
	}
	var devs struct {
		Devices []TSDevice `json:"devices"`
	}
	if err := json.Unmarshal(body, &devs); err != nil {
		return nil, fmt.Errorf("their device list did not parse as JSON: %w", err)
	}
	t.Devices = devs.Devices

	// 2) The policy file, verbatim HuJSON. Load-bearing: the whole fidelity question is
	// in this file, and a plan without it would report a clean migration of nothing.
	pbody, pstatus, perr := r.Get(ctx, "/tailnet/"+esc+"/acl")
	switch {
	case perr != nil:
		return nil, fmt.Errorf("reading the policy file of tailnet %s: %s", name, Scrub(perr.Error()))
	case pstatus != http.StatusOK:
		return nil, fmt.Errorf("reading the policy file of tailnet %s returned status %d: %s",
			name, pstatus, apiErrorText(pbody))
	}
	pol, lines, plerr := ParsePolicy(pbody)
	if plerr != nil {
		return nil, plerr
	}
	t.Policy, t.PolicyLines = pol, lines

	// 3) Per-device routes. Soft: a device whose routes we could not read carries the
	// reason, and the report prints it rather than a confident "no routes".
	for i := range t.Devices {
		d := &t.Devices[i]
		if strings.TrimSpace(d.ID) == "" {
			d.RoutesUnread = "the device carries no id"
			continue
		}
		rb, rs, rerr := r.Get(ctx, "/device/"+url.PathEscape(d.ID)+"/routes")
		switch {
		case rerr != nil:
			d.RoutesUnread = Scrub(rerr.Error())
		case rs != http.StatusOK:
			d.RoutesUnread = fmt.Sprintf("status %d: %s", rs, apiErrorText(rb))
		default:
			var rt struct {
				AdvertisedRoutes []string `json:"advertisedRoutes"`
				EnabledRoutes    []string `json:"enabledRoutes"`
			}
			if uerr := json.Unmarshal(rb, &rt); uerr != nil {
				d.RoutesUnread = "their route list did not parse as JSON"
			} else {
				d.AdvertisedRoutes, d.EnabledRoutes = rt.AdvertisedRoutes, rt.EnabledRoutes
			}
		}
	}

	// 4) Auth-key metadata. Soft, and the secrets are unreadable by design either way.
	readInto(ctx, r, t, "keys", "/tailnet/"+esc+"/keys", func(b []byte) error {
		var ks struct {
			Keys []TSKey `json:"keys"`
		}
		if err := json.Unmarshal(b, &ks); err != nil {
			return err
		}
		t.Keys = ks.Keys
		return nil
	})

	// 5) Users. Soft: they inform the owner mapping, and an unread user list widens no rule.
	readInto(ctx, r, t, "users", "/tailnet/"+esc+"/users", func(b []byte) error {
		var us struct {
			Users []TSUser `json:"users"`
		}
		if err := json.Unmarshal(b, &us); err != nil {
			return err
		}
		t.Users = us.Users
		return nil
	})

	// 6) DNS, in the four separate reads their API splits it into.
	readInto(ctx, r, t, "dns.nameservers", "/tailnet/"+esc+"/dns/nameservers", func(b []byte) error {
		var v struct {
			DNS []string `json:"dns"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		t.DNS.Nameservers = v.DNS
		return nil
	})
	readInto(ctx, r, t, "dns.preferences", "/tailnet/"+esc+"/dns/preferences", func(b []byte) error {
		var v struct {
			MagicDNS bool `json:"magicDNS"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		t.DNS.MagicDNS = v.MagicDNS
		return nil
	})
	readInto(ctx, r, t, "dns.searchpaths", "/tailnet/"+esc+"/dns/searchpaths", func(b []byte) error {
		var v struct {
			SearchPaths []string `json:"searchPaths"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		t.DNS.SearchPaths = v.SearchPaths
		return nil
	})
	readInto(ctx, r, t, "dns.split-dns", "/tailnet/"+esc+"/dns/split-dns", func(b []byte) error {
		var v map[string][]string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		t.DNS.SplitDNS = v
		return nil
	})

	return t, nil
}

// readInto performs one soft read: on any failure it records a NAMED ABSENCE and returns,
// so an empty section and an unread section can never be confused downstream.
func readInto(ctx context.Context, r APIReader, t *Tailnet, section, path string, decode func([]byte) error) {
	b, status, err := r.Get(ctx, path)
	switch {
	case err != nil:
		t.markUnread(section, err.Error(), false)
	case status == http.StatusForbidden:
		t.markUnread(section, "the credential is not scoped to read it (status 403)", false)
	case status != http.StatusOK:
		t.markUnread(section, fmt.Sprintf("status %d: %s", status, apiErrorText(b)), false)
	default:
		if derr := decode(b); derr != nil {
			t.markUnread(section, "the response did not parse: "+derr.Error(), false)
		}
	}
}

// apiErrorText lifts their error message out of a non-200 body, scrubbed, and truncated so
// a wall of HTML never lands in a terminal.
func apiErrorText(body []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && strings.TrimSpace(e.Message) != "" {
		return Scrub(strings.TrimSpace(e.Message))
	}
	s := Scrub(strings.TrimSpace(string(body)))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	if s == "" {
		s = "(no message)"
	}
	return s
}
