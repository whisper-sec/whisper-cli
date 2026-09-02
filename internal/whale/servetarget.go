// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// servetarget.go parses the one argument `whale serve` and `whale funnel` take: WHERE the
// request should go once we have terminated TLS and stamped the identity headers on it.
//
// Postel at the argument boundary, exactly like the rest of the whale shell. Every spelling
// a person would reach for means the same thing:
//
//	3000 -> http://127.0.0.1:3000
//	:3000 -> http://127.0.0.1:3000
//	localhost:3000 -> http://localhost:3000
//	127.0.0.1:3000 -> http://127.0.0.1:3000
//	[::1]:3000 -> http://[::1]:3000
//	http://127.0.0.1:3000 -> as written
//	http://localhost:3000/api -> as written, base path included
//	https://127.0.0.1:8443 -> as written (we dial the origin's own TLS)
//
// What it will NOT do is guess. A directory path, a `text:"..."` literal and the other
// Tailscale target forms are refused BY NAME, with the reason, because silently treating
// `./public` as a hostname would produce a serve that starts, looks healthy and answers
// nothing.

// ServeTarget is a parsed origin: where proxied requests are sent.
type ServeTarget struct {
	// URL is the origin, always with a scheme and a host:port.
	URL *url.URL
	// Raw is what the user typed, for messages.
	Raw string
	// Loopback reports whether the origin is on this host. A non-loopback origin is
	// allowed and noted, never refused: forwarding to a nearby box is a real thing to do.
	Loopback bool
}

// String is the canonical origin, the form written into the state record.
func (t ServeTarget) String() string {
	if t.URL == nil {
		return ""
	}
	return t.URL.String()
}

// ParseServeTarget turns any accepted spelling into one origin URL.
func ParseServeTarget(raw string) (ServeTarget, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ServeTarget{}, fmt.Errorf("give the local port or address to serve, for example `3000` or `http://127.0.0.1:3000`")
	}
	if strings.HasPrefix(s, "text:") {
		return ServeTarget{}, fmt.Errorf("`text:` targets are not supported: %s serves a local HTTP origin, so run one and point at its port", "whale serve")
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "~") || strings.HasPrefix(s, `.\`) {
		return ServeTarget{}, fmt.Errorf("%q looks like a path, and serving a directory is not supported yet: point at a local HTTP origin instead, for example `3000`", s)
	}

	// A bare port, with or without the colon a person types out of habit.
	bare := strings.TrimPrefix(s, ":")
	if p, err := strconv.Atoi(bare); err == nil {
		if p < 1 || p > 65535 {
			return ServeTarget{}, fmt.Errorf("%q is not a port: a port is 1 to 65535", s)
		}
		return target("http://127.0.0.1:" + strconv.Itoa(p))
	}

	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return ServeTarget{}, fmt.Errorf("%q is not a URL we can parse: %v", s, err)
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https":
		case "ws", "wss":
			return ServeTarget{}, fmt.Errorf("point at %q instead: WebSockets ride over the http/https origin and are proxied through, upgrade included",
				strings.Replace(s, u.Scheme+"://", map[string]string{"ws": "http", "wss": "https"}[strings.ToLower(u.Scheme)]+"://", 1))
		default:
			return ServeTarget{}, fmt.Errorf("%q is not a scheme we can proxy to: use http:// or https://", u.Scheme)
		}
		if u.Host == "" {
			return ServeTarget{}, fmt.Errorf("%q names no host: try http://127.0.0.1:3000", s)
		}
		return target(u.String())
	}

	// host:port, including a bracketed IPv6 literal.
	if _, _, err := net.SplitHostPort(s); err == nil {
		return target("http://" + s)
	}
	// A bare IPv6 literal with no port and no brackets is a common paste; say what is
	// missing rather than failing on a parse.
	if _, err := netip.ParseAddr(s); err == nil {
		return ServeTarget{}, fmt.Errorf("%q has no port: write it as [%s]:3000", s, s)
	}
	return ServeTarget{}, fmt.Errorf("%q is not a port, a host:port or a URL: try `3000`, `localhost:3000` or `http://127.0.0.1:3000`", s)
}

// target finalises a parsed origin: default the port from the scheme, and work out whether
// the origin is on this host.
func target(raw string) (ServeTarget, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return ServeTarget{}, fmt.Errorf("%q is not a URL we can parse: %v", raw, err)
	}
	host := u.Hostname()
	if host == "" {
		return ServeTarget{}, fmt.Errorf("%q names no host: try http://127.0.0.1:3000", raw)
	}
	if u.Port() == "" {
		if strings.EqualFold(u.Scheme, "https") {
			u.Host = net.JoinHostPort(host, "443")
		} else {
			u.Host = net.JoinHostPort(host, "80")
		}
	} else if p, perr := strconv.Atoi(u.Port()); perr != nil || p < 1 || p > 65535 {
		return ServeTarget{}, fmt.Errorf("%q is not a port: a port is 1 to 65535", u.Port())
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return ServeTarget{URL: u, Raw: raw, Loopback: isLoopbackHost(host)}, nil
}

// isLoopbackHost reports whether a host names this machine, by literal or by the two names
// every system resolves to it.
func isLoopbackHost(host string) bool {
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return addr.IsLoopback()
	}
	switch strings.ToLower(strings.TrimSuffix(host, ".")) {
	case "localhost", "localhost.localdomain":
		return true
	}
	return false
}

// MountPath normalises the --set-path value: "" or "/" mean the root, anything else is
// given its leading slash and stripped of a trailing one, so "/api/" and "api" are the
// same mount and the state record only ever holds one spelling.
func MountPath(p string) (string, error) {
	s := strings.TrimSpace(p)
	if s == "" || s == "/" {
		return "/", nil
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return "", fmt.Errorf("%q is not a path: a mount path has no spaces", p)
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	for len(s) > 1 && strings.HasSuffix(s, "/") {
		s = strings.TrimSuffix(s, "/")
	}
	if strings.Contains(s, "..") {
		return "", fmt.Errorf("%q is not a mount path: it must not contain `..`", p)
	}
	return s, nil
}
