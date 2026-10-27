// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"strings"
	"testing"
)

func TestResolvConfNamesOnlyTheTunnelResolvers(t *testing.T) {
	got := resolvConf([]string{"2a04:2a01:0:53::1", "not-an-ip", "2a04:2a00::53"})
	if strings.Count(got, "nameserver ") != 2 || !strings.Contains(got, "nameserver 2a04:2a01:0:53::1\n") ||
		!strings.Contains(got, "nameserver 2a04:2a00::53\n") || strings.Contains(got, "not-an-ip") {
		t.Fatalf("resolv.conf:\n%s", got)
	}
}

func TestNsswitchKeepsEverythingButTheHostsLine(t *testing.T) {
	host := "passwd:         files systemd\ngroup:          files systemd\nhosts:          files mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns myhostname\nnetworks:       files\n"
	got := nsswitch(host)
	if !strings.Contains(got, "hosts:          files dns\n") || strings.Contains(got, "mdns4") || strings.Contains(got, "resolve") {
		t.Fatalf("hosts line not replaced:\n%s", got)
	}
	if !strings.Contains(got, "passwd:         files systemd\n") || !strings.Contains(got, "networks:       files\n") {
		t.Fatalf("other databases must survive:\n%s", got)
	}
	if got := nsswitch("passwd: files\n"); !strings.Contains(got, "hosts:          files dns\n") {
		t.Fatal("a file with no hosts line gains one")
	}
	if got := nsswitch("hosts: files\nhosts: dns mdns\n"); strings.Count(got, "hosts:") != 1 {
		t.Fatal("duplicate hosts lines collapse to one")
	}
}

func TestUnderAny(t *testing.T) {
	c := map[string]bool{"/run/systemd/resolve": true}
	if !underAny("/run/systemd/resolve/stub-resolv.conf", c) || underAny("/run/systemd/resolvexx", c) || !underAny("/run/systemd/resolve", c) {
		t.Fatal("underAny prefix logic")
	}
}
