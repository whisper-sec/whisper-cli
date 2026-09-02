// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// tsapi_test.go proves the read is a read, and that a FAULT never renders as an ANSWER.

// fakeReader answers from a table and records every path it was asked for, so a test can
// assert both what came back and what was requested.
type fakeReader struct {
	bodies map[string]string
	status map[string]int
	errs   map[string]error
	asked  []string
}

func (f *fakeReader) Get(_ context.Context, path string) ([]byte, int, error) {
	f.asked = append(f.asked, path)
	if err, ok := f.errs[path]; ok {
		return nil, 0, err
	}
	st := http.StatusOK
	if s, ok := f.status[path]; ok {
		st = s
	}
	return []byte(f.bodies[path]), st, nil
}

func devicesJSON() string {
	return `{"devices":[{"id":"d1","hostname":"db-01","name":"db-01.tail1234.ts.net","addresses":["100.64.0.9"],"os":"linux"}]}`
}

func newFake() *fakeReader {
	return &fakeReader{
		bodies: map[string]string{
			"/tailnet/example.com/devices?fields=all": devicesJSON(),
			"/tailnet/example.com/acl":                `{"acls":[]}`,
			"/device/d1/routes":                       `{"advertisedRoutes":["10.0.0.0/24"],"enabledRoutes":[]}`,
			"/tailnet/example.com/keys":               `{"keys":[{"id":"kABC"}]}`,
			"/tailnet/example.com/users":              `{"users":[{"id":"u1","loginName":"a@example.com"}]}`,
			"/tailnet/example.com/dns/nameservers":    `{"dns":["1.1.1.1"]}`,
			"/tailnet/example.com/dns/preferences":    `{"magicDNS":true}`,
			"/tailnet/example.com/dns/searchpaths":    `{"searchPaths":[]}`,
			"/tailnet/example.com/dns/split-dns":      `{}`,
		},
		status: map[string]int{},
		errs:   map[string]error{},
	}
}

func TestReadTailnetReadsEverySection(t *testing.T) {
	f := newFake()
	tn, err := ReadTailnet(context.Background(), f, "example.com")
	if err != nil {
		t.Fatalf("ReadTailnet: %v", err)
	}
	if len(tn.Devices) != 1 || tn.Devices[0].ShortName() != "db-01" {
		t.Fatalf("devices: %+v", tn.Devices)
	}
	if len(tn.Devices[0].AdvertisedRoutes) != 1 {
		t.Fatal("the per-device route read did not land on the device")
	}
	if len(tn.Keys) != 1 || len(tn.Users) != 1 || len(tn.DNS.Nameservers) != 1 {
		t.Fatalf("a soft section was lost: keys=%d users=%d ns=%d", len(tn.Keys), len(tn.Users), len(tn.DNS.Nameservers))
	}
	if len(tn.Unread) != 0 {
		t.Fatalf("a clean read recorded absences: %+v", tn.Unread)
	}
}

// This is the one that keeps the tool from lying: a 403 on a soft section is recorded as a
// NAMED ABSENCE, never as an empty section.
func TestAForbiddenSectionIsANamedAbsenceNotAnEmptyOne(t *testing.T) {
	f := newFake()
	f.status["/tailnet/example.com/keys"] = http.StatusForbidden
	tn, err := ReadTailnet(context.Background(), f, "example.com")
	if err != nil {
		t.Fatalf("a 403 on auth keys must not abort the whole read: %v", err)
	}
	if len(tn.Keys) != 0 {
		t.Fatal("keys were populated from a 403")
	}
	var found bool
	for _, u := range tn.Unread {
		if u.Section == "keys" {
			found = true
			if u.LoadBearing {
				t.Error("auth-key metadata was marked load-bearing; a plan is still valid without it")
			}
			if !strings.Contains(u.Reason, "403") {
				t.Errorf("the reason does not name the status: %q", u.Reason)
			}
		}
	}
	if !found {
		t.Fatal("a 403 on keys left no record, so zero auth keys would read as a tailnet with none")
	}
}

// A load-bearing failure must be an error, not an empty plan.
func TestAFailedDeviceReadIsAnErrorNotAnEmptyTailnet(t *testing.T) {
	f := newFake()
	f.status["/tailnet/example.com/devices?fields=all"] = http.StatusInternalServerError
	f.bodies["/tailnet/example.com/devices?fields=all"] = `{"message":"upstream is down"}`
	_, err := ReadTailnet(context.Background(), f, "example.com")
	if err == nil {
		t.Fatal("a 500 on the device list produced a tailnet, which would plan a migration of nothing")
	}
	if !strings.Contains(err.Error(), "upstream is down") {
		t.Fatalf("the error does not carry their message: %v", err)
	}
}

func TestAFailedPolicyReadIsAnError(t *testing.T) {
	f := newFake()
	f.status["/tailnet/example.com/acl"] = http.StatusForbidden
	if _, err := ReadTailnet(context.Background(), f, "example.com"); err == nil {
		t.Fatal("an unreadable policy file produced a plan, and the entire fidelity question lives in that file")
	}
}

func TestAFailedRouteReadIsRecordedPerDevice(t *testing.T) {
	f := newFake()
	f.status["/device/d1/routes"] = http.StatusInternalServerError
	tn, err := ReadTailnet(context.Background(), f, "example.com")
	if err != nil {
		t.Fatalf("one device's route read failing must not abort the run: %v", err)
	}
	if tn.Devices[0].RoutesUnread == "" {
		t.Fatal("a failed route read left no trace, so a subnet router would look like an ordinary node")
	}
}

// The credential must not appear in an error, whatever their API echoed back.
func TestUpstreamErrorTextIsScrubbed(t *testing.T) {
	f := newFake()
	f.status["/tailnet/example.com/devices?fields=all"] = http.StatusUnauthorized
	f.bodies["/tailnet/example.com/devices?fields=all"] = `{"message":"invalid key tskey-api-abcdef123456"}`
	_, err := ReadTailnet(context.Background(), f, "example.com")
	if err == nil {
		t.Fatal("a 401 produced no error")
	}
	if strings.Contains(err.Error(), "tskey-api-abcdef123456") {
		t.Fatalf("the credential was echoed into an error message: %v", err)
	}
}

// "Changes nothing on either side" is structural: the reader has no method that could
// write. This test fails to compile, deliberately, if a write method is ever added and
// this assertion is updated to match it.
func TestTheReaderInterfaceIsReadOnly(t *testing.T) {
	var r APIReader = newFake()
	// APIReader has exactly one method. If that ever stops being true, this file is the
	// place the change gets argued about.
	if _, _, err := r.Get(context.Background(), "/tailnet/example.com/acl"); err != nil {
		t.Fatalf("Get: %v", err)
	}
}

func TestTailnetDefaultsToTheCredentialsOwnTailnet(t *testing.T) {
	f := &fakeReader{
		bodies: map[string]string{"/tailnet/-/devices?fields=all": devicesJSON(), "/tailnet/-/acl": `{}`},
		status: map[string]int{}, errs: map[string]error{},
	}
	tn, err := ReadTailnet(context.Background(), f, "  ")
	if err != nil {
		t.Fatalf("an empty tailnet name must mean \"the one this credential belongs to\": %v", err)
	}
	if tn.Name != "-" {
		t.Fatalf("tailnet name %q", tn.Name)
	}
}

func TestDeviceHelpers(t *testing.T) {
	d := TSDevice{Name: "db-01.tail1234.ts.net", Hostname: "db01",
		AdvertisedRoutes: []string{"10.0.0.0/24", "0.0.0.0/0", "::/0"}}
	if d.ShortName() != "db-01" {
		t.Fatalf("ShortName %q", d.ShortName())
	}
	if !d.IsExitNodeCandidate() {
		t.Fatal("a node advertising a default route is an exit node candidate")
	}
	if got := d.SubnetRoutes(); len(got) != 1 || got[0] != "10.0.0.0/24" {
		t.Fatalf("SubnetRoutes %v: the default routes must not be counted as subnet routes", got)
	}
	bare := TSDevice{Hostname: "only-a-hostname"}
	if bare.ShortName() != "only-a-hostname" {
		t.Fatalf("a device with no MagicDNS name must fall back to its hostname, got %q", bare.ShortName())
	}
}
