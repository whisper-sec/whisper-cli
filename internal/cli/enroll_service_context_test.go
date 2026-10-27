// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// enroll_service_context_test.go pins a Windows split. The sensor service runs as
// LocalSystem and reads its key and its bind marker from the SYSTEM profile, while an
// administrator's elevated PowerShell is their own account. A bind run there used to land
// in the administrator's profile, which the sensor never reads, and say nothing. Seen on a
// real machine: a key, an agent and a marker under C:\Users\Administrator\.config\whisper,
// none in the SYSTEM profile, and 32 "no bound /128 identity" lines in the sensor log.
//
// The platform half is a seam (it asks the Service Control Manager), so these rows run on
// every OS: the decision and the writes are the same code the Windows binary runs.

// withServiceContext pins what the service manager would have said.
func withServiceContext(t *testing.T, ctx serviceIdentityContext) {
	t.Helper()
	saved := serviceIdentityContextFn
	serviceIdentityContextFn = func() serviceIdentityContext { return ctx }
	t.Cleanup(func() { serviceIdentityContextFn = saved })
}

// withPasteGOOS renders pasteable lines for goos for the length of the test.
func withPasteGOOS(t *testing.T, goos string) {
	t.Helper()
	saved := pasteGOOS
	pasteGOOS = goos
	t.Cleanup(func() { pasteGOOS = saved })
}

// systemProfileDir is a stand-in for C:\Windows\system32\config\systemprofile\.config\whisper,
// beside (never inside) the hermetic home that plays the administrator's profile.
func systemProfileDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "systemprofile", ".config", "whisper")
}

// sensorHost is a Windows host with the sensor installed, seen from an administrator's
// elevated PowerShell.
func sensorHost(dir string, elevated bool) serviceIdentityContext {
	// CanRead follows Elevated, as the platform half sets it: the SYSTEM profile grants
	// LocalSystem and Administrators only.
	return serviceIdentityContext{Installed: true, Service: "whisper-sensor", Account: "LocalSystem",
		Dir: dir, Elevated: elevated, CanRead: elevated}
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// The red row. Before the fix this bound, wrote the marker into the administrator's own
// profile, and left the SYSTEM profile with no marker and no key.
func TestEnrollAsAnAdministratorBindsWhereTheSensorServiceReads(t *testing.T) {
	adminHome := testenv.HermeticHome(t)
	sys := systemProfileDir(t)
	withServiceContext(t, sensorHost(sys, true))
	withHostname(t, "WIN-FRONTDESK-01")
	seen := enrollRecording(t, nil)

	res, err := runEnroll("", false)
	if err != nil {
		t.Fatalf("enroll from an elevated shell on a sensor host: %v", err)
	}
	if !registered(*seen) {
		t.Fatalf("a fresh host must be bound; ops %v", opsSeen(*seen))
	}
	id, ok := client.ReadBoundFile(filepath.Join(sys, "bound"))
	if !ok || id.Addr.String() != res.addr {
		t.Fatalf("the marker must be in the service's profile %s naming %s, got %+v ok=%v", sys, res.addr, id, ok)
	}
	if exists(client.DefaultBoundFile()) {
		t.Fatalf("the administrator's own profile %s must get no marker: the sensor never reads it", adminHome)
	}
	b, err := os.ReadFile(filepath.Join(sys, "key"))
	if err != nil || strings.TrimSpace(string(b)) != "whisper_live_test" {
		t.Fatalf("the key the bind used must be the service's key too, or it has a marker and nothing to report with (err %v)", err)
	}
	if got := client.ReadAgentFile(filepath.Join(sys, "agent")); got != res.agent {
		t.Fatalf("the service's saved agent must be the bound one %q, got %q", res.agent, got)
	}
	if got := client.ReadAgentFile(""); got != "" {
		t.Fatalf("the administrator's saved agent must be left alone, got %q", got)
	}
}

// A second run from the same shell is free: the marker is where the service reads it, so
// the run says it is already bound and calls nothing.
func TestEnrollAsAnAdministratorIsIdempotentOnTheServicesMarker(t *testing.T) {
	testenv.HermeticHome(t)
	sys := systemProfileDir(t)
	withServiceContext(t, sensorHost(sys, true))
	withHostname(t, "WIN-FRONTDESK-01")
	seen := enrollRecording(t, nil)
	if _, err := runEnroll("", false); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(sys, "bound"))
	*seen = nil

	res, err := runEnroll("", false)
	if err != nil || !res.already {
		t.Fatalf("a re-run must report already bound, got %+v err %v", res, err)
	}
	if len(*seen) != 0 {
		t.Fatalf("a re-run must call nothing, ops %v", opsSeen(*seen))
	}
	after, _ := os.ReadFile(filepath.Join(sys, "bound"))
	if !bytes.Equal(before, after) {
		t.Fatal("a re-run must leave the service's marker byte-identical")
	}
}

// A shell that cannot write the SYSTEM profile refuses in one line that names the command
// that does, and writes nothing anywhere.
func TestEnrollFromAnUnelevatedShellOnASensorHostRefusesAndNamesTheFix(t *testing.T) {
	testenv.HermeticHome(t)
	sys := systemProfileDir(t)
	withServiceContext(t, sensorHost(sys, false))
	withPasteGOOS(t, "windows")
	withHostname(t, "WIN-FRONTDESK-01")
	seen := enrollRecording(t, nil)

	_, err := runEnroll("front desk", false)
	if err == nil {
		t.Fatal("an unelevated enroll on a sensor host must refuse, not write where the sensor cannot see")
	}
	msg := err.Error()
	for _, want := range []string{"whisper-sensor", "LocalSystem", sys, "nothing was written",
		"elevated PowerShell", `'whisper enroll --name "front desk"'`} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal must contain %q, got %q", want, msg)
		}
	}
	if strings.Contains(msg, "\n") {
		t.Errorf("the refusal must be one line, got %q", msg)
	}
	if strings.Contains(msg, "sudo") {
		t.Errorf("a Windows refusal must not name sudo, got %q", msg)
	}
	if len(*seen) != 0 {
		t.Fatalf("a refusal must call nothing, ops %v", opsSeen(*seen))
	}
	if exists(client.DefaultBoundFile()) || exists(filepath.Join(sys, "bound")) {
		t.Fatal("a refusal must write no marker anywhere")
	}
}

// The control: a host with no sensor service keeps binding into the account that ran it,
// exactly as before.
func TestEnrollOnAHostWithNoSensorServiceStillWritesTheUserProfile(t *testing.T) {
	testenv.HermeticHome(t)
	withServiceContext(t, serviceIdentityContext{})
	withHostname(t, "laptop")
	enrollRecording(t, nil)

	res, err := runEnroll("", false)
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := client.ReadBoundFile(""); !ok || id.Addr.String() != res.addr {
		t.Fatalf("with no service the marker belongs in this account's profile, got %+v ok=%v", id, ok)
	}
}

// The other control: the Intune install and the service itself run as SYSTEM, whose own
// profile IS the service's. That path is unchanged.
func TestEnrollRunAsLocalSystemWritesItsOwnProfile(t *testing.T) {
	testenv.HermeticHome(t)
	ctx := sensorHost(systemProfileDir(t), true)
	ctx.Self = true
	withServiceContext(t, ctx)
	withHostname(t, "WIN-INTUNE-01")
	enrollRecording(t, nil)

	if _, err := runEnroll("", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := client.ReadBoundFile(""); !ok {
		t.Fatal("run as the service's own account, the marker belongs in that account's profile")
	}
	if exists(filepath.Join(ctx.Dir, "bound")) {
		t.Fatal("run as SYSTEM there is no second copy to write")
	}
}

// A service moved onto an account whose profile we cannot name refuses rather than guess.
func TestEnrollRefusesWhenTheServicesAccountIsUnknown(t *testing.T) {
	testenv.HermeticHome(t)
	ctx := sensorHost("", true)
	ctx.Account = `CORP\svc-whisper`
	ctx.Err = errString(`it runs as CORP\svc-whisper, not LocalSystem`)
	withServiceContext(t, ctx)
	withHostname(t, "WIN-FRONTDESK-01")
	seen := enrollRecording(t, nil)

	_, err := runEnroll("", false)
	if err == nil || !strings.Contains(err.Error(), `CORP\svc-whisper`) || !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("want a refusal naming the account, got %v", err)
	}
	if len(*seen) != 0 || exists(client.DefaultBoundFile()) {
		t.Fatal("a refusal must call nothing and write nothing")
	}
}

// The service already holds a key, and it is not the one this shell would bind with. A
// marker bound under one account and a key from another is a sensor that reports nowhere,
// so it refuses before calling anything.
func TestEnrollRefusesWhenTheServiceHoldsADifferentKey(t *testing.T) {
	testenv.HermeticHome(t)
	sys := systemProfileDir(t)
	if err := client.SaveServiceKey(filepath.Join(sys, "key"), "whisper_live_other"); err != nil {
		t.Fatal(err)
	}
	withServiceContext(t, sensorHost(sys, true))
	withHostname(t, "WIN-FRONTDESK-01")
	seen := enrollRecording(t, nil)

	_, err := runEnroll("", false)
	if err == nil || !strings.Contains(err.Error(), "different API key") || !strings.Contains(err.Error(), filepath.Join(sys, "key")) {
		t.Fatalf("want a refusal naming the service's key file, got %v", err)
	}
	if len(*seen) != 0 || exists(filepath.Join(sys, "bound")) {
		t.Fatal("a refusal must call nothing and write nothing")
	}
	if b, _ := os.ReadFile(filepath.Join(sys, "key")); string(b) != "whisper_live_other" {
		t.Fatal("the service's own key must be left alone")
	}
}

// The service already holds THIS key: bind, and leave the key file as it is.
func TestEnrollWithTheServicesOwnKeyBindsAndLeavesItAlone(t *testing.T) {
	testenv.HermeticHome(t)
	sys := systemProfileDir(t)
	if err := client.SaveServiceKey(filepath.Join(sys, "key"), "whisper_live_test"); err != nil {
		t.Fatal(err)
	}
	withServiceContext(t, sensorHost(sys, true))
	withHostname(t, "WIN-FRONTDESK-01")
	enrollRecording(t, nil)
	if _, err := runEnroll("", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := client.ReadBoundFile(filepath.Join(sys, "bound")); !ok {
		t.Fatal("the marker must land in the service's profile")
	}
}

// What the person reads after a bind in the service's profile: where it went and that the
// key went with it, so nobody goes looking in their own profile.
func TestEnrollAsAnAdministratorSaysWhereTheBindWent(t *testing.T) {
	testenv.HermeticHome(t)
	sys := systemProfileDir(t)
	withServiceContext(t, sensorHost(sys, true))
	withHostname(t, "WIN-FRONTDESK-01")
	enrollRecording(t, nil)
	g.quiet = false

	cmd := newEnrollCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{})
	var err error
	_, stderr := captureStd(t, func() { err = cmd.Execute() })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"whisper-sensor", "LocalSystem", filepath.Join(sys, "bound"), "API key"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the report must contain %q, got %q", want, stderr)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
