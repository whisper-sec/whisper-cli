// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These tests talk to the real filter engine, so they need an elevated Windows session. They
// were run on Windows Server 2022; elsewhere they skip and say why.

var procFwpmLayerGetByKey0 = fwpuclnt.NewProc("FwpmLayerGetByKey0")

type fwpmField0 struct {
	fieldKey *wfpGUID
	typ      uint32
	dataType uint32
}

type fwpmLayer0 struct {
	layerKey           wfpGUID
	displayData        fwpmDisplayData0
	flags              uint32
	numFields          uint32
	field              *fwpmField0
	defaultSubLayerKey wfpGUID
	layerID            uint16
}

func elevatedOrSkip(t *testing.T) *engine {
	t.Helper()
	if !Elevated() {
		t.Skip("needs an elevated session: the filter engine refuses an ordinary user")
	}
	e, err := openEngine(true, "whisper enforce test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.close)
	return e
}

// The layer and condition keys are typed in by hand from the SDK. A wrong one would make the
// filter add fail (the run then refuses to start, closed), but a key that names the WRONG layer
// would be worse, so each is checked against the engine's own schema: the layer's name, and
// that it carries every condition this code puts on it with the data type the code writes.
func TestWFPKeysNameWhatTheyClaim(t *testing.T) {
	e := elevatedOrSkip(t)
	const byteArray16 = 11
	// The user-id FIELD carries the caller's token access information; a condition on it is
	// written as a security descriptor, which the engine checks the token against.
	const tokenAccessInfo = 16
	cases := []struct {
		layer Layer
		name  string
		want  map[wfpGUID]uint32
	}{
		{LayerConnectV4, "ale connect v4 layer", map[wfpGUID]uint32{guidCondUserID: tokenAccessInfo,
			guidCondProtocol: fwpUint8, guidCondRemoteAddr: fwpUint32, guidCondRemotePort: fwpUint16, guidCondLocalPort: fwpUint16}},
		{LayerConnectV6, "ale connect v6 layer", map[wfpGUID]uint32{guidCondUserID: tokenAccessInfo,
			guidCondProtocol: fwpUint8, guidCondRemoteAddr: byteArray16, guidCondRemotePort: fwpUint16, guidCondLocalPort: fwpUint16}},
		{LayerRecvAcceptV4, "ale receive/accept v4 layer", map[wfpGUID]uint32{guidCondUserID: tokenAccessInfo}},
		{LayerRecvAcceptV6, "ale receive/accept v6 layer", map[wfpGUID]uint32{guidCondUserID: tokenAccessInfo}},
	}
	for _, c := range cases {
		key, _ := c.layer.key()
		var lp *fwpmLayer0
		if err := wfpCall("FwpmLayerGetByKey0", procFwpmLayerGetByKey0, uintptr(e.h), uintptr(unsafe.Pointer(&key)),
			uintptr(unsafe.Pointer(&lp))); err != nil {
			t.Fatalf("%v (%s): the engine has no such layer: %v", c.layer, key, err)
		}
		name := strings.ToLower(windows.UTF16PtrToString(lp.displayData.name))
		got := map[wfpGUID]uint32{}
		for _, f := range unsafe.Slice(lp.field, lp.numFields) {
			got[*f.fieldKey] = f.dataType
		}
		freeWFP(unsafe.Pointer(&lp))
		if name != c.name {
			t.Errorf("%v: the engine calls %s %q", c.layer, key, name)
		}
		for k, dt := range c.want {
			if have, ok := got[k]; !ok || have != dt {
				t.Errorf("%v (%q): field %s has data type %d (present %v), the code writes %d", c.layer, name, k, have, ok, dt)
			}
		}
	}
}

// A filter added for a run that is gone is swept by the next run, and the engine plumbing
// (add in a transaction, ask for it by id, enumerate under the provider, delete) works end to
// end. The filters name a SID no process carries, so nothing on the host is refused meanwhile.
func TestFiltersOfAGoneRunAreSwept(t *testing.T) {
	static := elevatedOrSkip(t)
	if err := static.ensureProviderAndSublayer(); err != nil {
		t.Fatal(err)
	}
	sds, err := securityDescriptors("S-1-5-5-0-4242424242")
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := AgentPlan(1)
	gone := RunTag{PID: 0xFFFFFFF0, Created: 1}.String() // no such pid
	var ids []uint64
	if err := static.inTxn(func() error {
		for _, s := range plan {
			w, berr := buildFilter(s, sds, gone)
			if berr != nil {
				return berr
			}
			id, aerr := static.addFilter(w)
			if aerr != nil {
				return aerr
			}
			ids = append(ids, id)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if err := static.filterPresent(id); err != nil {
			t.Fatalf("filter %d not present after the add: %v", id, err)
		}
	}
	// A live run's filter (this test process) is kept by the same sweep.
	live, err := selfTag()
	if err != nil {
		t.Fatal(err)
	}
	w, _ := buildFilter(plan[1], sds, live.String())
	liveID, err := static.addFilter(w)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = static.deleteFilter(liveID) })

	n, err := sweepStale(static)
	if err != nil {
		t.Fatal(err)
	}
	if n < len(ids) {
		t.Fatalf("swept %d, want at least %d", n, len(ids))
	}
	for _, id := range ids {
		if static.filterPresent(id) == nil {
			t.Fatalf("filter %d of a gone run survived the sweep", id)
		}
	}
	if err := static.filterPresent(liveID); err != nil {
		t.Fatalf("the sweep removed a live run's filter: %v", err)
	}
	if err := static.deleteFilter(liveID); err != nil {
		t.Fatal(err)
	}
	if err := static.deleteFilter(liveID); err != nil {
		t.Fatalf("deleting a filter that is already gone must not be an error: %v", err)
	}
}

func TestTheAgentTokenIsDeElevatedWithAFreshLogonSID(t *testing.T) {
	elevatedOrSkip(t)
	a, err := newAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	mine, err := tokenLogonSID(windows.GetCurrentProcessToken())
	if err != nil {
		t.Fatal(err)
	}
	if a.logonSID == mine || !strings.HasPrefix(a.logonSID, "S-1-5-5-") {
		t.Fatalf("the agent's logon SID %q must be a new one (this process has %q)", a.logonSID, mine)
	}
	if a.tok.IsElevated() {
		t.Fatal("the agent's token is elevated")
	}
	lt, err := logonType(a.tok)
	if err != nil || lt != logon32LogonNewCredentials {
		t.Fatalf("logon type %d, %v", lt, err)
	}
	groups, err := a.tok.GetTokenGroups()
	if err != nil {
		t.Fatal(err)
	}
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	for _, g := range groups.AllGroups() {
		if g.Sid.Equals(admins) && g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			t.Fatal("Administrators is still usable in the agent's token")
		}
	}
}

func TestRunAliveReadsPidAndStartTime(t *testing.T) {
	me, err := selfTag()
	if err != nil {
		t.Fatal(err)
	}
	if !runAlive(me) {
		t.Fatal("this process reads as gone")
	}
	if runAlive(RunTag{PID: me.PID, Created: me.Created + 1}) {
		t.Fatal("a recycled pid (another start time) reads as the same run")
	}
	if runAlive(RunTag{PID: 0xFFFFFFF0, Created: 1}) {
		t.Fatal("a pid that does not exist reads as alive")
	}
}

// The run's two fail-closed paths, end to end through RunWindows with a real agent process: a
// filter deleted from under a running agent stops it within a few watch ticks, and an agent
// that exits on its own leaves no filter behind. The agent is a sleeping PowerShell, so the
// test needs no network and no proxy; port 1 is the "door".
func TestTheWatchStopsTheAgentWhenAFilterVanishes(t *testing.T) {
	elevatedOrSkip(t)
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("no powershell.exe")
	}
	self, _ := selfTag()
	var deleted atomic.Bool
	start := time.Now()
	res, err := RunWindows(WindowsSpec{Path: ps, Args: []string{"powershell", "-NoProfile", "-Command", "Start-Sleep 60"},
		Env: os.Environ(), ProxyPort: 1}, func() {
		go func() {
			time.Sleep(2 * time.Second)
			e, oerr := openEngine(false, "whisper enforce test (saboteur)")
			if oerr != nil {
				return
			}
			defer e.close()
			fs, _ := e.providerFilters(LayerConnectV6)
			for _, f := range fs {
				if f.desc == self.String() && e.deleteFilter(f.id) == nil {
					deleted.Store(true)
					return
				}
			}
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	if !deleted.Load() {
		t.Fatal("the test could not find the run's own IPv6 block to delete")
	}
	if res.Killed == "" || res.Code != exitFilterLost {
		t.Fatalf("the agent was not stopped when its filter vanished: %+v", res)
	}
	if took := time.Since(start); took > 15*time.Second {
		t.Fatalf("stopping took %v; the watch runs every %v", took, watchInterval)
	}
	assertNoFiltersOf(t, self)
}

func TestAnAgentThatExitsLeavesNoFilterBehind(t *testing.T) {
	elevatedOrSkip(t)
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("no powershell.exe")
	}
	self, _ := selfTag()
	res, err := RunWindows(WindowsSpec{Path: ps, Args: []string{"powershell", "-NoProfile", "-Command", "exit 7"},
		Env: os.Environ(), ProxyPort: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Code != 7 || res.Killed != "" {
		t.Fatalf("the agent's own exit code must come back: %+v", res)
	}
	assertNoFiltersOf(t, self)
}

func assertNoFiltersOf(t *testing.T, tag RunTag) {
	t.Helper()
	e, err := openEngine(false, "whisper enforce test (check)")
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	for _, l := range allLayers {
		fs, err := e.providerFilters(l)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			if f.desc == tag.String() {
				t.Fatalf("filter %d of the ended run is still in the engine on %v", f.id, l)
			}
		}
	}
}
