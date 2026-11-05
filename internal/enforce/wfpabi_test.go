// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"strings"
	"testing"
	"unsafe"
)

// The offsets below were measured on Windows Server 2022 from a program built
// against the Windows headers (sizeof/offsetof). Every Windows target the CLI ships is
// 64-bit, so the Go layout is checked on any 64-bit host.
func TestWFPStructsMatchTheMeasuredCLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("the Windows targets are 64-bit; this host is not")
	}
	type off struct {
		what      string
		got, want uintptr
	}
	var f fwpmFilter0
	var c fwpmFilterCondition0
	var sl fwpmSublayer0
	var p fwpmProvider0
	var s fwpmSession0
	var e fwpmFilterEnumTemplate0
	for _, o := range []off{
		{"FWPM_FILTER0", unsafe.Sizeof(f), 200},
		{"FWPM_FILTER0.flags", unsafe.Offsetof(f.flags), 32},
		{"FWPM_FILTER0.providerKey", unsafe.Offsetof(f.providerKey), 40},
		{"FWPM_FILTER0.providerData", unsafe.Offsetof(f.providerData), 48},
		{"FWPM_FILTER0.layerKey", unsafe.Offsetof(f.layerKey), 64},
		{"FWPM_FILTER0.subLayerKey", unsafe.Offsetof(f.subLayerKey), 80},
		{"FWPM_FILTER0.weight", unsafe.Offsetof(f.weight), 96},
		{"FWPM_FILTER0.numFilterConditions", unsafe.Offsetof(f.numFilterConditions), 112},
		{"FWPM_FILTER0.filterCondition", unsafe.Offsetof(f.filterCondition), 120},
		{"FWPM_FILTER0.action", unsafe.Offsetof(f.action), 128},
		{"FWPM_FILTER0.rawContext", unsafe.Offsetof(f.providerContextKey), 152},
		{"FWPM_FILTER0.reserved", unsafe.Offsetof(f.reserved), 168},
		{"FWPM_FILTER0.filterId", unsafe.Offsetof(f.filterID), 176},
		{"FWPM_FILTER0.effectiveWeight", unsafe.Offsetof(f.effectiveWeight), 184},
		{"FWPM_FILTER_CONDITION0", unsafe.Sizeof(c), 40},
		{"FWPM_FILTER_CONDITION0.matchType", unsafe.Offsetof(c.matchType), 16},
		{"FWPM_FILTER_CONDITION0.conditionValue", unsafe.Offsetof(c.condValue), 24},
		{"FWP_VALUE0", unsafe.Sizeof(fwpValue0{}), 16},
		{"FWPM_ACTION0", unsafe.Sizeof(fwpmAction0{}), 20},
		{"FWP_BYTE_BLOB", unsafe.Sizeof(fwpByteBlob{}), 16},
		{"FWPM_DISPLAY_DATA0", unsafe.Sizeof(fwpmDisplayData0{}), 16},
		{"FWPM_SUBLAYER0", unsafe.Sizeof(sl), 72},
		{"FWPM_SUBLAYER0.flags", unsafe.Offsetof(sl.flags), 32},
		{"FWPM_SUBLAYER0.providerKey", unsafe.Offsetof(sl.providerKey), 40},
		{"FWPM_SUBLAYER0.providerData", unsafe.Offsetof(sl.providerData), 48},
		{"FWPM_SUBLAYER0.weight", unsafe.Offsetof(sl.weight), 64},
		{"FWPM_PROVIDER0", unsafe.Sizeof(p), 64},
		{"FWPM_PROVIDER0.flags", unsafe.Offsetof(p.flags), 32},
		{"FWPM_PROVIDER0.providerData", unsafe.Offsetof(p.providerData), 40},
		{"FWPM_PROVIDER0.serviceName", unsafe.Offsetof(p.serviceName), 56},
		{"FWPM_SESSION0", unsafe.Sizeof(s), 72},
		{"FWPM_SESSION0.flags", unsafe.Offsetof(s.flags), 32},
		{"FWPM_SESSION0.txnWaitTimeoutInMSec", unsafe.Offsetof(s.txnWaitTimeoutInMSec), 36},
		{"FWPM_SESSION0.processId", unsafe.Offsetof(s.processID), 40},
		{"FWPM_SESSION0.sid", unsafe.Offsetof(s.sid), 48},
		{"FWPM_SESSION0.username", unsafe.Offsetof(s.username), 56},
		{"FWPM_SESSION0.kernelMode", unsafe.Offsetof(s.kernelMode), 64},
		{"FWPM_FILTER_ENUM_TEMPLATE0", unsafe.Sizeof(e), 72},
		{"FWPM_FILTER_ENUM_TEMPLATE0.layerKey", unsafe.Offsetof(e.layerKey), 8},
		{"FWPM_FILTER_ENUM_TEMPLATE0.enumType", unsafe.Offsetof(e.enumType), 24},
		{"FWPM_FILTER_ENUM_TEMPLATE0.flags", unsafe.Offsetof(e.flags), 28},
		{"FWPM_FILTER_ENUM_TEMPLATE0.providerContextTemplate", unsafe.Offsetof(e.providerContextTemplate), 32},
		{"FWPM_FILTER_ENUM_TEMPLATE0.numFilterConditions", unsafe.Offsetof(e.numFilterConditions), 40},
		{"FWPM_FILTER_ENUM_TEMPLATE0.filterCondition", unsafe.Offsetof(e.filterCondition), 48},
		{"FWPM_FILTER_ENUM_TEMPLATE0.actionMask", unsafe.Offsetof(e.actionMask), 56},
		{"FWPM_FILTER_ENUM_TEMPLATE0.calloutKey", unsafe.Offsetof(e.calloutKey), 64},
	} {
		if o.got != o.want {
			t.Errorf("%s: Go puts it at %d, the Windows headers at %d", o.what, o.got, o.want)
		}
	}
}

func TestGUIDsRoundTripAndRejectGarbage(t *testing.T) {
	for _, s := range []string{
		"c38d57d1-05a7-4c33-904f-7fbceee60e82",
		"{af043a0a-b34d-4f86-979c-c90371af6e66}",
		"  0C1BA1AF-5765-453F-AF22-A8F791AC775B ",
	} {
		g, err := parseGUID(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		want := strings.ToLower(strings.Trim(strings.TrimSpace(s), "{}"))
		if g.String() != want {
			t.Fatalf("%q round-trips to %q", s, g.String())
		}
	}
	// The byte order Windows uses: Data1..Data3 little-endian in memory, Data4 as written.
	g := mustGUID("c38d57d1-05a7-4c33-904f-7fbceee60e82")
	if g.Data1 != 0xc38d57d1 || g.Data2 != 0x05a7 || g.Data3 != 0x4c33 || g.Data4 != [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82} {
		t.Fatalf("fields: %+v", g)
	}
	for _, bad := range []string{"", "c38d57d1", "c38d57d1-05a7-4c33-904f-7fbceee60e8", "zzzzzzzz-05a7-4c33-904f-7fbceee60e82",
		"c38d57d105a74c33904f7fbceee60e82", "c38d57d1-05a7-4c33-904f7-fbceee60e82"} {
		if _, err := parseGUID(bad); err == nil {
			t.Fatalf("%q parsed as a GUID", bad)
		}
	}
	if guidProvider == guidSublayer {
		t.Fatal("the provider and the sublayer share a key")
	}
}

func testSDs() SecurityDescriptors {
	return SecurityDescriptors{WhoAgent: []byte("agent-sd"), WhoSystem: []byte("system-sd")}
}

func condByKey(w *wfpFilter, key wfpGUID) (fwpmFilterCondition0, bool) {
	for _, c := range w.conds {
		if c.fieldKey == key {
			return c, true
		}
	}
	return fwpmFilterCondition0{}, false
}

func TestTheProxyPermitBecomesExactlyItsConditions(t *testing.T) {
	plan, err := AgentPlan(41234)
	if err != nil {
		t.Fatal(err)
	}
	w, err := buildFilter(plan[0], testSDs(), "whisper-enforce pid=7 created=9")
	if err != nil {
		t.Fatal(err)
	}
	if w.f.action.typ != fwpActionPermit || w.f.flags&fwpmFilterFlagClearActionRight != 0 {
		t.Fatalf("a permit must be a plain permit (action %#x, flags %#x)", w.f.action.typ, w.f.flags)
	}
	if w.f.layerKey != guidLayerConnectV4 || w.f.subLayerKey != guidSublayer || *w.f.providerKey != guidProvider {
		t.Fatalf("layer/sublayer/provider: %v %v %v", w.f.layerKey, w.f.subLayerKey, *w.f.providerKey)
	}
	if w.f.weight.typ != fwpUint8 || w.f.weight.value != uintptr(weightPermit) {
		t.Fatalf("weight %+v", w.f.weight)
	}
	if int(w.f.numFilterConditions) != len(w.conds) || len(w.conds) != 4 || w.f.filterCondition != &w.conds[0] {
		t.Fatalf("conditions: %d declared, %d built", w.f.numFilterConditions, len(w.conds))
	}
	want := map[wfpGUID]fwpValue0{
		guidCondProtocol:   {typ: fwpUint8, value: 6},
		guidCondRemoteAddr: {typ: fwpUint32, value: 0x7F000001},
		guidCondRemotePort: {typ: fwpUint16, value: 41234},
	}
	for k, v := range want {
		c, ok := condByKey(w, k)
		if !ok || c.condValue != v || c.matchType != fwpMatchEqual {
			t.Fatalf("condition %v: got %+v (present %v), want %+v", k, c, ok, v)
		}
	}
	u, ok := condByKey(w, guidCondUserID)
	if !ok || u.condValue.typ != fwpSecurityDescriptorType {
		t.Fatalf("the user condition must carry a security descriptor: %+v", u)
	}
	if u.condValue.value != uintptr(unsafe.Pointer(w.sd)) {
		t.Fatal("the user condition does not point at the filter's own descriptor")
	}
	if got := string(unsafe.Slice(w.sd.data, w.sd.size)); got != "agent-sd" {
		t.Fatalf("the permit matches %q, not the agent's descriptor", got)
	}
}

func TestEveryBlockIsHardAndMatchesOnlyItsIdentity(t *testing.T) {
	plan, _ := AgentPlan(1)
	plan = append(plan, HostICMPPlan()...)
	for _, spec := range plan[1:] {
		w, err := buildFilter(spec, testSDs(), "d")
		if err != nil {
			t.Fatalf("%s: %v", spec.Name, err)
		}
		if w.f.action.typ != fwpActionBlock || w.f.flags&fwpmFilterFlagClearActionRight == 0 {
			t.Fatalf("%s: a block must clear the action right, or a lower sublayer's permit overrides it", spec.Name)
		}
		u, _ := condByKey(w, guidCondUserID)
		if u.condValue.value != uintptr(unsafe.Pointer(w.sd)) {
			t.Fatalf("%s: the user condition does not point at the filter's own descriptor", spec.Name)
		}
		want := map[Who]string{WhoAgent: "agent-sd", WhoSystem: "system-sd"}[spec.Who]
		if got := string(unsafe.Slice(w.sd.data, w.sd.size)); got != want {
			t.Fatalf("%s matches %q, want %q", spec.Name, got, want)
		}
		if spec.Who == WhoAgent && len(w.conds) != 1 {
			t.Fatalf("%s: an agent block must carry only the identity, or something it does not name would pass", spec.Name)
		}
	}
}

func TestTheICMPBlocksCarryTheTypeInTheLocalPortField(t *testing.T) {
	for _, spec := range HostICMPPlan() {
		w, err := buildFilter(spec, testSDs(), "d")
		if err != nil {
			t.Fatal(err)
		}
		c, ok := condByKey(w, guidCondLocalPort)
		if !ok || c.condValue != (fwpValue0{typ: fwpUint16, value: uintptr(spec.ICMPType)}) {
			t.Fatalf("%s: ICMP type condition %+v", spec.Name, c)
		}
		p, _ := condByKey(w, guidCondProtocol)
		if p.condValue.value != uintptr(spec.Proto) {
			t.Fatalf("%s: protocol %+v", spec.Name, p)
		}
	}
}

func TestBuildFilterRefusesWhatItCannotExpressExactly(t *testing.T) {
	cases := map[string]struct {
		spec FilterSpec
		sds  SecurityDescriptors
	}{
		"no layer":                {FilterSpec{Name: "x", Who: WhoAgent}, testSDs()},
		"unknown layer":           {FilterSpec{Name: "x", Layer: Layer(99), Who: WhoAgent}, testSDs()},
		"no descriptor":           {FilterSpec{Name: "x", Layer: LayerConnectV4, Who: WhoAgent}, SecurityDescriptors{}},
		"empty descriptor":        {FilterSpec{Name: "x", Layer: LayerConnectV4, Who: WhoAgent}, SecurityDescriptors{WhoAgent: {}}},
		"no identity at all":      {FilterSpec{Name: "x", Layer: LayerConnectV4}, testSDs()},
		"v4 loopback on v6 layer": {FilterSpec{Name: "x", Layer: LayerConnectV6, Who: WhoAgent, RemoteV4Loopback: true}, testSDs()},
		"ICMP type without ICMP":  {FilterSpec{Name: "x", Layer: LayerConnectV4, Who: WhoSystem, Proto: 6, HasICMPType: true}, testSDs()},
	}
	for name, c := range cases {
		if _, err := buildFilter(c.spec, c.sds, "d"); err == nil {
			t.Errorf("%s: built a filter that does not say what the plan says", name)
		}
	}
}

func TestMatchSDDLGrantsOneSIDAndRefusesInjection(t *testing.T) {
	got, err := MatchSDDL("S-1-5-5-0-95343587")
	if err != nil || got != "O:SYG:SYD:(A;;CC;;;S-1-5-5-0-95343587)" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", "SY", "S-1-5-18)(A;;CC;;;WD", "S-1-5-5-0-1;x", "S-1-5 18", "WD"} {
		if _, err := MatchSDDL(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestUTF16zEncodesAndTerminates(t *testing.T) {
	if got := utf16z("ab"); len(got) != 3 || got[0] != 'a' || got[2] != 0 {
		t.Fatalf("%v", got)
	}
	if got := utf16z("a\x00b"); len(got) != 2 || got[1] != 0 {
		t.Fatalf("an embedded NUL must end the string: %v", got)
	}
	if got := utf16z("\U0001F600"); len(got) != 3 || got[0] != 0xD83D || got[1] != 0xDE00 {
		t.Fatalf("surrogates: %x", got)
	}
}
