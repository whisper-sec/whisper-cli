// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"encoding/hex"
	"errors"
	"strings"
	"unsafe"
)

// wfpabi.go is the Windows Filtering Platform's C ABI, written as Go structs so the layout and
// the translation of a FilterSpec into a FWPM_FILTER0 are tested on every 64-bit platform, not
// only on Windows. The offsets are pinned in wfpabi_test.go against values measured from the
// Windows SDK headers on Windows Server 2022, so a field that drifts is
// a red test here, not a filter the kernel silently reads wrong.
//
// Integers in a FWP_VALUE0 union sit in its low bytes, which is where a uintptr puts them on a
// little-endian machine, and every Windows target the CLI ships is little-endian (amd64, arm64).

// wfpGUID is a Windows GUID, laid out as the C struct.
type wfpGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// parseGUID reads the canonical 8-4-4-4-12 spelling, braces optional.
func parseGUID(s string) (wfpGUID, error) {
	s = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "{"), "}")
	parts := strings.Split(s, "-")
	if len(parts) != 5 || len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 ||
		len(parts[3]) != 4 || len(parts[4]) != 12 {
		return wfpGUID{}, errors.New("enforce: not a GUID: " + s)
	}
	b, err := hex.DecodeString(strings.Join(parts, ""))
	if err != nil {
		return wfpGUID{}, errors.New("enforce: not a GUID: " + s)
	}
	var g wfpGUID
	g.Data1 = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	g.Data2 = uint16(b[4])<<8 | uint16(b[5])
	g.Data3 = uint16(b[6])<<8 | uint16(b[7])
	copy(g.Data4[:], b[8:])
	return g, nil
}

func mustGUID(s string) wfpGUID {
	g, err := parseGUID(s)
	if err != nil {
		panic(err)
	}
	return g
}

func (g wfpGUID) String() string {
	var b [16]byte
	b[0], b[1], b[2], b[3] = byte(g.Data1>>24), byte(g.Data1>>16), byte(g.Data1>>8), byte(g.Data1)
	b[4], b[5] = byte(g.Data2>>8), byte(g.Data2)
	b[6], b[7] = byte(g.Data3>>8), byte(g.Data3)
	copy(b[8:], g.Data4[:])
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// The well-known keys this code names. Each is checked against the running filter engine's own
// layer schema by TestWFPKeysNameWhatTheyClaim on Windows.
var (
	guidLayerConnectV4    = mustGUID("c38d57d1-05a7-4c33-904f-7fbceee60e82") // FWPM_LAYER_ALE_AUTH_CONNECT_V4
	guidLayerConnectV6    = mustGUID("4a72393b-319f-44bc-84c3-ba54dcb3b6b4") // FWPM_LAYER_ALE_AUTH_CONNECT_V6
	guidLayerRecvAcceptV4 = mustGUID("e1cd9fe7-f4b5-4273-96c0-592e487b8650") // FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
	guidLayerRecvAcceptV6 = mustGUID("a3b42c97-9f04-4672-b87e-cee9c483257f") // FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

	guidCondUserID     = mustGUID("af043a0a-b34d-4f86-979c-c90371af6e66") // FWPM_CONDITION_ALE_USER_ID
	guidCondProtocol   = mustGUID("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7") // FWPM_CONDITION_IP_PROTOCOL
	guidCondRemoteAddr = mustGUID("b235ae9a-1d64-49b8-a44c-5ff3d9095045") // FWPM_CONDITION_IP_REMOTE_ADDRESS
	guidCondRemotePort = mustGUID("c35a604d-d22b-4e1a-91b4-68f674ee674b") // FWPM_CONDITION_IP_REMOTE_PORT
	// FWPM_CONDITION_ICMP_TYPE is an alias of the local-port field: WFP carries an ICMP type there.
	guidCondLocalPort = mustGUID("0c1ba1af-5765-453f-af22-a8f791ac775b") // FWPM_CONDITION_IP_LOCAL_PORT

	// The CLI's own provider and sublayer. They are added non-persistent, so a reboot removes
	// them along with every filter under them.
	guidProvider = mustGUID("24666eb6-551a-4d8d-b18b-26f653920c60")
	guidSublayer = mustGUID("8c81506f-1436-4bb2-afd2-8d97ebcdf50a")
)

func (l Layer) key() (wfpGUID, bool) {
	switch l {
	case LayerConnectV4:
		return guidLayerConnectV4, true
	case LayerConnectV6:
		return guidLayerConnectV6, true
	case LayerRecvAcceptV4:
		return guidLayerRecvAcceptV4, true
	case LayerRecvAcceptV6:
		return guidLayerRecvAcceptV6, true
	}
	return wfpGUID{}, false
}

// allLayers is every layer a per-run filter can sit on, which is where a sweep looks.
var allLayers = []Layer{LayerConnectV4, LayerConnectV6, LayerRecvAcceptV4, LayerRecvAcceptV6}

// FWP_DATA_TYPE, FWP_MATCH_TYPE, FWP_ACTION_TYPE and the flag bits this code uses (fwptypes.h,
// fwpmtypes.h; values measured against the Windows SDK headers).
const (
	fwpEmpty                  = 0
	fwpUint8                  = 1
	fwpUint16                 = 2
	fwpUint32                 = 3
	fwpByteBlobType           = 12
	fwpSecurityDescriptorType = 14

	fwpMatchEqual = 0

	fwpActionBlock  = 0x1001
	fwpActionPermit = 0x1002

	fwpmFilterFlagClearActionRight = 0x8
	fwpmSessionFlagDynamic         = 0x1

	// sublayerWeight puts the CLI's sublayer above every other one, so its hard blocks are
	// evaluated with the most authority a user-mode sublayer can have.
	sublayerWeight = 0xFFFF
)

type fwpByteBlob struct {
	size uint32
	data *byte
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

// fwpValue0 is FWP_VALUE0 and FWP_CONDITION_VALUE0, which share a layout: a type tag and an
// eight-byte union. value holds an integer in place or the address of a blob the builder keeps
// alive (wfpFilter.keep).
type fwpValue0 struct {
	typ   uint32
	value uintptr
}

type fwpmFilterCondition0 struct {
	fieldKey  wfpGUID
	matchType uint32
	condValue fwpValue0
}

type fwpmAction0 struct {
	typ        uint32
	filterType wfpGUID
}

type fwpmFilter0 struct {
	filterKey           wfpGUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *wfpGUID
	providerData        fwpByteBlob
	layerKey            wfpGUID
	subLayerKey         wfpGUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	providerContextKey  [2]uint64 // the rawContext / providerContextKey union, 8-aligned
	reserved            *wfpGUID
	filterID            uint64
	effectiveWeight     fwpValue0
}

type fwpmSublayer0 struct {
	subLayerKey  wfpGUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *wfpGUID
	providerData fwpByteBlob
	weight       uint16
}

type fwpmProvider0 struct {
	providerKey  wfpGUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerData fwpByteBlob
	serviceName  *uint16
}

type fwpmSession0 struct {
	sessionKey           wfpGUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *byte
	username             *uint16
	kernelMode           int32
}

type fwpmFilterEnumTemplate0 struct {
	providerKey             *wfpGUID
	layerKey                wfpGUID
	enumType                uint32
	flags                   uint32
	providerContextTemplate uintptr
	numFilterConditions     uint32
	filterCondition         *fwpmFilterCondition0
	actionMask              uint32
	calloutKey              *wfpGUID
}

// utf16z is s as a NUL-terminated UTF-16 string. The strings this file writes are filter names
// and descriptions the CLI composes itself; a NUL inside one would only shorten it.
func utf16z(s string) []uint16 {
	out := make([]uint16, 0, len(s)+1)
	for _, r := range s {
		switch {
		case r == 0:
			return append(out, 0)
		case r >= 0x10000:
			r -= 0x10000
			out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
		default:
			out = append(out, uint16(r))
		}
	}
	return append(out, 0)
}

// wfpFilter is one FWPM_FILTER0 ready to hand to FwpmFilterAdd0, with everything it points at
// held in keep so the collector cannot free it before the call returns.
type wfpFilter struct {
	f     fwpmFilter0
	conds []fwpmFilterCondition0
	sd    *fwpByteBlob // the identity condition's descriptor
	keep  []any
}

// SecurityDescriptors maps each Who to the self-relative security descriptor that an
// ALE_USER_ID condition matches against: one granting FWP_ACTRL_MATCH_FILTER to that identity
// and to nobody else.
type SecurityDescriptors map[Who][]byte

// buildFilter translates spec into a FWPM_FILTER0 under the CLI's provider and sublayer, its
// description set to desc (a RunTag, so a later run can sweep it). It refuses a spec it cannot
// express exactly rather than add a filter that matches more, or less, than the plan says.
func buildFilter(spec FilterSpec, sds SecurityDescriptors, desc string) (*wfpFilter, error) {
	layer, ok := spec.Layer.key()
	if !ok {
		return nil, errors.New("enforce: filter " + spec.Name + " names no known layer")
	}
	sd := sds[spec.Who]
	if len(sd) == 0 {
		return nil, errors.New("enforce: filter " + spec.Name + " has no security descriptor for whose traffic it matches")
	}
	w := &wfpFilter{}
	name, d := utf16z(spec.Name), utf16z(desc)
	provider, sublayer := guidProvider, guidSublayer
	w.keep = append(w.keep, name, d, &provider)

	blob := &fwpByteBlob{size: uint32(len(sd)), data: &sd[0]}
	w.sd = blob
	w.keep = append(w.keep, sd, blob)
	w.conds = append(w.conds, fwpmFilterCondition0{fieldKey: guidCondUserID, matchType: fwpMatchEqual,
		condValue: fwpValue0{typ: fwpSecurityDescriptorType, value: uintptr(unsafe.Pointer(blob))}})
	if spec.Proto != 0 {
		w.conds = append(w.conds, fwpmFilterCondition0{fieldKey: guidCondProtocol, matchType: fwpMatchEqual,
			condValue: fwpValue0{typ: fwpUint8, value: uintptr(spec.Proto)}})
	}
	if spec.RemoteV4Loopback {
		if spec.Layer != LayerConnectV4 && spec.Layer != LayerRecvAcceptV4 {
			return nil, errors.New("enforce: filter " + spec.Name + " names 127.0.0.1 on an IPv6 layer")
		}
		// An IPv4 address is a FWP_UINT32 in host order.
		w.conds = append(w.conds, fwpmFilterCondition0{fieldKey: guidCondRemoteAddr, matchType: fwpMatchEqual,
			condValue: fwpValue0{typ: fwpUint32, value: 0x7F000001}})
	}
	if spec.RemotePort != 0 {
		w.conds = append(w.conds, fwpmFilterCondition0{fieldKey: guidCondRemotePort, matchType: fwpMatchEqual,
			condValue: fwpValue0{typ: fwpUint16, value: uintptr(spec.RemotePort)}})
	}
	if spec.HasICMPType {
		if spec.Proto != 1 && spec.Proto != 58 {
			return nil, errors.New("enforce: filter " + spec.Name + " matches an ICMP type without naming ICMP")
		}
		w.conds = append(w.conds, fwpmFilterCondition0{fieldKey: guidCondLocalPort, matchType: fwpMatchEqual,
			condValue: fwpValue0{typ: fwpUint16, value: uintptr(spec.ICMPType)}})
	}

	w.f = fwpmFilter0{
		displayData:         fwpmDisplayData0{name: &name[0], description: &d[0]},
		providerKey:         &provider,
		layerKey:            layer,
		subLayerKey:         sublayer,
		weight:              fwpValue0{typ: fwpUint8, value: uintptr(spec.Weight)},
		numFilterConditions: uint32(len(w.conds)),
		filterCondition:     &w.conds[0],
		action:              fwpmAction0{typ: fwpActionBlock},
	}
	if spec.Permit {
		w.f.action.typ = fwpActionPermit
	} else {
		// A hard block: no lower sublayer's permit can override it.
		w.f.flags |= fwpmFilterFlagClearActionRight
	}
	return w, nil
}

// MatchSDDL is the security descriptor, in SDDL, that an ALE_USER_ID condition uses to match the
// traffic of exactly one SID: it grants FWP_ACTRL_MATCH_FILTER (0x1, "CC" in SDDL) to that SID and
// to nobody else. SYSTEM owns it.
func MatchSDDL(sid string) (string, error) {
	sid = strings.TrimSpace(sid)
	if !strings.HasPrefix(sid, "S-1-") || strings.ContainsAny(sid, "();: \t") {
		return "", errors.New("enforce: not a SID: " + sid)
	}
	return "O:SYG:SYD:(A;;CC;;;" + sid + ")", nil
}
