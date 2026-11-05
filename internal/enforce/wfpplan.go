// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// wfpplan.go is the Windows enforcement written down as data: which filters exist, on which
// layers, with which conditions and weights. The Windows code only translates this
// plan into FWPM structures, so the plan itself is tested on every platform and the part that
// could be wrong in a way no compiler sees is the part that is tested most.

// Layer names the ALE layer a filter sits on.
type Layer int

const (
	LayerConnectV4 Layer = iota + 1
	LayerConnectV6
	LayerRecvAcceptV4
	LayerRecvAcceptV6
)

func (l Layer) String() string {
	switch l {
	case LayerConnectV4:
		return "ALE_AUTH_CONNECT_V4"
	case LayerConnectV6:
		return "ALE_AUTH_CONNECT_V6"
	case LayerRecvAcceptV4:
		return "ALE_AUTH_RECV_ACCEPT_V4"
	case LayerRecvAcceptV6:
		return "ALE_AUTH_RECV_ACCEPT_V6"
	}
	return "layer(" + strconv.Itoa(int(l)) + ")"
}

// Who says whose traffic a filter matches: the agent's logon SID, or SYSTEM (the identity
// Windows gives an echo sent through the ICMP API, whoever asked for it).
type Who int

const (
	WhoAgent Who = iota + 1
	WhoSystem
)

// FilterSpec is one WFP filter. Every filter matches Who; the other conditions are optional
// and zero means "no condition".
type FilterSpec struct {
	Name   string
	Layer  Layer
	Permit bool // false: a hard block (FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT)
	Weight uint8
	Who    Who
	// Proto is the IP protocol number (6 TCP, 1 ICMP, 58 ICMPv6).
	Proto uint8
	// RemoteV4Loopback is 127.0.0.1 exactly, as the remote address.
	RemoteV4Loopback bool
	RemotePort       uint16
	// ICMPType is matched when HasICMPType; WFP carries it in the local-port field.
	ICMPType    uint8
	HasICMPType bool
}

// Weights inside the CLI's sublayer: the permit outranks the blocks.
const (
	weightPermit uint8 = 15
	weightBlock  uint8 = 0
)

// AgentPlan is the per-run filter set for the agent's logon SID: TCP to the proxy on
// 127.0.0.1:proxyPort is the one thing permitted, and every connect and accept on both
// families is otherwise refused.
func AgentPlan(proxyPort uint16) ([]FilterSpec, error) {
	if proxyPort == 0 {
		return nil, errors.New("enforce: the egress proxy has no port, so there is no door to permit")
	}
	plan := []FilterSpec{{
		Name: "permit the agent's proxy", Layer: LayerConnectV4, Permit: true, Weight: weightPermit,
		Who: WhoAgent, Proto: 6, RemoteV4Loopback: true, RemotePort: proxyPort,
	}}
	for _, l := range []Layer{LayerConnectV4, LayerConnectV6, LayerRecvAcceptV4, LayerRecvAcceptV6} {
		plan = append(plan, FilterSpec{Name: "refuse the agent (" + l.String() + ")", Layer: l,
			Weight: weightBlock, Who: WhoAgent})
	}
	return plan, nil
}

// HostICMPPlan refuses ICMP echo requests sent by SYSTEM: the Windows ICMP API sends every
// caller's echo as the System process, so this is the only filter that can stop the agent's
// ping, and it stops everyone's for the run, which is the price the design accepted.
func HostICMPPlan() []FilterSpec {
	return []FilterSpec{
		{Name: "refuse ICMP API echo (IPv4) while an agent is enforced", Layer: LayerConnectV4,
			Weight: weightBlock, Who: WhoSystem, Proto: 1, ICMPType: 8, HasICMPType: true},
		{Name: "refuse ICMP API echo (IPv6) while an agent is enforced", Layer: LayerConnectV6,
			Weight: weightBlock, Who: WhoSystem, Proto: 58, ICMPType: 128, HasICMPType: true},
	}
}

// RunTag is written into every per-run filter's description, so a later run can tell a
// filter whose run is gone (safe to delete) from one whose run is alive (never touched).
type RunTag struct {
	PID     uint32
	Created uint64 // the CLI process's creation time (FILETIME), so a reused pid is not alive
}

const runTagPrefix = "whisper-enforce "

func (t RunTag) String() string {
	return fmt.Sprintf("%spid=%d created=%d", runTagPrefix, t.PID, t.Created)
}

// ParseRunTag reads a description written by RunTag.String. Anything else is not ours.
func ParseRunTag(desc string) (RunTag, bool) {
	rest, ok := strings.CutPrefix(desc, runTagPrefix)
	if !ok {
		return RunTag{}, false
	}
	var t RunTag
	var seen int
	for _, f := range strings.Fields(rest) {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			return RunTag{}, false
		}
		switch k {
		case "pid":
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil || n == 0 {
				return RunTag{}, false
			}
			t.PID, seen = uint32(n), seen|1
		case "created":
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return RunTag{}, false
			}
			t.Created, seen = n, seen|2
		default:
			return RunTag{}, false
		}
	}
	return t, seen == 3
}
