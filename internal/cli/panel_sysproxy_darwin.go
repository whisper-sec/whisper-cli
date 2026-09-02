// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build darwin

package cli

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// panel_sysproxy_darwin.go reads and writes the one setting that makes Safari, Chrome, Mail and
// every other windowed app on a Mac use the Whisper egress: the per-service SOCKS proxy in the
// system network settings.
//
// Nothing here is clever. `networksetup` is the supported, no-GUI way to read and set it, the
// same tool `whisper resolver` already drives for DNS on macOS. The care goes into three places:
//
// 1. Naming the service we act on. A Mac has several (Wi-Fi, Thunderbolt Bridge, an iPhone USB
// tether, half a dozen VPN entries), and setting the proxy on the wrong one changes nothing
// while reporting success. We find the interface the default route actually uses and map it
// back to its service name, and we report the name we used so a reader can check us.
// 2. Refusing to call a stale setting "on". See systemProxyPointsAtWhisper: enabled, loopback,
// and a port nothing is serving is the state that silently breaks every browser on the
// machine, and it must not read as working egress.
// 3. Ending a privilege refusal with the command that gets through it, never a raw exit status.
//
// The command surface stays in panel.go: this file declares no newXxxCmd, so the top-level
// command set is identical on every platform (the premise command_surface_test.go pins).

// systemProxySupported is the single declaration of whether this build can read and write the
// system proxy here. readSystemProxy reports it rather than hardcoding `true` a second time, and
// the command consults it before asking anybody to connect first.
const systemProxySupported = true

// sysProxyCmdTimeout bounds every shell-out. networksetup talks to configd, and a wedged configd
// would otherwise hang a panel poll forever. A var so a test can shorten it.
var sysProxyCmdTimeout = 10 * time.Second

// networksetupPath and routePath are absolute on purpose: this writes system network settings,
// and resolving the binary through $PATH would let anything earlier on the path do it for us.
const (
	networksetupPath = "/usr/sbin/networksetup"
	routePath        = "/sbin/route"
)

// runSysProxyCmd is the single seam every shell-out goes through, so the parsing below can be
// driven through all of its branches from a test without a Mac in the loop. Output and error are
// returned together because networksetup reports its refusals on stdout with a zero exit as
// often as not, so the caller has to be able to read both.
var runSysProxyCmd = func(name string, args ...string) (string, error) {
	cx, cancel := context.WithTimeout(context.Background(), sysProxyCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(cx, name, args...).CombinedOutput()
	text := string(out)
	if err != nil {
		return text, fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(text))
	}
	return text, nil
}

// readSystemProxy reports the SOCKS proxy the primary network service is configured with, and
// whether it points at a Whisper session that is serving RIGHT NOW.
func readSystemProxy(livePorts []int) (systemProxyState, error) {
	svc, err := primaryNetworkService()
	if err != nil {
		return systemProxyState{Supported: systemProxySupported}, err
	}
	st := systemProxyState{Supported: systemProxySupported, Service: svc}
	out, err := runSysProxyCmd(networksetupPath, "-getsocksfirewallproxy", svc)
	if err != nil {
		return st, err
	}
	st.Enabled, st.Host, st.Port = parseSocksFirewallProxy(out)
	st.PointsAtWhisper = systemProxyPointsAtWhisper(st.Host, st.Port, livePorts)
	return st, nil
}

// writeSystemProxy points the primary service's SOCKS proxy at the live local session, or turns
// it off. The caller has already established that port is one a live session is serving; this
// function will not invent one.
func writeSystemProxy(on bool, port int) error {
	svc, err := primaryNetworkService()
	if err != nil {
		return &client.ProblemError{Status: 500, Detail: friendly(err)}
	}
	if on {
		if port <= 0 {
			return &client.ProblemError{Status: 400,
				Detail: "no local port to point the system proxy at - run `whisper connect` first"}
		}
		if _, err := runSysProxyCmd(networksetupPath, "-setsocksfirewallproxy", svc, "127.0.0.1", strconv.Itoa(port)); err != nil {
			return sysProxyWriteError(err, "on")
		}
		if _, err := runSysProxyCmd(networksetupPath, "-setsocksfirewallproxystate", svc, "on"); err != nil {
			return sysProxyWriteError(err, "on")
		}
		return nil
	}
	if _, err := runSysProxyCmd(networksetupPath, "-setsocksfirewallproxystate", svc, "off"); err != nil {
		return sysProxyWriteError(err, "off")
	}
	return nil
}

// restoreSystemProxy puts the system SOCKS proxy back to prev, EXACTLY as it was found, which is
// what makes the dead man and the reaper safe to run at all.
//
// "Back" is not "off". A Mac that was already behind a corporate SOCKS proxy and had Whisper
// switched on and then reverted must end up behind its corporate proxy again; leaving it with no
// proxy would put somebody off their company network with no idea why. So the recorded host and
// port are written back and the enabled flag is set to whatever it was - including the real macOS
// state of a proxy that is configured and switched off, which networksetup keeps as two separate
// facts and this restores as two separate facts.
//
// THE ORDER IS LOAD-BEARING, AND macOS IS THE REASON. `networksetup -setsocksfirewallproxy` does
// not only write the host and port: it switches the proxy ON as a side effect. Measured on a
// macOS host, on a service whose proxy was off:
//
//	networksetup -setsocksfirewallproxy Wi-Fi "" 0
//	networksetup -getsocksfirewallproxy Wi-Fi   ->  Enabled: Yes  Server:  Port: 0
//
// An enabled SOCKS proxy pointing at no server at all is a Mac with no internet for every app
// that reads the setting. So a restore to OFF switches the proxy off FIRST - from that instant
// the machine works, whatever happens next - then writes the configuration back, then switches it
// off again to undo what writing it did. A restore to ON has no such hazard: the configuration it
// writes is the one the person was already using, and enabling it is where we are going anyway.
//
// Writing the configuration back UNCONDITIONALLY is the other half of "exactly". The earlier
// version skipped it whenever the previous host was empty, which is the common case of a Mac that
// never had a proxy, and so left our own 127.0.0.1:<session port> sitting in the field switched
// off. That residue is real and it is already in the wild: this Mac carries one on a second
// service, `Enabled: No Server: 127.0.0.1 Port: 55312`, from a session long gone. It is a
// foot-gun we planted - flip that switch in System Settings months later and the machine comes up
// pointed at a dead port - and an empty host and port 0 clear the fields properly.
//
// An unknown previous state (Known:false, when the setting could not be read before the change)
// restores as off and writes nothing. That is the conservative answer: off is a working machine,
// and inventing a host and port to "restore" would be worse than the outage it is undoing.
func restoreSystemProxy(prev sysProxyPrevious) error {
	svc := strings.TrimSpace(prev.Service)
	if svc == "" {
		found, err := primaryNetworkService()
		if err != nil {
			return &client.ProblemError{Status: 500, Detail: friendly(err)}
		}
		svc = found
	}
	setState := func(state string) error {
		if _, err := runSysProxyCmd(networksetupPath, "-setsocksfirewallproxystate", svc, state); err != nil {
			return sysProxyWriteError(err, "off")
		}
		return nil
	}
	writeConfig := func() error {
		if _, err := runSysProxyCmd(networksetupPath, "-setsocksfirewallproxy", svc,
			strings.TrimSpace(prev.Host), strconv.Itoa(prev.Port)); err != nil {
			return sysProxyWriteError(err, "off")
		}
		return nil
	}
	if !prev.Known {
		return setState("off")
	}
	if prev.Enabled {
		if err := writeConfig(); err != nil {
			return err
		}
		return setState("on")
	}
	if err := setState("off"); err != nil {
		return err
	}
	if err := writeConfig(); err != nil {
		return err
	}
	return setState("off")
}

// sysProxyWriteError ends a refusal with the way through it. Changing the system network
// settings needs admin rights, and "exit status 1" is not something a person can act on.
func sysProxyWriteError(err error, verb string) error {
	if looksLikeSysProxyPrivilegeRefusal(err) {
		return &client.ProblemError{Status: 403,
			Detail: "macOS will not let this account change the system network settings - " +
				"run it with admin rights: sudo whisper panel system-proxy " + verb}
	}
	return &client.ProblemError{Status: 500,
		Detail: "could not change this Mac's system proxy: " + friendly(err)}
}

// looksLikeSysProxyPrivilegeRefusal spots networksetup's admin-rights refusals, which it words
// several different ways depending on the release.
func looksLikeSysProxyPrivilegeRefusal(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{"privileg", "permission", "not allowed", "must be run as root", "admin"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// parseSocksFirewallProxy reads `networksetup -getsocksfirewallproxy <service>`:
//
//	Enabled: Yes
//	Server: 127.0.0.1
//	Port: 54209
//	Authenticated Proxy Enabled: 0
//
// Keys are matched exactly after trimming, which is what keeps the last line from being read as
// the Enabled flag.
func parseSocksFirewallProxy(out string) (enabled bool, host string, port int) {
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "Enabled":
			enabled = strings.EqualFold(value, "yes")
		case "Server":
			host = value
		case "Port":
			port, _ = strconv.Atoi(value)
		}
	}
	return enabled, host, port
}

// primaryNetworkService names the network service this Mac is actually using, so the proxy is
// set where the traffic is. The default route's interface is the truthful answer; the first
// enabled service is the fallback for a host whose default route we could not read (a Mac on a
// v6-only network with an unusual routing table, say), which is better than refusing to act.
func primaryNetworkService() (string, error) {
	if iface := defaultRouteInterface(); iface != "" {
		if svc := networkServiceForInterface(iface); svc != "" {
			return svc, nil
		}
	}
	if svc := firstEnabledNetworkService(); svc != "" {
		return svc, nil
	}
	return "", fmt.Errorf("could not work out which network service this Mac is using")
}

// defaultRouteInterface parses `route -n get default` for `interface: en0`. Both address
// families are tried, because a v6-only host has no v4 default route to report and the v4 call
// simply fails there (liberal in what we accept, per the north star).
func defaultRouteInterface() string {
	for _, args := range [][]string{
		{"-n", "get", "default"},
		{"-n", "get", "-inet6", "default"},
	} {
		out, err := runSysProxyCmd(routePath, args...)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
			if ok && strings.EqualFold(strings.TrimSpace(key), "interface") {
				if iface := strings.TrimSpace(value); iface != "" {
					return iface
				}
			}
		}
	}
	return ""
}

// networkServiceForInterface maps a BSD interface name back to its service name by walking
// `networksetup -listnetworkserviceorder`, which pairs them:
//
//	(1) Wi-Fi
//	(Hardware Port: Wi-Fi, Device: en0)
//
// The service name is the line above the hardware-port line, so we remember the last name seen
// and return it when the device matches.
func networkServiceForInterface(iface string) string {
	out, err := runSysProxyCmd(networksetupPath, "-listnetworkserviceorder")
	if err != nil {
		return ""
	}
	name := ""
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "(Hardware Port:") {
			if _, dev, ok := strings.Cut(line, "Device:"); ok {
				if strings.EqualFold(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(dev), ")")), iface) && name != "" {
					return name
				}
			}
			continue
		}
		if n, ok := serviceOrderName(line); ok {
			name = n
		}
	}
	return ""
}

// serviceOrderName pulls "Wi-Fi" out of "(1) Wi-Fi". The header line and blank lines carry no
// parenthesised index and are skipped.
func serviceOrderName(line string) (string, bool) {
	if !strings.HasPrefix(line, "(") {
		return "", false
	}
	close := strings.IndexByte(line, ')')
	if close < 0 {
		return "", false
	}
	name := strings.TrimSpace(line[close+1:])
	if name == "" {
		return "", false
	}
	return name, true
}

// firstEnabledNetworkService returns the first service `networksetup -listallnetworkservices`
// reports as enabled. Its first line is a legend, and a disabled service is prefixed with an
// asterisk; both are skipped.
func firstEnabledNetworkService() string {
	out, err := runSysProxyCmd(networksetupPath, "-listallnetworkservices")
	if err != nil {
		return ""
	}
	for i, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if i == 0 || line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		return line
	}
	return ""
}
