// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	slashpath "path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

// networkd.go decides whether systemd-networkd would bring up, and pass off the host, a network device that a
// contained process could put in the host's namespace itself. It is the platform-independent half of that check,
// kept apart so it is tested on every platform; networkd_linux.go reads the host and asks the kernel.
//
// The way out it looks for: a kernel without the peer-namespace check (upstream commit 7b735ef81286, "rtnetlink: add
// missing netlink_ns_capable() check for peer netns") lets a process that is root only in a user namespace of its
// own create a veth pair whose far end lands in any network namespace it can name, by a pid or a descriptor, the
// host's included, with a name and a MAC address of its choosing. The far end arrives down, and on Linux 6.8 that
// process can neither bring it up (the peer's own IFF_UP at creation answers ENOTCONN, an ioctl through a socket of
// the host's namespace EPERM) nor enter the namespace. Something on the host has to bring it up, and
// systemd-networkd does so for any device whose properties satisfy a .network file's [Match]: its stock
// 80-container-ve.network matches "Kind=veth Name=ve-*" and brings such a device up, turns forwarding on, serves
// it DHCP and masquerades it (measured on Ubuntu 24.04 with systemd 255: a process with no capabilities at all,
// through a user namespace of its own, pinged off the host as the host's own address). A packet that leaves that
// way passes no program of the containment's cgroup.
//
// So the configuration is read the way networkd 255 reads it, and the question is answered exactly: is there a
// device a process could place (a kind, a MAC address, a name) whose first matching file, in networkd's own order,
// brings it up and passes what it sends on? Names are searched over every name the kernel accepts, by walking all the
// files' patterns at once; addresses over every address the files list plus one they do not.

// networkDirs are networkd's configuration directories, highest priority first: a file name found in one hides the
// same name in every later one.
var networkDirs = []string{
	"/etc/systemd/network",
	"/run/systemd/network",
	"/usr/local/lib/systemd/network",
	"/usr/lib/systemd/network",
	"/lib/systemd/network",
}

// netCond is a host condition of a .network file's [Match] (Host=, Virtualization=, ...): networkd skips a file
// whose conditions do not hold when it loads it.
type netCond struct {
	value  string
	negate bool
}

// networkFile is one .network file as networkd keeps it once its drop-ins are applied.
type networkFile struct {
	path    string   // the file networkd loads
	dropins []string // the drop-ins applied after it, in order
	version int      // the networkd release it is read for (networkdReader.version)

	// [Match]: each list as networkd stores it, a leading "!" on a word inverting that word.
	names, paths, drivers, types, kinds, props, wlanTypes, ssids []string
	hwAddrs, permAddrs, bssids                                   []string // lowercase, colon-separated
	conds                                                        map[string]netCond

	// [Link] and [Network], as far as they decide whether a matched device is brought up and passed on.
	unmanaged    bool
	activation   string // ActivationPolicy=, "" for the default
	bindCarrier  bool   // BindCarrier= is set, which forces ActivationPolicy=bound
	ipForward    string // IPForward= as written, "" when unset or no
	ipMasquerade string // IPMasquerade= as written, "" when unset or no
	v4Forwarding string // IPv4Forwarding= / IPv6Forwarding= (systemd 256), as written when true
	v6Forwarding string
	bridge       string // Bridge=, Bond=, VRF= or BatmanAdvanced=, as "Key=value"
}

// matchEmpty reports whether the file's [Match] names no property of a device, which with no host condition either
// makes networkd ignore the file.
func (f *networkFile) matchEmpty() bool {
	return len(f.names)+len(f.paths)+len(f.drivers)+len(f.types)+len(f.kinds)+len(f.props)+len(f.wlanTypes)+
		len(f.ssids)+len(f.hwAddrs)+len(f.permAddrs)+len(f.bssids) == 0
}

// up reports whether networkd brings a device the file matches up: it manages it and its activation policy is not
// one that leaves the device down. A process that placed the device cannot bring it up itself.
func (f *networkFile) up() bool {
	if f.unmanaged {
		return false
	}
	if f.bindCarrier {
		return true // bound: up while a link it is bound to has carrier, which is not the placing process's to stop
	}
	switch f.activation {
	case "manual", "down", "always-down":
		return false
	}
	return true
}

// passesOn says how the file sends what a matched device receives off the host by itself, or "": it masquerades
// it, turns forwarding on for it, or makes it a port of a bridge.
func (f *networkFile) passesOn() string {
	switch {
	case f.ipMasquerade != "":
		return "masquerade what it sends off the host (IPMasquerade=" + f.ipMasquerade + ")"
	case f.ipForward != "":
		return "forward what it sends (IPForward=" + f.ipForward + ")"
	case f.v4Forwarding != "":
		return "forward what it sends (IPv4Forwarding=" + f.v4Forwarding + ")"
	case f.v6Forwarding != "":
		return "forward what it sends (IPv6Forwarding=" + f.v6Forwarding + ")"
	case f.bridge != "":
		return "enslave it (" + f.bridge + "), which passes what it sends on at the link layer"
	}
	return ""
}

// forwards reports whether applying f turns forwarding on for the whole namespace: networkd sets the sysctls as it
// configures a managed link, before and whatever its activation policy.
func (f *networkFile) forwards() bool {
	return !f.unmanaged && (f.ipMasquerade != "" || f.ipForward != "" || f.v4Forwarding != "" || f.v6Forwarding != "")
}

// how says what networkd would do with a device f matches that lets what it sends leave, or "" for nothing. upIsEnough
// counts a device brought up as a way out by itself: in the host's own namespace, forwarding is turned on as a matter
// of course by Docker, libvirt, a container manager or networkd itself for another link, for the rest of the boot,
// so a device networkd keeps up there is one forwarding switch away from passing traffic on, and a containment lasts
// long enough for that switch to be thrown.
func (f *networkFile) how(fwd hostForwarding, upIsEnough bool) string {
	if !f.up() {
		return ""
	}
	if h := f.passesOn(); h != "" {
		return h
	}
	if fwd.v4 || fwd.v6 {
		return "forward what it sends, since " + fwd.String()
	}
	if upIsEnough {
		return "bring it up, after which it needs only forwarding, which much else turns on for the whole host, to " +
			"pass what it sends off the host"
	}
	return ""
}

// networkdReader is where the configuration is read from and who reads it: root ("" for the host itself) is put
// before every path, and access, when set, says whether networkd's own user may read (4) or search (1) a file or
// directory (it runs unprivileged, and ignores a file or directory it cannot open, as it says in its log).
type networkdReader struct {
	root   string
	access func(fi fs.FileInfo, want uint32) bool
	// version is the networkd release the files are read for (0: the newest this reading knows): a key it does not
	// know yet it ignores, as an unknown key.
	version int
}

// maxConfFile bounds what is read of one configuration file; a larger one cannot be judged.
const maxConfFile = 4 << 20

// readUnder and listUnder read a file and list a directory under a root, every symbolic link and ".." resolved inside
// that root, never opening anything but a regular file or a directory, and never waiting: a root can be a container
// tenant's, or a process's own, with a FIFO or a device where a file should be. readUnder gives nil data and a nil
// FileInfo for nothing there (a link that ends nowhere included), the FileInfo alone for something that is not a
// regular file, and an error for a file over maxConfFile. listUnder gives the names in a directory and the FileInfo
// of each directory on the way to it, from the root down, or fs.ErrNotExist. Linux replaces both with openat2
// (RESOLVE_IN_ROOT) versions (networkd_linux.go); these are for the tests on every platform.
var (
	readUnder = readUnderPortable
	listUnder = listUnderPortable
)

func readUnderPortable(root, path string) ([]byte, fs.FileInfo, error) {
	p := path
	for hops := 0; ; hops++ {
		fi, err := os.Lstat(filepath.Join(root, p))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				return nil, nil, nil
			}
			return nil, nil, err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			if !fi.Mode().IsRegular() {
				return nil, fi, nil
			}
			if fi.Size() > maxConfFile {
				return nil, fi, fmt.Errorf("%s is larger than %d bytes", path, maxConfFile)
			}
			b, err := os.ReadFile(filepath.Join(root, p))
			return b, fi, err
		}
		if hops >= 32 {
			return nil, nil, nil // ELOOP, which networkd cannot open either
		}
		t, err := os.Readlink(filepath.Join(root, p))
		if err != nil {
			return nil, nil, err
		}
		if t = filepath.ToSlash(t); slashpath.IsAbs(t) {
			p = t
		} else {
			p = slashpath.Join(slashpath.Dir(p), t)
		}
	}
}

func listUnderPortable(root, path string) ([]string, []fs.FileInfo, error) {
	var chain []fs.FileInfo
	cur := "/"
	for _, part := range append([]string{""}, strings.Split(strings.Trim(path, "/"), "/")...) {
		cur = slashpath.Join(cur, part)
		fi, err := os.Stat(filepath.Join(root, cur))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				return nil, nil, fs.ErrNotExist
			}
			return nil, nil, err
		}
		chain = append(chain, fi)
	}
	ents, err := os.ReadDir(filepath.Join(root, path))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return nil, nil, fs.ErrNotExist
		}
		return nil, nil, err
	}
	names := make([]string, len(ents))
	for i, e := range ents {
		names[i] = e.Name()
	}
	return names, chain, nil
}

// loadNetworkFiles reads every .network file networkd would load, in the order it tries them against a device. A
// masked, empty or unreadable file is left out, as is one networkd would refuse to parse or that matches nothing,
// and so is a file one of whose drop-ins it could not read or parse. An error is a directory or file this command
// cannot read, which leaves it nothing to judge by.
func loadNetworkFiles(r networkdReader) ([]networkFile, error) {
	winners, err := r.confFiles(networkDirs, ".network")
	if err != nil {
		return nil, err
	}
	var out []networkFile
	for _, w := range winners {
		data, state, err := r.read(w)
		if err != nil {
			return nil, err
		}
		if state != confRead {
			continue
		}
		f := networkFile{path: w, conds: map[string]netCond{}, version: r.version}
		if err := parseNetworkUnit(&f, data); err != nil {
			continue // networkd refuses the whole file
		}
		dirs := make([]string, len(networkDirs))
		for i, d := range networkDirs {
			dirs[i] = slashpath.Join(d, slashpath.Base(w)+".d")
		}
		dropins, err := r.confFiles(dirs, ".conf")
		if err != nil {
			return nil, err
		}
		bad := false
		for _, d := range dropins {
			data, state, err := r.read(d)
			if err != nil {
				return nil, err
			}
			switch state {
			case confUnreadable:
				bad = true // networkd skips an empty drop-in, but one it cannot open fails the file it belongs to
			case confRead:
				f.dropins = append(f.dropins, d)
				if parseNetworkUnit(&f, data) != nil {
					bad = true
				}
			}
		}
		if bad || (f.matchEmpty() && len(f.conds) == 0) {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// confFiles lists, for dirs in priority order, the files whose names end in suffix: the first directory holding a
// name wins it, and the winners are sorted by name, as systemd's conf_files_list does. A directory that does not
// exist holds nothing, and so does one networkd's own user cannot open.
func (r networkdReader) confFiles(dirs []string, suffix string) ([]string, error) {
	byName := map[string]string{}
	var names []string
	for _, d := range dirs {
		ents, chain, err := listUnder(r.root, d)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("cannot list %s: %w", quoteText(d), err)
		}
		if !r.canList(chain) {
			continue
		}
		for _, n := range ents {
			if !strings.HasSuffix(n, suffix) || n == suffix {
				continue
			}
			if _, ok := byName[n]; ok {
				continue
			}
			byName[n] = slashpath.Join(d, n)
			names = append(names, n)
		}
	}
	sort.Strings(names)
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = byName[n]
	}
	return out, nil
}

// canList reports whether networkd's own user can search every directory on the way and read the last.
func (r networkdReader) canList(chain []fs.FileInfo) bool {
	if r.access == nil {
		return true
	}
	for i, fi := range chain {
		want := uint32(1)
		if i == len(chain)-1 {
			want = 5
		}
		if !r.access(fi, want) {
			return false
		}
	}
	return true
}

// What reading one configuration file found.
const (
	confRead       = iota // read: data holds it
	confAbsent            // nothing there, a link to /dev/null or nowhere, or not a regular file: a mask
	confEmpty             // an empty file: a mask too
	confUnreadable        // networkd's own user cannot read it, so networkd skips it
)

// read reads one configuration file.
func (r networkdReader) read(path string) (string, int, error) {
	b, fi, err := readUnder(r.root, path)
	if err != nil {
		return "", 0, fmt.Errorf("cannot read %s: %w", quoteText(path), err)
	}
	switch {
	case fi == nil || !fi.Mode().IsRegular():
		return "", confAbsent, nil
	case len(b) == 0:
		return "", confEmpty, nil
	case r.access != nil && !r.access(fi, 4):
		return "", confUnreadable, nil
	}
	return string(b), confRead, nil
}

// quoteText makes a path or name read from a configuration safe to print: anything but printable ASCII is shown as
// \xNN, so a file name cannot carry a terminal's escape sequences into a refusal.
func quoteText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 32 && c < 127 && c != '\\' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "\\x%02x", c)
		}
	}
	return b.String()
}

// pasteable reports whether s can be put in a command to paste: printable ASCII only, so it carries nothing to the
// terminal it is printed on.
func pasteable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] >= 127 {
			return false
		}
	}
	return true
}

// shellWord quotes s as one word for a POSIX shell, so a name read from a configuration can be put in a command to
// paste and stay one argument whatever it holds.
func shellWord(s string) string {
	safe := s != ""
	for i := 0; i < len(s) && safe; i++ {
		c := s[i]
		safe = c == '/' || c == '.' || c == '-' || c == '_' || c == '+' || c == ',' || c == ':' || c == '@' || c == '=' ||
			(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// errBadSection is a section header networkd cannot parse, which makes it refuse the whole file.
var errBadSection = errors.New("invalid section header")

// parseNetworkUnit applies one file's assignments to f, as systemd's config_parse does: comment lines skipped, a
// line ending in an unescaped backslash continued, assignments outside [Match], [Link] and [Network] ignored.
func parseNetworkUnit(f *networkFile, data string) error {
	return parseUnit(data, f.assign)
}

// parseUnit calls assign for every assignment in a systemd configuration file, with the section it is in.
func parseUnit(data string, assign func(section, key, value string)) error {
	section := ""
	for _, l := range unitLines(data) {
		if len(l) > longLineMax {
			return errBadSection
		}
		l = strings.Trim(l, " \t\n\r")
		if l == "" {
			continue
		}
		if !utf8.ValidString(l) {
			return errBadSection // systemd refuses a file with a line that is not UTF-8
		}
		if l[0] == '[' {
			if !strings.HasSuffix(l, "]") || !safeSection(l[1:len(l)-1]) {
				return errBadSection
			}
			section = l[1 : len(l)-1]
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok || strings.Trim(k, " \t\n\r") == "" {
			continue
		}
		assign(section, strings.Trim(k, " \t\n\r"), strings.Trim(v, " \t\n\r"))
	}
	return nil
}

// longLineMax is systemd's LONG_LINE_MAX: a longer line fails the file.
const longLineMax = 1 << 20

// safeSection is systemd's string_is_safe for a section name: no control character, quote or backslash.
func safeSection(n string) bool {
	for i := 0; i < len(n); i++ {
		if c := n[i]; c < ' ' || c == 127 || c == '"' || c == '\'' || c == '\\' {
			return false
		}
	}
	return true
}

// unitLines joins continued lines and drops comment lines, as systemd's config_parse reads a file.
func unitLines(data string) []string {
	data = strings.TrimPrefix(data, "\ufeff")
	var out []string
	cont, inCont := "", false
	for _, raw := range strings.Split(data, "\n") {
		raw = strings.TrimSuffix(raw, "\r")
		if t := strings.TrimLeft(raw, " \t"); t != "" && (t[0] == '#' || t[0] == ';') {
			continue
		}
		p := raw
		if inCont {
			p = cont + raw
		}
		escaped := false
		for i := 0; i < len(p); i++ {
			if escaped {
				escaped = false
			} else if p[i] == '\\' {
				escaped = true
			}
		}
		if escaped {
			cont, inCont = p[:len(p)-1]+" ", true
			continue
		}
		out = append(out, p)
		cont, inCont = "", false
	}
	if inCont {
		out = append(out, cont)
	}
	return out
}

// sharedVersion is the one release named by libsystemd-shared-<release>.so in lines, or 0 for none or several.
func sharedVersion(lines []string) int {
	found := 0
	for _, l := range lines {
		i := strings.Index(l, "libsystemd-shared-")
		if i < 0 {
			continue
		}
		rest := l[i+len("libsystemd-shared-"):]
		n := 0
		for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
			n++
		}
		v, err := strconv.Atoi(rest[:n])
		if err != nil {
			continue
		}
		if found != 0 && found != v {
			return 0
		}
		found = v
	}
	return found
}

// keyAddedIn is the networkd release that first knows a key this reading uses, where that is later than the oldest
// release it is read for (systemd.network(5), "Added in version"): an older networkd ignores the key, which can make
// a file match more than it says, or leave a device up that it says is down.
var keyAddedIn = map[string]int{
	"Match.Kind": 251, "Match.PermanentMACAddress": 245, "Match.Property": 243, "Match.WLANInterfaceType": 244,
	"Match.SSID": 244, "Match.BSSID": 244, "Match.KernelVersion": 237, "Match.Credential": 252, "Match.Firmware": 249,
	"Link.ActivationPolicy": 248, "Link.Unmanaged": 233, "Network.BatmanAdvanced": 248,
	"Network.IPv4Forwarding": 256, "Network.IPv6Forwarding": 256,
}

// oldestNetworkd is the oldest networkd release a configuration is read for when the running one cannot be told.
const oldestNetworkd = 239

// assign applies one assignment, with networkd's parser for its key, unless the release it is read for does not know
// the key.
func (f *networkFile) assign(section, key, value string) {
	if v := keyAddedIn[section+"."+key]; v > 0 && f.version > 0 && f.version < v {
		return
	}
	switch section {
	case "Match":
		switch key {
		case "Name":
			f.names = matchWords(f.names, value, wordsPlain, ifnameValid)
		case "Path":
			f.paths = matchWords(f.paths, value, wordsUnquote, nil)
		case "Driver":
			f.drivers = matchWords(f.drivers, value, wordsUnquote, nil)
		case "Type":
			f.types = matchWords(f.types, value, wordsUnquote, nil)
		case "Kind":
			f.kinds = matchWords(f.kinds, value, wordsUnquote, nil)
		case "WLANInterfaceType":
			f.wlanTypes = matchWords(f.wlanTypes, value, wordsUnquote, nil)
		case "SSID":
			f.ssids = matchWords(f.ssids, value, wordsUnquote, nil)
		case "Property":
			f.props = matchWords(f.props, value, wordsCUnquote, propertyValid)
		case "MACAddress":
			f.hwAddrs = hwAddrList(f.hwAddrs, value)
		case "PermanentMACAddress":
			f.permAddrs = hwAddrList(f.permAddrs, value)
		case "BSSID":
			f.bssids = hwAddrList(f.bssids, value)
		case "Host", "Virtualization", "KernelCommandLine", "KernelVersion", "Credential", "Architecture", "Firmware":
			if value == "" {
				delete(f.conds, key)
			} else if v, neg := strings.CutPrefix(value, "!"); neg {
				f.conds[key] = netCond{value: v, negate: true}
			} else {
				f.conds[key] = netCond{value: value}
			}
		}
	case "Link":
		switch key {
		case "Unmanaged":
			if b, ok := parseSystemdBool(value); ok {
				f.unmanaged = b
			}
		case "ActivationPolicy":
			switch value {
			case "up", "always-up", "manual", "always-down", "down", "bound":
				f.activation = value
			}
		}
	case "Network":
		switch key {
		case "IPForward":
			// networkd 255: a boolean, ipv4 or ipv6; "kernel" is the old spelling of no; anything else is ignored.
			if b, ok := parseSystemdBool(value); ok {
				f.ipForward = map[bool]string{true: value, false: ""}[b]
			} else if value == "ipv4" || value == "ipv6" {
				f.ipForward = value
			} else if value == "kernel" {
				f.ipForward = ""
			}
		case "IPMasquerade":
			// Empty or false is no, true the deprecated spelling of ipv4; ipv4, ipv6 and both; anything else ignored.
			if value == "" {
				f.ipMasquerade = ""
			} else if b, ok := parseSystemdBool(value); ok {
				f.ipMasquerade = map[bool]string{true: value, false: ""}[b]
			} else if (value == "ipv4" || value == "ipv6" || value == "both") && (f.version == 0 || f.version >= 248) {
				f.ipMasquerade = value
			}
		case "IPv4Forwarding", "IPv6Forwarding":
			b, ok := parseSystemdBool(value)
			if !ok && value != "" {
				return // not a boolean: ignored
			}
			v := ""
			if b {
				v = value
			}
			if key == "IPv4Forwarding" {
				f.v4Forwarding = v
			} else {
				f.v6Forwarding = v
			}
		case "Bridge", "Bond", "VRF", "BatmanAdvanced":
			if value != "" {
				f.bridge = key + "=" + value
			} else if strings.HasPrefix(f.bridge, key+"=") {
				f.bridge = ""
			}
		case "BindCarrier":
			f.bindCarrier = value != ""
		}
	}
}

// parseSystemdBool reads a boolean as systemd's parse_boolean does.
func parseSystemdBool(s string) (bool, bool) {
	switch strings.ToLower(s) {
	case "1", "yes", "y", "true", "t", "on":
		return true, true
	case "0", "no", "n", "false", "f", "off":
		return false, true
	}
	return false, false
}

// matchWords applies one [Match] list assignment the way networkd's config_parse_match_strv (unquote, keeping
// backslashes for fnmatch), config_parse_match_ifnames (neither) or config_parse_match_property (unquote and C
// escapes) does: an empty value clears the list, a leading "!" inverts every word of the value, a word valid rejects
// is dropped with networkd's warning, and a word it cannot parse (an unclosed quote, a bad escape) ends the value,
// the words before it kept.
func matchWords(list []string, value string, mode wordMode, valid func(string) bool) []string {
	if value == "" {
		return nil
	}
	invert := strings.HasPrefix(value, "!")
	if invert {
		value = value[1:]
	}
	words, _ := splitWordsMode(value, mode)
	for _, w := range words {
		if valid != nil && !valid(w) {
			continue
		}
		if invert {
			w = "!" + w
		}
		list = append(list, w)
	}
	return list
}

// wordMode is how a value's words are read, as extract_first_word's flags say.
type wordMode int

const (
	wordsPlain    wordMode = iota // no flags: a backslash takes the next byte literally, quotes are ordinary
	wordsUnquote                  // EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE: quotes group and go, backslashes stay
	wordsCUnquote                 // EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE: quotes group and go, C escapes are decoded
)

// splitWords splits a value at whitespace, unquoting or not.
func splitWords(s string, unquote bool) []string {
	m := wordsPlain
	if unquote {
		m = wordsUnquote
	}
	w, _ := splitWordsMode(s, m)
	return w
}

// splitWordsMode splits a value at whitespace in mode, and reports false when it stopped at a word it could not
// parse, returning the words before it.
func splitWordsMode(s string, mode wordMode) ([]string, bool) {
	var out []string
	var w strings.Builder
	in, quote := false, byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && mode == wordsCUnquote:
			n, b, ok := cEscape(s[i+1:])
			if !ok {
				return out, false
			}
			w.WriteString(b)
			i += n
			in = true
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				w.WriteByte(c)
			}
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if in {
				out = append(out, w.String())
				w.Reset()
				in = false
			}
		case mode != wordsPlain && (c == '"' || c == '\''):
			quote, in = c, true
		case c == '\\' && i+1 < len(s):
			if mode == wordsUnquote {
				w.WriteByte(c)
			}
			i++
			w.WriteByte(s[i])
			in = true
		default:
			w.WriteByte(c)
			in = true
		}
	}
	if quote != 0 {
		return out, false // an unclosed quote: systemd refuses the word
	}
	if in {
		out = append(out, w.String())
	}
	return out, true
}

// cEscape decodes the C escape after a backslash at the start of s (systemd's cunescape_one), returning how many
// bytes it took and what it stands for.
func cEscape(s string) (int, string, bool) {
	simple := map[byte]string{'a': "\a", 'b': "\b", 'f': "\f", 'n': "\n", 'r': "\r", 't': "\t", 'v': "\v",
		'\\': "\\", '"': "\"", '\'': "'", 's': " "}
	if r, ok := simple[s[0]]; ok {
		return 1, r, true
	}
	switch {
	case s[0] == 'x' && len(s) >= 3:
		v, err := strconv.ParseUint(s[1:3], 16, 8)
		if err != nil || v == 0 {
			return 0, "", false
		}
		return 3, string([]byte{byte(v)}), true
	case s[0] >= '0' && s[0] <= '7' && len(s) >= 3:
		v, err := strconv.ParseUint(s[0:3], 8, 8)
		if err != nil || v == 0 {
			return 0, "", false
		}
		return 3, string([]byte{byte(v)}), true
	}
	return 0, "", false // \u, \U and anything else are not taken here
}

// ifnameValid is systemd's ifname_valid_full for a Name= word (IFNAME_VALID_ALTERNATIVE): networkd drops any other
// word, so a list whose only words are dropped matches every name.
func ifnameValid(w string) bool {
	if w == "" || len(w) >= 128 || w == "." || w == ".." || w == "all" || w == "default" {
		return false
	}
	numeric := true
	for i := 0; i < len(w); i++ {
		c := w[i]
		if c <= 32 || c >= 127 || c == ':' || c == '/' || c == '%' {
			return false
		}
		numeric = numeric && c >= '0' && c <= '9'
	}
	return !numeric
}

// propertyValid is systemd's env_assignment_is_valid for a Property= word: KEY=VALUE with a valid name.
func propertyValid(w string) bool {
	k, _, ok := strings.Cut(w, "=")
	if !ok || k == "" || (k[0] >= '0' && k[0] <= '9') {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// hwAddrList applies one MACAddress=, PermanentMACAddress= or BSSID= assignment: empty clears it, and each word
// that is a hardware address joins it (an invalid one is dropped).
func hwAddrList(list []string, value string) []string {
	if value == "" {
		return nil
	}
	for _, w := range strings.Fields(value) {
		if a, ok := parseHWAddr(w); ok {
			list = append(list, a)
		}
	}
	return list
}

// parseHWAddr reads a hardware address in the forms systemd accepts (aa:bb:..., aa-bb-..., aabb.ccdd.eeff) and
// returns it lowercase and colon-separated.
func parseHWAddr(s string) (string, bool) {
	var b []byte
	if strings.Count(s, ".") == 2 && !strings.ContainsAny(s, ":-") {
		h, err := hex.DecodeString(strings.ReplaceAll(s, ".", ""))
		if err != nil || len(h) != 6 {
			return "", false
		}
		b = h
	} else {
		sep := ":"
		if strings.Contains(s, "-") {
			sep = "-"
		}
		for _, p := range strings.Split(s, sep) {
			if len(p) == 0 || len(p) > 2 {
				return "", false
			}
			v, err := strconv.ParseUint(p, 16, 8)
			if err != nil {
				return "", false
			}
			b = append(b, byte(v))
		}
		if len(b) > 32 {
			return "", false
		}
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":"), true
}

// networkdConf is what networkd.conf says that this check reads: the global forwarding switches (systemd 256,
// [Network] IPv4Forwarding= and IPv6Forwarding=), which networkd applies when it starts, and whether it deletes the
// routing policy rules and routes it did not make (ManageForeignRoutingPolicyRules=, ManageForeignRoutes=, both on
// by default).
type networkdConf struct {
	fwd   hostForwarding
	keeps bool // both deletions turned off
}

// readNetworkdConf reads networkd.conf, the first main file found, then its drop-ins.
func readNetworkdConf(r networkdReader) (networkdConf, error) {
	var c networkdConf
	rules, routes := true, true
	assign := func(section, key, value string) {
		if section != "Network" {
			return
		}
		b, ok := parseSystemdBool(value)
		switch {
		case key == "IPv4Forwarding" && (ok || value == ""):
			c.fwd.v4 = b
		case key == "IPv6Forwarding" && (ok || value == ""):
			c.fwd.v6 = b
		case key == "ManageForeignRoutingPolicyRules" && ok:
			rules = b
		case key == "ManageForeignRoutes" && ok:
			routes = b
		}
	}
	for _, d := range networkDirs {
		data, state, err := r.read(slashpath.Join(slashpath.Dir(d), "networkd.conf"))
		if err != nil {
			return c, err
		}
		if state == confRead {
			_ = parseUnit(data, assign)
			break
		}
	}
	dirs := make([]string, len(networkDirs))
	for i, d := range networkDirs {
		dirs[i] = slashpath.Join(slashpath.Dir(d), "networkd.conf.d")
	}
	dropins, err := r.confFiles(dirs, ".conf")
	if err != nil {
		return c, err
	}
	for _, d := range dropins {
		data, state, err := r.read(d)
		if err != nil {
			return c, err
		}
		if state == confRead {
			_ = parseUnit(data, assign)
		}
	}
	c.keeps = !rules && !routes
	return c, nil
}

// placeKind is a kind of device whose far end a creation request can put in another namespace, with the type and
// driver networkd reads for it. vxcan takes the same path in the kernel but carries CAN frames, not IP.
//
// nsresourced marks the veth systemd-nsresourced makes for a caller (nsresourcedKind): its host end's name starts
// "ns-" and the rest is not the caller's to pick freely, its address is the kernel's random one, and its .link file
// gives it ID_NET_MANAGED_BY=io.systemd.Network.
type placeKind struct {
	kind, typ, driver string
	nsresourced       bool
}

// placeKinds: a veth (measured), and netkit, which takes the same path and is an Ethernet device on Linux 6.8 in
// either of its modes; a later kernel may give its L3 mode no link layer, so that is tried too.
var placeKinds = []placeKind{
	{kind: "veth", typ: "ether", driver: "veth"},
	{kind: "netkit", typ: "ether", driver: "netkit"},
	{kind: "netkit", typ: "none", driver: "netkit"},
}

// nsresourcedKind is the device systemd-nsresourced (systemd 256 and later) puts in its own network namespace, the
// host's, when an unprivileged caller asks it, over varlink (io.systemd.NamespaceResource.AddNetworkToUserNamespace),
// for a veth into a network namespace of a user namespace it registered there: no kernel fault is involved, so a
// kernel with the peer-namespace check does not stop it. Measured on systemd 257 (Debian 13, kernel 6.12): the host
// end is "ns-" and twelve hex digits, with the alternative name "ns-<uid>-<gid>-<name>-<ifname>" whose last two
// parts the caller chooses, and networkd matches Name= against either. The name search takes every name of up to 15
// bytes that starts "ns-", which holds the kernel name and every alternative name that short, and some names the
// device cannot have, in the direction that refuses.
var nsresourcedKind = placeKind{kind: "veth", typ: "ether", driver: "veth", nsresourced: true}

// nsresourcedPrefix is what every name of an nsresourced device starts with.
const nsresourcedPrefix = "ns-"

// placedDevice is a device a process could put in the host's namespace from a user namespace of its own, as
// networkd sees it once udev has initialized it.
type placedDevice struct {
	placeKind
	name, mac string
}

// nameProps are the udev properties of a placed device that carry its name, each with what comes before the name;
// constProps are the rest, as measured on a veth (systemd 255, its 99-default.link). It has no ID_PATH.
var nameProps = map[string]string{
	"INTERFACE":     "",
	"ID_NET_NAME":   "",
	"DEVPATH":       "/devices/virtual/net/",
	"SYSTEMD_ALIAS": "/sys/subsystem/net/devices/",
}

func constProps(k placeKind) map[string]string {
	p := map[string]string{
		"SUBSYSTEM":       "net",
		"ID_NET_DRIVER":   k.driver,
		"ID_MM_CANDIDATE": "1",
		"TAGS":            ":systemd:",
		"CURRENT_TAGS":    ":systemd:",
	}
	if k.nsresourced {
		p["ID_NET_MANAGED_BY"] = "io.systemd.Network" // 80-namespace-ns.link
	}
	return p
}

// absentProps are udev properties a virtual device never has: udev's path_id and net_id builtins set them from the
// physical device beneath it.
var absentProps = map[string]bool{"ID_PATH": true, "ID_PATH_TAG": true, "ID_BUS": true, "ID_VENDOR_ID": true,
	"ID_MODEL_ID": true, "ID_NET_NAME_PATH": true, "ID_NET_NAME_SLOT": true, "ID_NET_NAME_ONBOARD": true,
	"ID_NET_NAME_MAC": true, "DEVTYPE": true}

// hostFacts are what a file's host conditions are judged against: the host's, or a container's for a networkd
// that runs in one.
type hostFacts struct {
	hostname, machineID, arch, kernel string // arch as uname reports it
	cmdline                           []string
	// container is the kind of container the networkd runs in ("lxc", "systemd-nspawn", ..., "container-other"),
	// "" for the host itself: a containment is made only from the host's own pid and cgroup namespaces.
	container string
}

// tri is a judgement that may be unknown.
type tri int8

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

// constMatch judges every part of f's [Match] that does not depend on a device's name, for a placed device of kind
// k with address mac: the host conditions (one this cannot judge is unknown), the address lists, and the lists a
// placed device answers the same whatever it is named. A device has no permanent address, no ID_PATH and no
// wireless properties.
func (f *networkFile) constMatch(k placeKind, mac string, h hostFacts) tri {
	if len(f.hwAddrs) > 0 && !slices.Contains(f.hwAddrs, mac) {
		return triFalse
	}
	if len(f.permAddrs) > 0 || len(f.bssids) > 0 {
		return triFalse
	}
	if !testStrv(f.paths, "", false) || !testStrv(f.drivers, k.driver, true) || !testStrv(f.types, k.typ, true) ||
		!testStrv(f.kinds, k.kind, true) || !testStrv(f.wlanTypes, "", false) || !testStrv(f.ssids, "", false) {
		return triFalse
	}
	props := constProps(k)
	out := triTrue
	if h.container != "" && len(f.props) > 0 {
		// In a container networkd may have no udev at all (an unprivileged LXD one has none), and then every positive
		// Property= fails and every negated one holds; whether this one has, is not read.
		out = triUnknown
	}
	for _, p := range f.props {
		if h.container != "" {
			break
		}
		q, invert := strings.CutPrefix(p, "!")
		key, glob, _ := strings.Cut(q, "=")
		if _, named := nameProps[key]; named {
			continue
		}
		v, ok := props[key]
		if !ok && !absentProps[key] {
			out = triUnknown // a property a site's udev rule or .link file may give it
			continue
		}
		if (ok && fnmatch(glob, v)) == invert {
			return triFalse
		}
	}
	for key, c := range f.conds {
		switch condHolds(key, c, h) {
		case triFalse:
			return triFalse
		case triUnknown:
			out = triUnknown
		}
	}
	return out
}

// nameMatch judges the parts of f's [Match] that depend on the device's name: Name= and the name-bearing Property=
// words.
func (f *networkFile) nameMatch(name string) bool {
	if !testStrv(f.names, name, true) {
		return false
	}
	for _, p := range f.props {
		q, invert := strings.CutPrefix(p, "!")
		key, glob, _ := strings.Cut(q, "=")
		if prefix, named := nameProps[key]; named && fnmatch(glob, prefix+name) == invert {
			return false
		}
	}
	return true
}

// testStrv is networkd's net_condition_test_strv: an inverted pattern that matches refuses; otherwise, if there is
// any positive pattern, one of them must match. A device without the property (has false) matches no pattern.
func testStrv(patterns []string, s string, has bool) bool {
	if len(patterns) == 0 {
		return true
	}
	match, positive := false, false
	for _, p := range patterns {
		q, invert := strings.CutPrefix(p, "!")
		if !invert {
			positive = true
		}
		if has && fnmatch(q, s) {
			if invert {
				return false
			}
			match = true
		}
	}
	return !positive || match
}

// condHolds judges one host condition the way systemd's condition tests do, or answers unknown for one this cannot
// judge from here. Virtualization= can be judged for containers: a containment is made only from the host's own
// pid and cgroup namespaces.
func condHolds(key string, c netCond, h hostFacts) tri {
	v, known := condValue(key, c.value, h)
	if !known {
		return triUnknown
	}
	if v != c.negate {
		return triTrue
	}
	return triFalse
}

func condValue(key, value string, h hostFacts) (bool, bool) {
	switch key {
	case "Host":
		if id := strings.ReplaceAll(strings.ToLower(value), "-", ""); len(id) == 32 && isHex(id) {
			return id == strings.ToLower(h.machineID), h.machineID != ""
		}
		if h.hostname == "" {
			return false, false
		}
		return fnmatch(strings.ToLower(value), strings.ToLower(h.hostname)), true
	case "Architecture":
		a := systemdArch(h.arch)
		if a == "" {
			return false, false
		}
		if value == "native" {
			return true, true
		}
		if !knownArch(value) {
			return false, true // systemd refuses a name it does not know: the condition fails
		}
		return value == a, true
	case "KernelCommandLine":
		if h.cmdline == nil {
			return false, false
		}
		for _, w := range h.cmdline {
			if strings.Contains(value, "=") {
				if w == value {
					return true, true
				}
			} else if rest, ok := strings.CutPrefix(w, value); ok && (rest == "" || rest[0] == '=') {
				return true, true
			}
		}
		return false, true
	case "KernelVersion":
		if h.kernel == "" {
			return false, false
		}
		for _, w := range strings.Fields(value) {
			if strings.ContainsAny(w[:1], "<>=!") {
				return false, false // a comparison: systemd's version order is not reproduced here
			}
			if !fnmatch(w, h.kernel) {
				return false, true
			}
		}
		return true, true
	case "Virtualization":
		// systemd reports a container before a VM, so inside a container every VM value is false.
		inContainer := h.container != ""
		if b, ok := parseSystemdBool(value); ok {
			if inContainer {
				return b, true
			}
			return false, false // yes or no turns on whether this host is a VM
		}
		switch value {
		case "container":
			return inContainer, true
		case "private-users":
			return false, false
		case "openvz", "lxc", "lxc-libvirt", "systemd-nspawn", "docker", "podman", "rkt", "wsl", "proot", "pouch",
			"container-other":
			return inContainer && value == h.container, true
		}
		if inContainer {
			return false, true // "vm" or a VM's name
		}
	}
	return false, false
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// systemdArch is systemd's name for the architecture uname reports, or "" for one not listed here.
func systemdArch(machine string) string {
	switch machine {
	case "x86_64":
		return "x86-64"
	case "i386", "i486", "i586", "i686":
		return "x86"
	case "aarch64":
		return "arm64"
	case "aarch64_be":
		return "arm64-be"
	case "ppc64le":
		return "ppc64-le"
	case "ppc64", "s390x", "s390", "riscv64", "loongarch64", "alpha", "ia64", "m68k", "sparc64":
		return machine
	}
	if strings.HasPrefix(machine, "armv") && !strings.HasSuffix(machine, "b") {
		return "arm"
	}
	return ""
}

func knownArch(name string) bool {
	switch name {
	case "x86", "x86-64", "arm", "arm-be", "arm64", "arm64-be", "ppc", "ppc-le", "ppc64", "ppc64-le", "s390", "s390x",
		"riscv32", "riscv64", "loongarch64", "alpha", "ia64", "m68k", "sparc", "sparc64", "mips", "mips-le", "mips64",
		"mips64-le", "parisc", "parisc64", "sh", "sh64", "tilegx", "cris", "nios2", "arc", "arc-be":
		return true
	}
	return false
}

// hostForwarding is whether the host already forwards what a new device receives, per family: IPv4 by the
// forwarding a new device inherits (net.ipv4.conf.default.forwarding), IPv6 by the one switch it has.
type hostForwarding struct {
	v4, v6 bool
	// byPlacement: the namespace does not forward now, but a device a process places turns forwarding on in it (a
	// file that forwards takes one first), for the next device too.
	byPlacement bool
}

func (h hostForwarding) String() string {
	switch {
	case h.byPlacement:
		return "a device a process places there first turns forwarding on in that namespace"
	case h.v4 && h.v6:
		return "this host forwards (net.ipv4.conf.default.forwarding=1 and net.ipv6.conf.all.forwarding=1)"
	case h.v4:
		return "this host forwards IPv4 (net.ipv4.conf.default.forwarding=1)"
	case h.v6:
		return "this host forwards IPv6 (net.ipv6.conf.all.forwarding=1)"
	}
	return ""
}

// placedPath is a file networkd would apply to a placed device and bring up, and how what that device sends then
// leaves the host.
type placedPath struct {
	file   networkFile
	device placedDevice
	how    string
}

// findPlacedPaths answers whether some device a process could place, of the given kinds, has a first matching file
// that lets it out (how), and returns every such file in networkd's order, each with a device it takes. taken are the
// names already held in the namespace, which a placed device cannot have.
func findPlacedPaths(files []networkFile, taken map[string]bool, h hostFacts, fwd hostForwarding, upIsEnough bool,
	kinds []placeKind) []placedPath {
	return firstMatches(files, taken, h, kinds, func(f *networkFile) string { return f.how(fwd, upIsEnough) })
}

// placedCanForward reports whether some device a process could place is first matched by a file that turns
// forwarding on for its whole namespace when networkd applies it, whatever that file then does with the device.
func placedCanForward(files []networkFile, taken map[string]bool, h hostFacts, kinds []placeKind) bool {
	return len(firstMatches(files, taken, h, kinds, func(f *networkFile) string {
		if f.forwards() {
			return "turn forwarding on"
		}
		return ""
	})) > 0
}

// firstMatches returns, for every file pick says something for, a placed device whose first matching file it is.
//
// A host condition this cannot judge is resolved per file in the direction that refuses: a file pick names is taken
// to match, one it does not is taken not to (so it hides nothing behind it). Every address a file lists is tried, and
// one no file lists; for each kind and address, the files that come earlier and certainly take such a device are the
// names to avoid, and the name is searched exactly (nameWitness).
func firstMatches(files []networkFile, taken map[string]bool, h hostFacts, kinds []placeKind, pick func(*networkFile) string) []placedPath {
	macs := []string{}
	for _, f := range files {
		for _, m := range f.hwAddrs {
			if unicastMAC(m) && !slices.Contains(macs, m) {
				macs = append(macs, m)
			}
		}
	}
	for i := 1; ; i++ {
		m := fmt.Sprintf("02:00:00:00:00:%02x", i)
		if !slices.Contains(macs, m) {
			macs = append(macs, m)
			break
		}
	}
	var out []placedPath
	for b := range files {
		how := pick(&files[b])
		if how == "" {
			continue
		}
	kinds:
		for _, k := range kinds {
			kmacs, prefix := macs, ""
			if k.nsresourced {
				// the kernel's random address, which no file's list can be counted on to hold
				kmacs, prefix = macs[len(macs)-1:], nsresourcedPrefix
			}
			for _, m := range kmacs {
				if files[b].constMatch(k, m, h) == triFalse {
					continue
				}
				var avoid []*networkFile
				for e := 0; e < b; e++ {
					if pick(&files[e]) == "" && files[e].constMatch(k, m, h) == triTrue {
						avoid = append(avoid, &files[e])
					}
				}
				name, ok, capped := nameWitness(&files[b], avoid, taken, prefix)
				if capped {
					// Too many patterns to search: taken to have a name it takes, in the direction that refuses.
					out = append(out, placedPath{file: files[b], device: placedDevice{placeKind: k, mac: m}, how: how})
					break kinds
				}
				if ok {
					name = readableWitness(name, &files[b], avoid, taken)
					out = append(out, placedPath{file: files[b], device: placedDevice{placeKind: k, name: name, mac: m}, how: how})
					break kinds
				}
			}
		}
	}
	return out
}

// readableWitness lengthens a witness by an "x" when the longer name is taken the same way, so that a refusal names
// "ve-x" rather than a "ve-" that reads as cut short.
func readableWitness(name string, b *networkFile, avoid []*networkFile, taken map[string]bool) string {
	longer := name + "x"
	if !kernelNameValid(longer) || taken[longer] || !b.nameMatch(longer) {
		return name
	}
	for _, f := range avoid {
		if f.nameMatch(longer) {
			return name
		}
	}
	return longer
}

// kernelNameValid is the kernel's dev_valid_name, less a "%", which would make the kernel number the name itself.
func kernelNameValid(n string) bool {
	if n == "" || len(n) > maxIfName || n == "." || n == ".." {
		return false
	}
	for i := 0; i < len(n); i++ {
		if !nameByte(n[i]) {
			return false
		}
	}
	return true
}

// maxIfName is the longest interface name the kernel takes (IFNAMSIZ less its terminating NUL).
const maxIfName = 15

// nameByte reports whether the kernel takes c in an interface name: anything but a slash, a colon, the kernel's
// white space and a "%".
func nameByte(c byte) bool {
	switch c {
	case 0, '/', ':', '%', ' ', '\t', '\n', '\v', '\f', '\r', 0xa0:
		return false
	}
	return true
}

// unicastMAC reports whether a is an Ethernet address a veth may be given: six bytes, not multicast, not zero.
func unicastMAC(a string) bool {
	b := strings.Split(a, ":")
	if len(b) != 6 || a == "00:00:00:00:00:00" {
		return false
	}
	v, err := strconv.ParseUint(b[0], 16, 8)
	return err == nil && v&1 == 0
}

// nameWitness finds the shortest name the kernel would take for a new device that b's name tests admit, that no
// file in avoid admits, and that no device in the host's namespace has, or reports there is none. It walks every
// pattern involved at once over the names of up to maxIfName bytes, one representative byte for each set of bytes
// no pattern tells apart, so the answer is exact. Every name searched starts with prefix ("" for any name).
func nameWitness(b *networkFile, avoid []*networkFile, taken map[string]bool, prefix string) (name string, found, capped bool) {
	var s nameSearch
	want := s.cond(b)
	var not []nameCond
	for _, f := range avoid {
		not = append(not, s.cond(f))
	}
	var takenGlobs []int
	for n := range taken {
		takenGlobs = append(takenGlobs, s.add(literalGlob(n), ""))
	}
	type node struct {
		states [][]uint64
		name   string
	}
	start := node{states: make([][]uint64, len(s.globs)), name: prefix}
	for i, g := range s.globs {
		start.states[i] = g.advance(g.start(), s.prefix[i]+prefix)
	}
	alphabet := s.alphabet()
	seen := map[string]bool{s.key(start.states, prefix): true}
	queue := []node{start}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if n.name != "" {
			acc := make([]bool, len(s.globs))
			for i, g := range s.globs {
				acc[i] = g.accepts(n.states[i])
			}
			ok := want.holds(acc) && n.name != "." && n.name != ".."
			for _, c := range not {
				ok = ok && !c.holds(acc)
			}
			for _, t := range takenGlobs {
				ok = ok && !acc[t]
			}
			if ok {
				return n.name, true, false
			}
		}
		if len(n.name) == maxIfName {
			continue
		}
		if len(seen) > maxWitnessNodes {
			return "", false, true
		}
		for _, c := range alphabet {
			next := node{states: make([][]uint64, len(s.globs)), name: n.name + string(c)}
			for i, g := range s.globs {
				next.states[i] = g.step(n.states[i], c)
			}
			if k := s.key(next.states, next.name); !seen[k] {
				seen[k] = true
				queue = append(queue, next)
			}
		}
	}
	return "", false, false
}

// maxWitnessNodes bounds a name search: a configuration whose patterns make more states than this (a tenant can
// write one that would take minutes and gigabytes) is taken to have a name its file takes.
const maxWitnessNodes = 100000

// nameSearch holds the patterns of one name search, each with the text a name follows in what it is matched
// against (a property's prefix).
type nameSearch struct {
	globs  []glob
	prefix []string
}

func (s *nameSearch) add(g glob, prefix string) int {
	s.globs = append(s.globs, g)
	s.prefix = append(s.prefix, prefix)
	return len(s.globs) - 1
}

// nameCond is what a file's name tests ask, as indices into the search's patterns: no inverted Name= word may match,
// one positive word must if there is any, and every name-bearing property must hold.
type nameCond struct{ pos, neg, propPos, propNeg []int }

func (s *nameSearch) cond(f *networkFile) nameCond {
	var c nameCond
	for _, p := range f.names {
		if q, invert := strings.CutPrefix(p, "!"); invert {
			c.neg = append(c.neg, s.add(compileGlob(q), ""))
		} else {
			c.pos = append(c.pos, s.add(compileGlob(q), ""))
		}
	}
	for _, p := range f.props {
		q, invert := strings.CutPrefix(p, "!")
		key, g, _ := strings.Cut(q, "=")
		prefix, named := nameProps[key]
		if !named {
			continue
		}
		if invert {
			c.propNeg = append(c.propNeg, s.add(compileGlob(g), prefix))
		} else {
			c.propPos = append(c.propPos, s.add(compileGlob(g), prefix))
		}
	}
	return c
}

func (c nameCond) holds(acc []bool) bool {
	for _, i := range c.neg {
		if acc[i] {
			return false
		}
	}
	if len(c.pos) > 0 && !slices.ContainsFunc(c.pos, func(i int) bool { return acc[i] }) {
		return false
	}
	for _, i := range c.propPos {
		if !acc[i] {
			return false
		}
	}
	for _, i := range c.propNeg {
		if acc[i] {
			return false
		}
	}
	return true
}

// alphabet is one byte for each set of name bytes that every pattern treats alike, a readable one where there is a
// choice. A dot is always its own, since "." and ".." are not names.
func (s *nameSearch) alphabet() []byte {
	const prefer = "xwveqz0123456789-_abcdfghijklmnoprstuyABCDEFGHIJKLMNOPQRSTUVWXYZ"
	order := []byte(prefer)
	for c := 1; c < 256; c++ {
		if !strings.ContainsRune(prefer, rune(c)) {
			order = append(order, byte(c))
		}
	}
	bySig := map[string]bool{}
	var out []byte
	for _, c := range order {
		if !nameByte(c) {
			continue
		}
		var sig strings.Builder
		if c == '.' {
			sig.WriteString("dot")
		}
		for _, g := range s.globs {
			for _, t := range g {
				if t.op == 'c' {
					if t.set[c] {
						sig.WriteByte('1')
					} else {
						sig.WriteByte('0')
					}
				}
			}
		}
		if k := sig.String(); !bySig[k] {
			bySig[k] = true
			out = append(out, c)
		}
	}
	return out
}

// key identifies a node of the search by its pattern states, and by what makes a name no name: being empty, or
// "." or "..".
func (s *nameSearch) key(states [][]uint64, name string) string {
	var b strings.Builder
	switch name {
	case "", ".", "..":
		b.WriteString(name + "|")
	}
	for _, st := range states {
		for _, w := range st {
			b.WriteString(strconv.FormatUint(w, 36))
			b.WriteByte(',')
		}
		b.WriteByte(';')
	}
	return b.String()
}

// glob is a pattern compiled for glibc's fnmatch(pattern, s, 0): a sequence of steps, each matching one byte
// from a set, any one byte, or any run of bytes. It is matched as a set of positions in that sequence.
type glob []globTok

type globTok struct {
	op  byte       // 'c' one byte of set, '?' any one byte, '*' any run of bytes
	set *[256]bool // for 'c'
}

// compileGlob compiles a pattern the way glibc reads it with no flags: "*" and "?" match a slash too; a bracket
// expression matches one byte, "!" or "^" negating it, with ranges, the POSIX classes and a "]" first taken as a
// member; a backslash quotes the next byte, and a trailing one makes the pattern match nothing; a "[" that is not
// closed is an ordinary byte.
func compileGlob(p string) glob {
	var g glob
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '*':
			g = append(g, globTok{op: '*'})
		case '?':
			g = append(g, globTok{op: '?'})
		case '[':
			if set, end, ok := parseBracket(p, i); ok {
				g = append(g, globTok{op: 'c', set: set})
				i = end
				continue
			}
			g = append(g, oneByte('['))
		case '\\':
			if i+1 == len(p) {
				return glob{{op: 'c', set: &[256]bool{}}} // "Trailing \ loses"
			}
			i++
			g = append(g, oneByte(p[i]))
		default:
			g = append(g, oneByte(c))
		}
	}
	return g
}

func oneByte(c byte) globTok {
	var set [256]bool
	set[c] = true
	return globTok{op: 'c', set: &set}
}

// literalGlob matches exactly s.
func literalGlob(s string) glob {
	g := make(glob, len(s))
	for i := 0; i < len(s); i++ {
		g[i] = oneByte(s[i])
	}
	return g
}

// parseBracket reads the bracket expression that opens at p[open], as glibc reads it, returning the bytes it matches
// and the index of its closing "]", or ok false when it is not closed (then the "[" is an ordinary byte). Inside it:
// "!" or "^" first negates; a "]" first is a member; a backslash quotes the next byte; "a-z" is a range; "[:name:]" is
// a class when name is lowercase letters, "[.c.]" and "[=c=]" are the byte c; any other "[" is a member. glibc stops
// at a class name it does not know, so bytes the members before it admit still match and nothing else does (and a
// negated expression then matches nothing).
func parseBracket(p string, open int) (*[256]bool, int, bool) {
	var set [256]bool
	j := open + 1
	negate := j < len(p) && (p[j] == '!' || p[j] == '^')
	if negate {
		j++
	}
	stopped := false
	for first := true; j < len(p); first = false {
		c := p[j]
		if c == ']' && !first {
			if negate {
				if stopped {
					return &[256]bool{}, j, true
				}
				for k := range set {
					set[k] = !set[k]
				}
			}
			return &set, j, true
		}
		if c == '[' && j+1 < len(p) && (p[j+1] == ':' || p[j+1] == '.' || p[j+1] == '=') {
			delim := p[j+1]
			if k := strings.Index(p[j+2:], string(delim)+"]"); k >= 0 {
				body := p[j+2 : j+2+k]
				switch {
				case delim == ':' && isLowerWord(body):
					if !posixClassKnown(body) {
						stopped = true
					}
					if !stopped {
						for b := 0; b < 256; b++ {
							if posixClass(body, byte(b)) {
								set[b] = true
							}
						}
					}
					j += 2 + k + 2
					continue
				case (delim == '.' || delim == '=') && len(body) == 1:
					if !stopped {
						set[body[0]] = true
					}
					j += 2 + k + 2
					continue
				}
			}
		}
		if c == '\\' {
			if j+1 >= len(p) {
				return nil, 0, false
			}
			j++
			c = p[j]
		}
		j++
		lo, hi := c, c
		if j+1 < len(p) && p[j] == '-' && p[j+1] != ']' {
			hi = p[j+1]
			j += 2
			if hi == '\\' && j < len(p) {
				hi = p[j]
				j++
			}
		}
		if !stopped {
			for b := int(lo); b <= int(hi); b++ {
				set[b] = true
			}
		}
	}
	return nil, 0, false
}

func isLowerWord(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return true
}

func posixClassKnown(name string) bool {
	switch name {
	case "alpha", "digit", "alnum", "upper", "lower", "xdigit", "space", "blank", "punct", "print", "graph", "cntrl":
		return true
	}
	return false
}

func posixClass(name string, c byte) bool {
	switch name {
	case "alpha":
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	case "digit":
		return c >= '0' && c <= '9'
	case "alnum":
		return posixClass("alpha", c) || posixClass("digit", c)
	case "upper":
		return c >= 'A' && c <= 'Z'
	case "lower":
		return c >= 'a' && c <= 'z'
	case "xdigit":
		return posixClass("digit", c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
	case "space":
		return c == ' ' || (c >= '\t' && c <= '\r')
	case "blank":
		return c == ' ' || c == '\t'
	case "punct":
		return c > 32 && c < 127 && !posixClass("alnum", c)
	case "print":
		return c >= 32 && c < 127
	case "graph":
		return c > 32 && c < 127
	case "cntrl":
		return c < 32 || c == 127
	}
	return false
}

// start is the set of positions before any byte is read.
func (g glob) start() []uint64 {
	st := make([]uint64, (len(g)+64)/64)
	g.close(st, 0)
	return st
}

// close adds position i and every position a run of "*" lets it skip to.
func (g glob) close(st []uint64, i int) {
	for {
		st[i/64] |= 1 << (i % 64)
		if i == len(g) || g[i].op != '*' {
			return
		}
		i++
	}
}

// step is the set of positions after reading c from any of st.
func (g glob) step(st []uint64, c byte) []uint64 {
	next := make([]uint64, len(st))
	for i := 0; i < len(g); i++ {
		if st[i/64]&(1<<(i%64)) == 0 {
			continue
		}
		switch t := g[i]; t.op {
		case '*':
			g.close(next, i)
		case '?':
			g.close(next, i+1)
		case 'c':
			if t.set[c] {
				g.close(next, i+1)
			}
		}
	}
	return next
}

// advance reads s from st.
func (g glob) advance(st []uint64, s string) []uint64 {
	for i := 0; i < len(s); i++ {
		st = g.step(st, s[i])
	}
	return st
}

func (g glob) accepts(st []uint64) bool { return st[len(g)/64]&(1<<(len(g)%64)) != 0 }

// fnmatch is glibc's fnmatch(pattern, s, 0) == 0 (compileGlob).
func fnmatch(pattern, s string) bool {
	g := compileGlob(pattern)
	return g.accepts(g.advance(g.start(), s))
}

// placedFinding is what one networkd would do with a placed device, for the refusal.
type placedFinding struct {
	where     string // "in this host's namespace", "in the container web1 (networkd pid 4242)"
	why       string // how that networkd comes to manage a new device there
	host      bool
	running   bool // networkd runs, so a restart applies a fix (one that does not run reads its files when it starts)
	pid       int  // the networkd's pid, 0 when it does not run
	container string
	paths     []placedPath
	leftover  []placedPath        // host: what the one unmanaged file would not close (files that sort before it)
	inUse     map[string][]string // file -> the links it configures now
	stale     []string            // what changed since networkd started, which it may not have read
	staleOnly bool                // the files on disk leave no way out; only what networkd may still hold does
	unknown   bool                // something changed in place or went, so what networkd holds cannot be read at all
	initPid   int                 // a container's init, through which a fix enters it (networkd's own mounts are read-only)
	foreign   []string            // host: routing policy rules networkd would delete at a restart, by priority
	keeps     bool                // host: networkd.conf turns off both of networkd's deletions of what it did not make
	unread    bool                // host: the fix file is there, but networkd's own user cannot read it
	// nsresourced says why systemd-nsresourced would make a device in this networkd's namespace ("" when it is not
	// counted); kernelToo whether the kernel places one there as well. With nsresourced alone the fix is to mask, or
	// change, the files that would take its device (nsrMasks, nsrEdits), not to leave every veth unmanaged.
	nsresourced        string
	kernelToo          bool
	nsrMasks, nsrEdits []string
}

// unmanagedFixFile is the file the refusal asks for on the host: it sorts before every stock file and keeps every
// device of a kind a process can place unmanaged, since networkd applies the first file that matches.
const unmanagedFixFile = "00-whisper-unmanaged-veth.network"

// withUnmanagedFirst is files with the refusal's fix in place: a file that sorts before the rest and keeps every
// veth and netkit device unmanaged.
func withUnmanagedFirst(files []networkFile) []networkFile {
	fix := networkFile{path: slashpath.Join("/etc/systemd/network", unmanagedFixFile), drivers: []string{"veth", "netkit"},
		unmanaged: true, conds: map[string]netCond{}}
	out := make([]networkFile, 0, len(files)+1)
	placed := false
	for _, f := range files {
		if slashpath.Base(f.path) == unmanagedFixFile {
			continue // the fix replaces a file of its own name
		}
		if !placed && slashpath.Base(f.path) > unmanagedFixFile {
			out = append(out, fix)
			placed = true
		}
		out = append(out, f)
	}
	if !placed {
		out = append(out, fix)
	}
	return out
}

// vendorDir reports whether a configuration file sits in a directory a package owns, so that the fix is a mask in
// /etc rather than an edit.
func vendorDir(path string) bool { return !strings.HasPrefix(path, "/etc/") }

// nsresourcedFix is what closes the way out through systemd-nsresourced's device on a kernel that places nothing
// itself: every file that would take such a device and let it out, masked when a package owns it and changed by hand
// when it is the site's, followed until no file takes one, since masking one file hands the device to the next.
func nsresourcedFix(files []networkFile, taken map[string]bool, h hostFacts, fwd hostForwarding) (masks, edits []string) {
	cur := slices.Clone(files)
	for range files {
		paths := findPlacedPaths(cur, taken, h, fwd, true, []placeKind{nsresourcedKind})
		if len(paths) == 0 {
			break
		}
		gone := map[string]bool{}
		for _, p := range paths {
			if vendorDir(p.file.path) && pasteable(p.file.path) {
				masks = append(masks, p.file.path)
			} else {
				edits = append(edits, quoteText(p.file.path))
			}
			gone[p.file.path] = true
		}
		cur = slices.DeleteFunc(cur, func(f networkFile) bool { return gone[f.path] })
	}
	return masks, edits
}

// placedRefusal is the refusal for a containment of pid (named name) on a host where findings say a placed device
// would be let out. probe says what the kernel test found, "" when the kernel places nothing and only
// systemd-nsresourced does. Each command to paste is on a line of its own.
func placedRefusal(pid int, name string, findings []placedFinding, probe string) string {
	var b strings.Builder
	nsr := ""
	for _, f := range findings {
		if f.nsresourced != "" {
			nsr = f.nsresourced
		}
	}
	fmt.Fprintf(&b, "pid %d (%s) was not contained: it could reach the network past the containment.", pid, name)
	if probe != "" {
		fmt.Fprintf(&b, " Any unprivileged process can make a user namespace of its own and from there put the far end "+
			"of a veth or netkit pair in another network namespace, with a name and MAC address of its choosing (%s).", probe)
	}
	if nsr != "" {
		fmt.Fprintf(&b, " systemd-nsresourced makes a veth for any unprivileged process that asks it for one into a user "+
			"namespace of its own, the host end named \"ns-\" and more, with no kernel fault at all (%s).", nsr)
	}
	b.WriteString(" systemd-networkd would take such a device")
	containers := false
	for i, f := range findings {
		if i > 0 {
			b.WriteString("; and")
		}
		fmt.Fprintf(&b, " %s, %s:", f.where, f.why)
		if f.unknown {
			fmt.Fprintf(&b, " it started before %s changed, so what it holds may not be what is on disk, and a reload "+
				"cannot be seen from here", quoteList(f.stale))
		}
		for j, p := range f.paths {
			if j > 0 || f.unknown {
				b.WriteString(", and")
			}
			if p.device.name == "" {
				fmt.Fprintf(&b, " %s has patterns too many to search, so it is taken to take one and %s", fileAndDropins(p.file), p.how)
			} else {
				fmt.Fprintf(&b, " %s takes one named %q and would %s", fileAndDropins(p.file), quoteText(p.device.name), p.how)
			}
			if users := f.inUse[p.file.path]; len(users) > 0 {
				fmt.Fprintf(&b, " (it configures %s now)", strings.Join(users, ", "))
			}
		}
		containers = containers || !f.host
	}
	b.WriteString(". Nothing was changed. A firewall's forward policy is not counted: Docker, firewalld and a plain " +
		"`iptables -P FORWARD ACCEPT` each change it.")
	if containers {
		b.WriteString(" A container started after this check is not judged, and a fix inside a container lasts only as long " +
			"as that container does: on a host that runs such containers, a kernel with the fix is the one that lasts.")
	}
	for _, f := range findings {
		b.WriteString("\n")
		b.WriteString(placedFix(f))
	}
	if probe != "" {
		b.WriteString("\nA kernel that checks the far end's namespace (upstream commit 7b735ef81286) closes the kernel's " +
			"part of it.")
	}
	if nsr != "" {
		b.WriteString("\nMasking systemd-nsresourced closes its part as well, at the cost of every unprivileged " +
			"container it serves and the user ranges it has handed out:" +
			cmdLine("sudo systemctl mask --now systemd-nsresourced.socket systemd-nsresourced.service"))
	}
	fmt.Fprintf(&b, "\nThen run `sudo whisper contain %d` again.", pid)
	return b.String()
}

// quoteList is a list of paths read from a configuration, each made safe to print.
func quoteList(ps []string) string {
	q := make([]string, len(ps))
	for i, p := range ps {
		q[i] = quoteText(p)
	}
	return strings.Join(q, ", ")
}

func fileAndDropins(f networkFile) string {
	if len(f.dropins) == 0 {
		return quoteText(f.path)
	}
	return quoteText(f.path) + " (with " + quoteList(f.dropins) + ")"
}

// cmdLine is one command to paste, on a line of its own.
func cmdLine(c string) string { return "\n    " + c }

// fixFileCommand writes the host's fix file readable by networkd's own user whatever the umask, making the directory
// if need be.
const fixFileCommand = "printf '[Match]\\nDriver=veth netkit\\n\\n[Link]\\nUnmanaged=yes\\n' | sudo install -D -m 0644 /dev/stdin " +
	"/etc/systemd/network/" + unmanagedFixFile

// placedFix says how to close what one networkd would do, with the commands to paste, a restart last so that
// nothing changed after it is left for networkd to have missed.
func placedFix(f placedFinding) string {
	if !f.host {
		var masks, edits []string
		for _, p := range f.paths {
			if f.staleOnly || f.unknown {
				continue
			}
			if vendorDir(p.file.path) && pasteable(p.file.path) {
				masks = append(masks, "ln -s /dev/null "+shellWord("/etc/systemd/network/"+slashpath.Base(p.file.path)))
			} else {
				edits = append(edits, quoteText(p.file.path)) // a name no command should carry is masked or changed by hand
			}
		}
		if f.initPid == 0 {
			return fmt.Sprintf("In the container %s, whose init this command could not find, enter it as its own root and "+
				"mask or change the files named above, then restart networkd there.", f.container)
		}
		out := fmt.Sprintf("In the container %s, whose init is pid %d here", f.container, f.initPid)
		if len(edits) > 0 {
			out += ", change " + strings.Join(edits, " and ") + " there so that no such device matches it (" + narrowHint + ")"
		}
		inner := "systemctl restart systemd-networkd"
		if len(masks) > 0 {
			inner = "mkdir -p /etc/systemd/network && " + strings.Join(masks, " && ") + " && " + inner
		}
		return out + ", then run:" + cmdLine(fmt.Sprintf("sudo nsenter -t %d -a -- sh -c %s", f.initPid, shellWord(inner)))
	}
	restart := "sudo systemctl restart systemd-networkd"
	var out string
	if f.nsresourced != "" && !f.kernelToo && !f.staleOnly && !f.unknown {
		// The kernel places nothing here, so only nsresourced's device has to be kept in: masking the files that take
		// it leaves every other veth (systemd-nspawn's, netplan's) as it is.
		out = "To close it on this host, keep networkd from taking systemd-nsresourced's device"
		if len(f.nsrMasks) > 0 {
			out += ": mask " + quoteList(f.nsrMasks)
		}
		if len(f.nsrEdits) > 0 {
			out += map[bool]string{true: ", and", false: ":"}[len(f.nsrMasks) > 0] + " change " +
				strings.Join(f.nsrEdits, " and ") + " so that no device named ns-* matches (" + narrowHint + ")"
		}
		if f.running {
			out += ", then restart networkd"
		}
		out += ":"
		for _, m := range f.nsrMasks {
			out += cmdLine("sudo ln -s /dev/null " + shellWord("/etc/systemd/network/"+slashpath.Base(m)))
		}
		if f.running {
			out += cmdLine(restart)
		}
		out += "\nUnprivileged containers that systemd-nsresourced serves then get no network from networkd."
		if f.running && !f.keeps {
			out += foreignNote(f)
		}
		return out
	}
	if f.staleOnly || f.unknown {
		if !f.running {
			return "On this host, networkd reads its files when it starts, so nothing more is needed there."
		}
		out = "On this host, restart networkd so that it holds what is on disk:" + cmdLine(restart)
	} else {
		out = "To close it on this host, make networkd leave every veth and netkit device alone with one file that sorts " +
			"before the rest"
		var masks, edits []string
		for _, p := range f.leftover {
			if vendorDir(p.file.path) && pasteable(p.file.path) {
				masks = append(masks, p.file.path)
			} else {
				edits = append(edits, quoteText(p.file.path))
			}
		}
		if len(masks) > 0 {
			out += ", mask " + quoteList(masks) + ", which sort" + map[bool]string{true: "s", false: ""}[len(masks) == 1] +
				" before it"
		}
		if len(edits) > 0 {
			out += ", change " + strings.Join(edits, " and ") + ", which sort" + map[bool]string{true: "s", false: ""}[len(edits) == 1] +
				" before it too, so that no such device matches (" + narrowHint + ")"
		}
		if f.running {
			out += ", and then restart networkd"
		}
		out += ":" + cmdLine(fixFileCommand)
		for _, m := range masks {
			out += cmdLine("sudo ln -s /dev/null " + shellWord("/etc/systemd/network/"+slashpath.Base(m)))
		}
		if f.running {
			out += cmdLine(restart)
		}
		out += "\nnetworkd then configures no veth or netkit device at all: systemd-nspawn containers started with " +
			"--network-veth, --network-zone or --network-bridge, netplan's virtual-ethernets and any veth this host's own " +
			".netdev files make lose their network, and a host that needs them has no fix on the networkd side on this kernel."
	}
	if f.unread {
		out += " /etc/systemd/network/" + unmanagedFixFile + " is there already, but networkd's own user cannot read it, so " +
			"networkd ignores it; the command above writes it readable."
	}
	if f.running && !f.keeps {
		if strings.HasSuffix(out, restart) {
			out += "\n" + strings.TrimPrefix(foreignNote(f), " ") // never on the command's own line, which is pasted
		} else {
			out += foreignNote(f)
		}
	}
	return out
}

// foreignNote warns what a restart of a host's networkd deletes.
func foreignNote(f placedFinding) string {
	out := " The restart makes networkd delete the routing policy rules and routes it did not make itself " +
		"(ManageForeignRoutingPolicyRules= and ManageForeignRoutes=, on unless networkd.conf turns them off)"
	if len(f.foreign) > 0 {
		out += ", which here are the rules at priority " + strings.Join(f.foreign, ", ")
	}
	return out + ": a WireGuard or Tailscale client or a CNI puts its own back only when it restarts, so run it from a " +
		"console if this host's own access rides on one."
}

// narrowHint says how to narrow a site file's [Match] so that no placed device satisfies it.
const narrowHint = "a [Match] with a PermanentMACAddress= or Path= that names a real device, or, on networkd 251 and " +
	"later, Kind=!* as systemd's own 89-ethernet example has; never Name= or MACAddress= alone, which the placing request " +
	"chooses"

// capNetAdmin is CAP_NET_ADMIN's number, which a veth's creation needs.
const capNetAdmin = 12

// boundingHasNetAdmin reads CapabilityBoundingSet= from a service's unit file and its drop-ins, in the order systemd
// applies them (units), the way systemd's config_parse_capability_set does: with no assignment the set is every
// capability; an assignment that names no capability replaces the set, with none for an empty value and every one
// for a lone "~"; otherwise the first assignment sets the set, and a later one is ORed in, or, starting with "~",
// which inverts its list, ANDed in. It reports whether CAP_NET_ADMIN is left in the set, and known false when a file
// or a word cannot be read, which the caller counts in the direction that refuses.
func boundingHasNetAdmin(units []string) (has, known bool) {
	has, set := true, false
	known = true
	for _, u := range units {
		err := parseUnit(u, func(section, key, value string) {
			if section != "Service" || key != "CapabilityBoundingSet" {
				return
			}
			words, invert := strings.CutPrefix(value, "~")
			bit, any := false, false
			for _, w := range strings.Fields(words) {
				lw := strings.ToLower(w)
				switch {
				case lw == "cap_net_admin":
					bit, any = true, true
				case strings.HasPrefix(lw, "cap_"):
					any = true
				case isDigits(lw):
					n, err := strconv.Atoi(lw)
					bit, any = bit || (err == nil && n == capNetAdmin), true
				default:
					known = false // a specifier or something systemd may read otherwise
				}
			}
			switch {
			case !any:
				has = invert
			case !set:
				has = bit != invert
			case invert:
				has = has && !bit
			default:
				has = has || bit
			}
			set = true
		})
		if err != nil {
			known = false
		}
	}
	return has, known
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
