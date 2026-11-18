// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// networkd_test.go holds the placed-device check to networkd's own reading of its files. The files under
// testdata/networkd are real: usr-lib is /usr/lib/systemd/network of an Ubuntu 24.04 install (systemd 255.4, the
// stock files, MIT-0), run is what netplan generated there for the host's uplink. Each test builds a configuration
// root from them and adds the site files it is about.

// stockHost is the host the measurement ran on: one uplink named enp1s0 and loopback, nothing forwarding.
var stockHost = hostFacts{hostname: "lab-host", machineID: "0123456789abcdef0123456789abcdef", arch: "x86_64",
	kernel: "6.8.0-147-generic", cmdline: []string{"BOOT_IMAGE=/vmlinuz", "root=/dev/vda1", "ro", "quiet"}}

var stockTaken = map[string]bool{"lo": true, "enp1s0": true}

// netRoot is a configuration root holding the stock files, with extra written on top (a path relative to the
// root, mapped to its content).
func netRoot(t *testing.T, extra map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for from, to := range map[string]string{"usr-lib": "usr/lib/systemd/network", "run": "run/systemd/network"} {
		ents, err := os.ReadDir(filepath.Join("testdata", "networkd", from))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, to), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			b, err := os.ReadFile(filepath.Join("testdata", "networkd", from, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, to, e.Name()), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for p, content := range extra {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// mask puts a symbolic link to /dev/null at p under root, as `ln -s /dev/null` does.
func mask(t *testing.T, root, p string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", full); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("this Windows account cannot make symbolic links: %v", err)
		}
		t.Fatal(err)
	}
}

func pathIn(t *testing.T, root string, taken map[string]bool, h hostFacts, fwd hostForwarding) (placedPath, bool) {
	t.Helper()
	files, err := loadNetworkFiles(networkdReader{root: root})
	if err != nil {
		t.Fatalf("loading the configuration: %v", err)
	}
	return firstPath(findPlacedPaths(files, taken, h, fwd, false, placeKinds))
}

func firstPath(ps []placedPath) (placedPath, bool) {
	if len(ps) == 0 {
		return placedPath{}, false
	}
	return ps[0], true
}

// The measured case: on a stock host, networkd takes a veth named ve-* with 80-container-ve.network and
// masquerades it, and nothing earlier in its order takes such a device first.
func TestTheStockContainerFileTakesAPlacedVeth(t *testing.T) {
	root := netRoot(t, nil)
	files, err := loadNetworkFiles(networkdReader{root: root})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f.path))
	}
	// The .example and .link files are not .network files, and netplan's file sorts first.
	want := "10-netplan-enp1s0.network 80-6rd-tunnel.network 80-container-host0.network 80-container-vb.network " +
		"80-container-ve.network 80-container-vz.network 80-vm-vt.network 80-wifi-adhoc.network"
	if got := strings.Join(names, " "); got != want {
		t.Fatalf("loaded %s\nwant   %s", got, want)
	}
	p, ok := firstPath(findPlacedPaths(files, stockTaken, stockHost, hostForwarding{}, false, placeKinds))
	if !ok {
		t.Fatal("no path found on the stock host")
	}
	if p.file.path != "/usr/lib/systemd/network/80-container-ve.network" || p.device.kind != "veth" ||
		!strings.HasPrefix(p.device.name, "ve-") || !strings.Contains(p.how, "IPMasquerade=both") {
		t.Fatalf("got %s for a %s named %q: %s", p.file.path, p.device.kind, p.device.name, p.how)
	}
}

func TestAMaskedContainerFileLeavesNoPath(t *testing.T) {
	t.Run("a link to /dev/null in /etc", func(t *testing.T) {
		root := netRoot(t, nil)
		mask(t, root, "etc/systemd/network/80-container-ve.network")
		if p, ok := pathIn(t, root, stockTaken, stockHost, hostForwarding{}); ok {
			t.Fatalf("path through %s", p.file.path)
		}
	})
	t.Run("an empty file in /etc", func(t *testing.T) {
		root := netRoot(t, map[string]string{"etc/systemd/network/80-container-ve.network": ""})
		if p, ok := pathIn(t, root, stockTaken, stockHost, hostForwarding{}); ok {
			t.Fatalf("path through %s", p.file.path)
		}
	})
	t.Run("but a mask in a lower directory than the file hides nothing", func(t *testing.T) {
		root := netRoot(t, map[string]string{"etc/systemd/network/80-container-ve.network": "[Match]\nKind=veth\nName=ve-*\n[Network]\nIPMasquerade=ipv4\n"})
		mask(t, root, "run/systemd/network/80-container-ve.network")
		p, ok := pathIn(t, root, stockTaken, stockHost, hostForwarding{})
		if !ok || p.file.path != "/etc/systemd/network/80-container-ve.network" {
			t.Fatalf("got %v %+v", ok, p.file.path)
		}
	})
	t.Run("but on a host that forwards, the bridge-side file takes a veth too", func(t *testing.T) {
		// 80-container-vb.network brings a vb-* veth up with no address; on a host that forwards, what it receives
		// is forwarded all the same. host0 is for inside a container, vz- is a bridge and vt- a tap.
		root := netRoot(t, nil)
		mask(t, root, "etc/systemd/network/80-container-ve.network")
		p, ok := pathIn(t, root, stockTaken, stockHost, hostForwarding{v4: true})
		if !ok || p.file.path != "/usr/lib/systemd/network/80-container-vb.network" || !strings.HasPrefix(p.device.name, "vb-") ||
			!strings.Contains(p.how, "net.ipv4.conf.default.forwarding=1") {
			t.Fatalf("got %v %s %q %s", ok, p.file.path, p.device.name, p.how)
		}
		mask(t, root, "etc/systemd/network/80-container-vb.network")
		if p, ok := pathIn(t, root, stockTaken, stockHost, hostForwarding{v4: true, v6: true}); ok {
			t.Fatalf("path through %s for %q", p.file.path, p.device.name)
		}
	})
}

func TestADropInDecidesWhatTheFileDoes(t *testing.T) {
	const dir = "etc/systemd/network/80-container-ve.network.d/"
	cases := []struct {
		name, dropin string
		fwd          hostForwarding
		path         bool
	}{
		{"unmanaged", "[Link]\nUnmanaged=yes\n", hostForwarding{}, false},
		{"no masquerade, host not forwarding", "[Network]\nIPMasquerade=no\n", hostForwarding{}, false},
		{"no masquerade, host forwarding", "[Network]\nIPMasquerade=no\n", hostForwarding{v4: true}, true},
		{"masquerade emptied", "[Network]\nIPMasquerade=\n", hostForwarding{}, false},
		{"left down", "[Link]\nActivationPolicy=down\n", hostForwarding{v6: true}, false},
		{"manual", "[Link]\nActivationPolicy=manual\n", hostForwarding{}, false},
		{"bound by BindCarrier whatever its policy", "[Link]\nActivationPolicy=down\n[Network]\nBindCarrier=enp1s0\n", hostForwarding{}, true},
		{"Name reset to one nobody can take", "[Match]\nName=\nName=enp1s0\n", hostForwarding{}, false},
		{"a drop-in networkd cannot parse fails the file", "[Network\nIPMasquerade=no\n", hostForwarding{}, false},
		{"a later drop-in wins", "[Network]\nIPMasquerade=no\n", hostForwarding{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			extra := map[string]string{dir + "50-test.conf": c.dropin}
			if c.name == "a later drop-in wins" {
				extra[dir+"10-first.conf"] = "[Network]\nIPMasquerade=both\n"
			}
			root := netRoot(t, extra)
			mask(t, root, "etc/systemd/network/80-container-vb.network") // only the ve file is judged here
			p, ok := pathIn(t, root, stockTaken, stockHost, c.fwd)
			if ok != c.path {
				t.Fatalf("path %v (%s %q %s), want %v", ok, p.file.path, p.device.name, p.how, c.path)
			}
			if ok && len(p.file.dropins) == 0 {
				t.Fatal("the path does not name the drop-in it read")
			}
		})
	}
	t.Run("a drop-in in /etc hides the same name in /usr/lib", func(t *testing.T) {
		root := netRoot(t, map[string]string{
			"usr/lib/systemd/network/80-container-ve.network.d/50-x.conf": "[Link]\nUnmanaged=yes\n",
			dir + "50-x.conf": "[Network]\nIPMasquerade=both\n",
		})
		if _, ok := pathIn(t, root, stockTaken, stockHost, hostForwarding{}); !ok {
			t.Fatal("the /usr/lib drop-in was read over the /etc one")
		}
	})
	t.Run("a masked drop-in is skipped", func(t *testing.T) {
		root := netRoot(t, map[string]string{"usr/lib/systemd/network/80-container-ve.network.d/50-x.conf": "[Link]\nUnmanaged=yes\n"})
		mask(t, root, dir+"50-x.conf")
		if _, ok := pathIn(t, root, stockTaken, stockHost, hostForwarding{}); !ok {
			t.Fatal("a masked drop-in was applied")
		}
	})
}

func TestNetworkdAppliesTheFirstFileThatMatches(t *testing.T) {
	t.Run("an earlier file keeps every veth unmanaged", func(t *testing.T) {
		root := netRoot(t, map[string]string{"etc/systemd/network/05-veth.network": "[Match]\nKind=veth netkit\n[Link]\nUnmanaged=yes\n"})
		if p, ok := pathIn(t, root, stockTaken, stockHost, hostForwarding{v4: true}); ok {
			t.Fatalf("path through %s for a %s", p.file.path, p.device.kind)
		}
	})
	t.Run("an earlier file that takes only some names leaves the rest", func(t *testing.T) {
		root := netRoot(t, map[string]string{"etc/systemd/network/05-vex.network": "[Match]\nName=ve-x*\n[Link]\nUnmanaged=yes\n"})
		p, ok := pathIn(t, root, stockTaken, stockHost, hostForwarding{})
		if !ok || !strings.HasSuffix(p.file.path, "80-container-ve.network") || strings.HasPrefix(p.device.name, "ve-x") {
			t.Fatalf("got %v %s %q", ok, p.file.path, p.device.name)
		}
	})
	t.Run("an earlier file that only addresses it, with the host not forwarding", func(t *testing.T) {
		root := netRoot(t, map[string]string{"etc/systemd/network/05-ve.network": "[Match]\nName=ve-*\n[Network]\nDHCP=yes\n"})
		if p, ok := pathIn(t, root, stockTaken, stockHost, hostForwarding{}); ok {
			t.Fatalf("path through %s", p.file.path)
		}
	})
}

func TestSiteFilesThatTakeAPlacedDevice(t *testing.T) {
	fw := hostForwarding{v4: true}
	cases := []struct {
		name, file string
		fwd        hostForwarding
		taken      map[string]bool
		want       string // the device's name or kind it must have, "" for no path
	}{
		{"a catch-all with DHCP, host not forwarding", "[Match]\nName=*\n[Network]\nDHCP=yes\n", hostForwarding{}, nil, ""},
		{"a catch-all with DHCP, host forwarding", "[Match]\nName=*\n[Network]\nDHCP=yes\n", fw, nil, "veth"},
		{"the ethernet example made real excludes every kind", "[Match]\nKind=!*\nType=ether\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, ""},
		{"a MAC match is the request's to satisfy", "[Match]\nMACAddress=00:16:3e:aa:bb:cc\n[Network]\nIPForward=ipv4\n", hostForwarding{}, nil, "00:16:3e:aa:bb:cc"},
		{"a multicast MAC cannot be given", "[Match]\nMACAddress=01:00:5e:00:00:01\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, ""},
		{"a permanent address no placed device has", "[Match]\nPermanentMACAddress=52:54:00:12:34:56\n[Network]\nIPForward=yes\n", fw, nil, ""},
		{"an exact name the host holds", "[Match]\nName=enp1s0\n[Network]\nIPForward=yes\n", fw, nil, ""},
		{"an exact name the host does not hold", "[Match]\nName=eth9\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, "eth9"},
		{"only inverted names", "[Match]\nName=!enp* !lo\n[Network]\nIPMasquerade=both\n", hostForwarding{}, nil, "veth"},
		{"a whole-value inversion", "[Match]\nKind=!veth netkit\n[Network]\nIPMasquerade=both\n", hostForwarding{}, nil, ""},
		{"inverting veth leaves netkit", "[Match]\nKind=!veth\nName=n*\n[Network]\nIPMasquerade=both\n", hostForwarding{}, nil, "netkit"},
		{"a container condition does not hold on a host", "[Match]\nKind=veth\nName=host0\nVirtualization=container\n[Network]\nIPForward=yes\n", fw, nil, ""},
		{"its negation does", "[Match]\nKind=veth\nName=host0\nVirtualization=!container\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, "host0"},
		{"a VM condition is taken to hold", "[Match]\nKind=veth\nName=v*\nVirtualization=!vm\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, "veth"},
		{"an empty [Match] is ignored", "[Match]\n[Network]\nIPForward=yes\n", fw, nil, ""},
		{"a host condition alone matches every device", "[Match]\nHost=lab-*\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, "veth"},
		{"another host's file", "[Match]\nHost=other\nName=*\n[Network]\nIPForward=yes\n", fw, nil, ""},
		{"by machine id", "[Match]\nHost=01234567-89ab-cdef-0123-456789abcdef\nName=*\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, "veth"},
		{"another architecture", "[Match]\nArchitecture=arm64\nName=*\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, ""},
		{"this architecture", "[Match]\nArchitecture=x86-64\nName=*\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, "veth"},
		{"a word on the command line", "[Match]\nKernelCommandLine=quiet\nName=*\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, "veth"},
		{"a word not on it", "[Match]\nKernelCommandLine=splash\nName=*\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, ""},
		{"a kernel version glob", "[Match]\nKernelVersion=5.*\nName=*\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, ""},
		{"a kernel version comparison is taken to hold", "[Match]\nKernelVersion=>=7.0\nName=*\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, "veth"},
		{"an invalid Name word is dropped, leaving no restriction", "[Match]\nKind=veth\nName=foo/bar\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, "veth"},
		{"a Path no virtual device has", "[Match]\nPath=pci-*\n[Network]\nIPForward=yes\n", fw, nil, ""},
		{"an inverted Path", "[Match]\nPath=!pci-*\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, "veth"},
		{"a driver property", "[Match]\nProperty=ID_NET_DRIVER=veth\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, "veth"},
		{"a property a placed device lacks", "[Match]\nProperty=ID_PATH=*\n[Network]\nIPForward=yes\n", fw, nil, ""},
		{"an inverted property", "[Match]\nProperty=!ID_PATH=*\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, "veth"},
		{"a wireless type", "[Match]\nWLANInterfaceType=station\n[Network]\nIPForward=yes\n", fw, nil, ""},
		{"a bridge port", "[Match]\nName=vnet*\n[Network]\nBridge=br0\n", hostForwarding{}, nil, "vnet"},
		{"deprecated masquerade spelling", "[Match]\nName=q*\n[Network]\nIPMasquerade=yes\n", hostForwarding{}, nil, "q"},
		{"IPForward=kernel is no", "[Match]\nName=q*\n[Network]\nIPForward=kernel\n", hostForwarding{}, nil, ""},
		{"systemd 256 forwarding", "[Match]\nName=q*\n[Network]\nIPv6Forwarding=yes\n", hostForwarding{}, nil, "q"},
		{"continued and commented lines", "[Match]\nKind=veth \\\n# a comment inside\n  netkit\nName=c*\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, "c"},
		{"an invalid section header refuses the file", "[Match\nName=*\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, ""},
		{"a bracket pattern", "[Match]\nName=br[0-9]-[!a]\n[Network]\nIPForward=yes\n", hostForwarding{}, nil, "br0-"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The stock veth files masked, so only the site file is judged.
			root := netRoot(t, map[string]string{"etc/systemd/network/20-site.network": c.file})
			mask(t, root, "etc/systemd/network/80-container-ve.network")
			mask(t, root, "etc/systemd/network/80-container-vb.network")
			taken := stockTaken
			if c.taken != nil {
				taken = c.taken
			}
			p, ok := pathIn(t, root, taken, stockHost, c.fwd)
			if c.want == "" {
				if ok {
					t.Fatalf("path through %s for a %s named %q (%s)", p.file.path, p.device.kind, p.device.name, p.how)
				}
				return
			}
			if !ok {
				t.Fatal("no path")
			}
			if p.file.path != "/etc/systemd/network/20-site.network" {
				t.Fatalf("path through %s, not the site file", p.file.path)
			}
			if !strings.HasPrefix(p.device.name, c.want) && p.device.kind != c.want && p.device.mac != c.want {
				t.Fatalf("the device is a %s named %q with %s; want %q", p.device.kind, p.device.name, p.device.mac, c.want)
			}
		})
	}
}

func TestFnmatchIsGlibcs(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"ve-*", "ve-x", true},
		{"ve-*", "ve-", true},
		{"ve-*", "vex", false},
		{"*", "", true},
		{"?", "", false},
		{"a?c", "abc", true},
		{"*/*", "a/b", true}, // no FNM_PATHNAME: a star crosses a slash
		{"[abc]x", "bx", true},
		{"[!abc]x", "bx", false},
		{"[^abc]x", "dx", true},
		{"[a-c]", "b", true},
		{"[a-c]", "d", false},
		{"[]a]", "]", true},
		{"[!]a]", "]", false},
		{"[[:digit:]]*", "0eth", true},
		{"[[:digit:]]*", "eth0", false},
		{"[[:alpha:]-]", "-", true},
		{"\\*", "*", true},
		{"\\*", "a", false},
		{"[", "[", true},
		{"[ab", "[ab", true},
		{"a\\", "a\\", false}, // glibc: "Trailing \\ loses"
		{"a\\", "a", false},
		{"*", ".hidden", true},
		{"/devices/virtual/*", "/devices/virtual/net/ve-x", true},
		{"[[:nosuch:]]", "a", false},
		{"[a-]", "-", true},
		{"[!a-c]", "-", true},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"*x*", "abc", false},
		{"[a\\]]", "]", true},
	}
	for _, c := range cases {
		if got := fnmatch(c.pattern, c.s); got != c.want {
			t.Errorf("fnmatch(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestNetworkdParsesValuesAsSystemdDoes(t *testing.T) {
	f := networkFile{conds: map[string]netCond{}}
	if err := parseNetworkUnit(&f, "\ufeff[Match]\nName=a \"b c\" d\\ e d\\x\nKind=\"ve th\"\nProperty=FOO=bar !BAD 1X=y Z=\"q r\"\n"+
		"MACAddress=00-16-3E-AA-BB-CC 0016.3eaa.bbcd nonsense\nHost=\nHost=!h\n[Other]\nName=ignored\n"); err != nil {
		t.Fatal(err)
	}
	// Name= takes no quoting: quotes stay, a backslash takes the next character, and a word with a space in it is
	// not a name (networkd drops it); Kind= unquotes.
	if got := strings.Join(f.names, "|"); got != `a|"b|c"|dx` {
		t.Errorf("names %q", got)
	}
	if got := strings.Join(f.kinds, "|"); got != "ve th" {
		t.Errorf("kinds %q", got)
	}
	if got := strings.Join(f.props, "|"); got != "FOO=bar|Z=q r" {
		t.Errorf("properties %q", got)
	}
	if got := strings.Join(f.hwAddrs, "|"); got != "00:16:3e:aa:bb:cc|00:16:3e:aa:bb:cd" {
		t.Errorf("addresses %q", got)
	}
	if c, ok := f.conds["Host"]; !ok || c.value != "h" || !c.negate {
		t.Errorf("Host %+v", c)
	}
	for _, w := range []string{"", ".", "..", "all", "default", "123", "a:b", "a/b", "a%d", "a b"} {
		if ifnameValid(w) {
			t.Errorf("%q passed as an interface name", w)
		}
	}
	for _, w := range []string{"ve-*", "!eth0", "1a", "x"} {
		if !ifnameValid(w) {
			t.Errorf("%q refused as an interface name", w)
		}
	}
}

// The name search is exact: over many small random configurations it finds a device whenever brute force over
// short names does, and every device it finds is one networkd would take with the file it names. Patterns are
// built from a, b, - and x, and brute force tries names of up to four bytes over those and c, which no pattern
// names and so stands for every byte no pattern names; the search tries every length up to the kernel's.
func TestTheNameSearchAgreesWithBruteForce(t *testing.T) {
	rng := rand.New(rand.NewPCG(2683, 413))
	atoms := []string{"a", "b", "-", "*", "?", "[ab]", "[!a]", "x"}
	pattern := func() string {
		var b strings.Builder
		for n := 1 + rng.IntN(3); n > 0; n-- {
			b.WriteString(atoms[rng.IntN(len(atoms))])
		}
		return b.String()
	}
	var short []string
	var grow func(prefix string)
	grow = func(prefix string) {
		if prefix != "" {
			short = append(short, prefix)
		}
		if len(prefix) < 4 {
			for _, c := range "ab-xc" {
				grow(prefix + string(c))
			}
		}
	}
	grow("")
	k := placeKinds[0]
	for iter := 0; iter < 600; iter++ {
		var files []networkFile
		for n := 1 + rng.IntN(4); n > 0; n-- {
			f := networkFile{path: fmt.Sprintf("/f%d", len(files)), conds: map[string]netCond{}}
			for w := 1 + rng.IntN(2); w > 0; w-- {
				p := pattern()
				if rng.IntN(3) == 0 {
					p = "!" + p
				}
				f.names = append(f.names, p)
			}
			if rng.IntN(2) == 0 {
				f.ipForward = "yes"
			} else {
				f.unmanaged = rng.IntN(2) == 0
			}
			files = append(files, f)
		}
		taken := map[string]bool{}
		for n := rng.IntN(3); n > 0; n-- {
			taken[short[rng.IntN(len(short))]] = true
		}
		first := func(name string) int {
			for i := range files {
				if files[i].constMatch(k, "02:00:00:00:00:01", stockHost) == triTrue && files[i].nameMatch(name) {
					return i
				}
			}
			return -1
		}
		brute := -1
		for _, n := range short {
			if taken[n] {
				continue
			}
			if i := first(n); i >= 0 && files[i].how(hostForwarding{}, false) != "" && (brute < 0 || i < brute) {
				brute = i
			}
		}
		p, ok := firstPath(findPlacedPaths(files, taken, stockHost, hostForwarding{}, false, []placeKind{k}))
		if ok {
			i := first(p.device.name)
			if taken[p.device.name] || !kernelNameValid(p.device.name) || i < 0 || files[i].path != p.file.path || files[i].how(hostForwarding{}, false) == "" {
				t.Fatalf("config %d: the search found %q through %s, which networkd would not take that way (first match %d)\n%s",
					iter, p.device.name, p.file.path, i, describeConfig(files, taken))
			}
		}
		if brute >= 0 && (!ok || p.file.path != files[brute].path) {
			t.Fatalf("config %d: brute force reaches %s, the search says %v %q\n%s", iter, files[brute].path, ok, p.file.path,
				describeConfig(files, taken))
		}
	}
}

func describeConfig(files []networkFile, taken map[string]bool) string {
	var b strings.Builder
	for _, f := range files {
		fmt.Fprintf(&b, "  %s Name=%s forward=%q unmanaged=%v\n", f.path, strings.Join(f.names, " "), f.ipForward, f.unmanaged)
	}
	fmt.Fprintf(&b, "  taken %v", taken)
	return b.String()
}

// On the host a device networkd keeps up is a way out by itself, since forwarding is turned on for the whole host by
// so much else; in a container it is one only if that container forwards, or a placed device can make it forward.
func TestUpIsEnoughOnTheHostOnly(t *testing.T) {
	root := netRoot(t, nil)
	mask(t, root, "etc/systemd/network/80-container-ve.network")
	files, err := loadNetworkFiles(networkdReader{root: root})
	if err != nil {
		t.Fatal(err)
	}
	host, ok := firstPath(findPlacedPaths(files, stockTaken, stockHost, hostForwarding{}, true, placeKinds))
	if !ok || !strings.HasSuffix(host.file.path, "80-container-vb.network") || !strings.Contains(host.how, "bring it up") {
		t.Fatalf("on the host: %v %s %q", ok, host.file.path, host.how)
	}
	if p, ok := firstPath(findPlacedPaths(files, stockTaken, stockHost, hostForwarding{}, false, placeKinds)); ok {
		t.Fatalf("in a container that does not forward: path through %s", p.file.path)
	}
	// A container whose stock files are all there: a placed ve-* device turns forwarding on (IPMasquerade=both),
	// for the next device too.
	all, err := loadNetworkFiles(networkdReader{root: netRoot(t, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if !placedCanForward(all, map[string]bool{"lo": true}, hostFacts{container: "lxc"}, placeKinds) {
		t.Fatal("a placed ve-* device would turn forwarding on, and that was missed")
	}
	if placedCanForward(files, map[string]bool{"lo": true}, hostFacts{container: "lxc"}, placeKinds) {
		t.Fatal("with 80-container-ve masked nothing a placed device matches turns forwarding on")
	}
}

// Inside a container networkd judges Virtualization= as the container it is: the stock host0 file applies there.
func TestAContainersNetworkdJudgesItsOwnVirtualization(t *testing.T) {
	root := netRoot(t, nil)
	files, err := loadNetworkFiles(networkdReader{root: root})
	if err != nil {
		t.Fatal(err)
	}
	d := placedDevice{placeKind: placeKinds[0], name: "host0", mac: "02:00:00:00:00:01"}
	var host0 *networkFile
	for i := range files {
		if strings.HasSuffix(files[i].path, "80-container-host0.network") {
			host0 = &files[i]
		}
	}
	if host0 == nil {
		t.Fatal("no host0 file")
	}
	if host0.constMatch(d.placeKind, d.mac, stockHost) != triFalse {
		t.Fatal("the host0 file matched on the host")
	}
	for _, kind := range []string{"lxc", "systemd-nspawn", "container-other"} {
		if host0.constMatch(d.placeKind, d.mac, hostFacts{container: kind}) != triTrue {
			t.Fatalf("the host0 file did not match in a %s container", kind)
		}
	}
	for _, c := range []struct {
		value, container string
		want             tri
	}{{"lxc", "lxc", triTrue}, {"docker", "lxc", triFalse}, {"vm", "lxc", triFalse}, {"kvm", "lxc", triFalse},
		{"yes", "lxc", triTrue}, {"no", "lxc", triFalse}, {"no", "", triUnknown}, {"vm", "", triUnknown},
		{"private-users", "lxc", triUnknown}} {
		if got := condHolds("Virtualization", netCond{value: c.value}, hostFacts{container: c.container}); got != c.want {
			t.Errorf("Virtualization=%s in %q: %v, want %v", c.value, c.container, got, c.want)
		}
	}
}

// A condition that cannot be judged here never hides a way out: a file that would close it is taken not to match,
// one that would open it is taken to.
func TestAConditionThatCannotBeJudgedRefusesBothWays(t *testing.T) {
	for _, cond := range []string{"KernelVersion=>=7.0", "Credential=x", "Firmware=device-tree", "Virtualization=vm",
		"Property=SITE_SET=yes"} {
		t.Run(cond, func(t *testing.T) {
			root := netRoot(t, map[string]string{"etc/systemd/network/05-closing.network": "[Match]\nKind=veth netkit\n" + cond +
				"\n[Link]\nUnmanaged=yes\n"})
			if _, ok := pathIn(t, root, stockTaken, stockHost, hostForwarding{}); !ok {
				t.Fatal("a closing file whose condition cannot be judged hid the stock file")
			}
			root = netRoot(t, map[string]string{"etc/systemd/network/05-opening.network": "[Match]\nKind=veth\nName=zz*\n" + cond +
				"\n[Network]\nIPMasquerade=both\n"})
			mask(t, root, "etc/systemd/network/80-container-ve.network")
			mask(t, root, "etc/systemd/network/80-container-vb.network")
			if p, ok := pathIn(t, root, stockTaken, stockHost, hostForwarding{}); !ok || !strings.HasSuffix(p.file.path, "05-opening.network") {
				t.Fatalf("an opening file whose condition cannot be judged was not taken to match: %v %s", ok, p.file.path)
			}
		})
	}
}

func TestAFileSystemdCannotParseIsLeftOut(t *testing.T) {
	for name, body := range map[string]string{
		"not UTF-8":        "[Match]\nKind=veth\nName=\xff\xfe\n[Link]\nUnmanaged=yes\n",
		"unsafe header":    "[Ma\"tch]\nKind=veth\n[Link]\nUnmanaged=yes\n",
		"line over 1 MiB":  "[Match]\nKind=veth\nName=" + strings.Repeat("x", 1<<20) + "\n[Link]\nUnmanaged=yes\n",
		"unclosed section": "[Match\nKind=veth\n[Link]\nUnmanaged=yes\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := netRoot(t, map[string]string{"etc/systemd/network/05-bad.network": body})
			if _, ok := pathIn(t, root, stockTaken, stockHost, hostForwarding{}); !ok {
				t.Fatal("a file networkd refuses hid the stock file")
			}
		})
	}
}

// The refusal names each networkd, each file and device, and gives the fix for each, every command on a line of its
// own: on the host the one file that sorts first (written readable whatever the umask), masks and edits for what sorts
// before it, and the restart last, only for a networkd that runs, with what the restart costs; in a container one
// command entered through the container's init, whose mounts are writable where networkd's are not.
func TestTheRefusalNamesEveryWayOutAndItsFix(t *testing.T) {
	ve := networkFile{path: "/usr/lib/systemd/network/80-container-ve.network", ipMasquerade: "both"}
	early := networkFile{path: "/usr/lib/systemd/network/00-early.network"}
	site := networkFile{path: "/etc/systemd/network/00-site.network", dropins: []string{"/etc/systemd/network/00-site.network.d/x.conf"}}
	dev := placedDevice{placeKind: placeKinds[0], name: "ve-x", mac: "02:00:00:00:00:01"}
	msg := placedRefusal(4242, "agent", []placedFinding{
		{where: "in this host's namespace", why: "where it runs as pid 848", host: true, running: true, pid: 848,
			paths:    []placedPath{{file: ve, device: dev, how: ve.passesOn()}},
			leftover: []placedPath{{file: early, device: dev}, {file: site, device: dev}},
			inUse:    map[string][]string{ve.path: {"ve-web"}}, foreign: []string{"5210", "5230"}},
		{where: "in the container web1 (networkd pid 4300)", why: "where it runs as pid 4300", pid: 4300, container: "web1",
			initPid: 4100, running: true, paths: []placedPath{{file: ve, device: dev, how: ve.passesOn()}}},
	}, "this kernel allowed exactly that for a veth in a test just now")
	for _, want := range []string{
		"pid 4242 (agent) was not contained",
		"in this host's namespace, where it runs as pid 848: /usr/lib/systemd/network/80-container-ve.network takes one named \"ve-x\" and would masquerade",
		"(it configures ve-web now)",
		"in the container web1 (networkd pid 4300)",
		"mask /usr/lib/systemd/network/00-early.network, which sorts before it, change /etc/systemd/network/00-site.network, which sorts before it too",
		"Kind=!*",
		"\n    printf '[Match]\\nDriver=veth netkit\\n\\n[Link]\\nUnmanaged=yes\\n' | sudo install -D -m 0644 /dev/stdin /etc/systemd/network/" + unmanagedFixFile +
			"\n    sudo ln -s /dev/null /etc/systemd/network/00-early.network\n    sudo systemctl restart systemd-networkd\n",
		"--network-veth, --network-zone or --network-bridge, netplan's virtual-ethernets",
		"ManageForeignRoutingPolicyRules=", "the rules at priority 5210, 5230", "run it from a console",
		"In the container web1, whose init is pid 4100 here, then run:\n    sudo nsenter -t 4100 -a -- sh -c 'mkdir -p /etc/systemd/network && " +
			"ln -s /dev/null /etc/systemd/network/80-container-ve.network && systemctl restart systemd-networkd'",
		"A container started after this check is not judged",
		"7b735ef81286",
		"A firewall's forward policy is not counted",
		"Then run `sudo whisper contain 4242` again",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "\u2014") || strings.Contains(msg, "ln -sf") || strings.Contains(msg, "tee ") {
		t.Error("the refusal has an em dash, a forced link, or a tee that would write the file with the umask")
	}
	notRunning := placedRefusal(1, "x", []placedFinding{{where: "in this host's namespace", why: "where it does not run",
		host: true, paths: []placedPath{{file: ve, device: dev, how: "x"}}}}, "p")
	if strings.Contains(notRunning, "restart") || strings.Contains(notRunning, "ManageForeign") {
		t.Error("the fix restarts a networkd that does not run, which would start it")
	}
	keeps := placedRefusal(1, "x", []placedFinding{{where: "h", why: "w", host: true, running: true, keeps: true,
		paths: []placedPath{{file: ve, device: dev, how: "x"}}}}, "p")
	if strings.Contains(keeps, "ManageForeign") {
		t.Error("the restart's cost was said for a networkd.conf that turns both deletions off")
	}
	stale := placedRefusal(1, "x", []placedFinding{{where: "in this host's namespace", why: "where it runs as pid 848",
		host: true, running: true, pid: 848, unknown: true, staleOnly: true,
		stale: []string{"/etc/systemd/network/80-container-ve.network", "/etc/systemd/network"}}}, "p")
	if !strings.Contains(stale, "changed, so what it holds may not be what is on disk") ||
		!strings.Contains(stale, "\n    sudo systemctl restart systemd-networkd\n") || strings.Contains(stale, unmanagedFixFile) {
		t.Errorf("a refusal for what networkd may still hold:\n%s", stale)
	}
	// A file name read from a root a container tenant or the process controls is one word in every command, and
	// prints without escapes.
	evil := "/usr/lib/systemd/network/00-$(curl a|sh)'x.network"
	hostile := placedRefusal(1, "x", []placedFinding{
		{where: "h", why: "w", host: true, running: true, paths: []placedPath{{file: ve, device: dev, how: "x"}},
			leftover: []placedPath{{file: networkFile{path: evil}}}},
		{where: "c", why: "w", container: "c1", initPid: 7, running: true,
			paths: []placedPath{{file: networkFile{path: evil}, how: "x"}}},
	}, "p")
	hostMask := "sudo ln -s /dev/null " + shellWord("/etc/systemd/network/"+filepath.Base(evil))
	inner := "mkdir -p /etc/systemd/network && ln -s /dev/null " + shellWord("/etc/systemd/network/"+filepath.Base(evil)) +
		" && systemctl restart systemd-networkd"
	for _, want := range []string{hostMask, "sudo nsenter -t 7 -a -- sh -c " + shellWord(inner)} {
		if !strings.Contains(hostile, want) {
			t.Errorf("a hostile file name was not quoted as one word: want %q in\n%s", want, hostile)
		}
	}
	escaped := placedRefusal(1, "x", []placedFinding{{where: "h", why: "w", host: true, running: true,
		paths:    []placedPath{{file: networkFile{path: "/etc/x\x1b[2J.network"}, device: placedDevice{name: "v\x1bx"}, how: "x"}},
		leftover: []placedPath{{file: networkFile{path: "/usr/lib/systemd/network/00-\x1b[2J.network"}}}}}, "p")
	if strings.Contains(escaped, "\x1b") || !strings.Contains(escaped, `00-\x1b[2J.network`) {
		t.Errorf("a name carried an escape sequence into the refusal, or was not shown:\n%s", escaped)
	}
	for _, s := range []string{"plain", "", "a b", "it's", "$(x)", "'", "a'b'c", "`x`", ";{curl,a}|sh"} {
		if got := unquoteShell(t, shellWord(s)); got != s {
			t.Errorf("shellWord(%q) = %s reads back as %q", s, shellWord(s), got)
		}
	}
	unread := placedRefusal(1, "x", []placedFinding{{where: "h", why: "w", host: true, running: true, unread: true,
		paths: []placedPath{{file: ve, device: dev, how: "x"}}}}, "p")
	if !strings.Contains(unread, "networkd's own user cannot read it") {
		t.Errorf("a fix file networkd cannot read was not named:\n%s", unread)
	}
}

// A key the running networkd does not know yet is ignored, as networkd ignores it: on systemd 249 a [Match] that has
// only Kind= is empty, and the file is not loaded at all, which is why the fix matches on Driver=.
func TestAKeyTheRunningNetworkdDoesNotKnowIsIgnored(t *testing.T) {
	kindOnly := "[Match]\nKind=veth netkit\n[Link]\nUnmanaged=yes\n"
	for _, c := range []struct {
		version int
		closed  bool
	}{{255, true}, {251, true}, {249, false}, {0, true}} {
		root := netRoot(t, map[string]string{"etc/systemd/network/00-kind.network": kindOnly})
		files, err := loadNetworkFiles(networkdReader{root: root, version: c.version})
		if err != nil {
			t.Fatal(err)
		}
		_, open := firstPath(findPlacedPaths(files, stockTaken, stockHost, hostForwarding{}, true, placeKinds))
		if open == c.closed {
			t.Errorf("networkd %d: a Kind= file closes it: %v, want %v", c.version, !open, c.closed)
		}
	}
	root := netRoot(t, map[string]string{"etc/systemd/network/" + unmanagedFixFile: "[Match]\nDriver=veth netkit\n\n[Link]\nUnmanaged=yes\n"})
	for _, v := range []int{239, 249, 255, 0} {
		files, err := loadNetworkFiles(networkdReader{root: root, version: v})
		if err != nil {
			t.Fatal(err)
		}
		if p, open := firstPath(findPlacedPaths(files, stockTaken, stockHost, hostForwarding{}, true, placeKinds)); open {
			t.Errorf("networkd %d: the fix file left %s open", v, p.file.path)
		}
	}
	f := networkFile{conds: map[string]netCond{}, version: 247}
	f.assign("Network", "IPMasquerade", "both")
	f.assign("Link", "ActivationPolicy", "down")
	if f.ipMasquerade != "" || f.activation != "" {
		t.Errorf("networkd 247 took IPMasquerade=both or ActivationPolicy=: %q %q", f.ipMasquerade, f.activation)
	}
}

func TestTheRunningNetworkdsReleaseIsReadFromItsLibrary(t *testing.T) {
	for _, c := range []struct {
		lines []string
		want  int
	}{
		{[]string{"7f00-7f01 r-xp 0 08:01 1 /usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-255.so"}, 255},
		{[]string{"a /usr/lib64/systemd/libsystemd-shared-256.11-1.fc41.so", "b /usr/lib64/systemd/libsystemd-shared-256.11-1.fc41.so"}, 256},
		{[]string{"a libsystemd-shared-249.so", "b libsystemd-shared-255.so"}, 0},
		{[]string{"/usr/lib/libc.so.6"}, 0},
	} {
		if got := sharedVersion(c.lines); got != c.want {
			t.Errorf("%v: %d, want %d", c.lines, got, c.want)
		}
	}
}

// The fix file closes every way the stock files open, and what sorts before it is left for its own fix.
func TestTheOneFileFixClosesTheStockFiles(t *testing.T) {
	files, err := loadNetworkFiles(networkdReader{root: netRoot(t, map[string]string{
		"etc/systemd/network/00-aaa.network": "[Match]\nName=aa*\n[Network]\nDHCP=yes\n"})})
	if err != nil {
		t.Fatal(err)
	}
	left := findPlacedPaths(withUnmanagedFirst(files), stockTaken, stockHost, hostForwarding{}, true, placeKinds)
	if len(left) != 1 || left[0].file.path != "/etc/systemd/network/00-aaa.network" {
		var got []string
		for _, p := range left {
			got = append(got, p.file.path)
		}
		t.Fatalf("with the fix in place, still open: %v", got)
	}
}

// Enslaving a placed device passes what it sends on at the link layer, without any forwarding.
func TestEnslavementLetsADeviceOut(t *testing.T) {
	for _, key := range []string{"Bridge", "Bond", "VRF", "BatmanAdvanced"} {
		f := networkFile{conds: map[string]netCond{}}
		f.assign("Network", key, "x0")
		if h := f.how(hostForwarding{}, false); !strings.Contains(h, key+"=x0") {
			t.Errorf("%s=: %q", key, h)
		}
		f.assign("Network", key, "")
		if h := f.how(hostForwarding{}, false); h != "" {
			t.Errorf("%s= emptied still lets it out: %q", key, h)
		}
	}
}

// unquoteShell reads back one word as a POSIX shell reads it, for the quoting shellWord writes: plain characters,
// single-quoted runs, and a backslash-escaped character.
func unquoteShell(t *testing.T, w string) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < len(w); i++ {
		switch w[i] {
		case '\'':
			j := strings.IndexByte(w[i+1:], '\'')
			if j < 0 {
				t.Fatalf("unclosed quote in %s", w)
			}
			b.WriteString(w[i+1 : i+1+j])
			i += j + 1
		case '\\':
			i++
			b.WriteByte(w[i])
		case ' ', '\t', '$', '`', ';', '|', '&', '(', ')', '<', '>', '"':
			t.Fatalf("an unquoted %q in %s", w[i], w)
		default:
			b.WriteByte(w[i])
		}
	}
	return b.String()
}

// A configuration whose patterns would take the search minutes and gigabytes is not searched to the end: the search
// stops at its bound, in the direction that refuses, and says so.
func TestASearchTooLargeIsTakenToFindAName(t *testing.T) {
	avoid := networkFile{names: []string{"x*", "*a????????????", "*b????????????", "*c????????????"}, unmanaged: true, conds: map[string]netCond{}}
	bad := networkFile{path: "/etc/systemd/network/50-x.network", names: []string{"x*"}, ipMasquerade: "both", conds: map[string]netCond{}}
	start := time.Now()
	paths := findPlacedPaths([]networkFile{avoid, bad}, map[string]bool{}, stockHost, hostForwarding{}, false, placeKinds[:1])
	if took := time.Since(start); took > 20*time.Second {
		t.Fatalf("the search took %s", took)
	}
	if len(paths) != 1 || paths[0].device.name != "" {
		t.Fatalf("a search past its bound found %v", paths)
	}
	msg := placedRefusal(1, "x", []placedFinding{{where: "h", why: "w", host: true, paths: paths}}, "p")
	if !strings.Contains(msg, "patterns too many to search") {
		t.Errorf("the refusal does not say the search stopped:\n%s", msg)
	}
}

// Property= decodes C escapes, and a word systemd cannot parse ends the value with the words before it kept: a bad
// escape there, an unclosed quote in any unquoted list.
func TestAWordSystemdCannotParseEndsTheValue(t *testing.T) {
	f := networkFile{conds: map[string]netCond{}}
	f.assign("Match", "Property", `A=\x41 B="b c" C=\q D=d`)
	if got := strings.Join(f.props, "|"); got != "A=A|B=b c" {
		t.Errorf("properties %q", got)
	}
	f.assign("Match", "Kind", `veth "netkit`)
	if got := strings.Join(f.kinds, "|"); got != "veth" {
		t.Errorf("kinds %q", got)
	}
}
