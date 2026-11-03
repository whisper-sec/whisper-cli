// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// The birth pin rests on knowing the agent was just born. op:identity is idempotent: on a key
// that already holds a /128 it hands that one back, and a host that then publishes its own key there
// would move the TLSA, SSHFP and OPENPGPKEY another host serves. The service now answers `created`, and
// these drive the real run command against the fake plane through all three of its answers.

func identityAnswer(created string) string {
	cols := `"label","address","fqdn"`
	cells := `"own","` + pickOwnAddr + `","own.agents.whisper.online."`
	if created != "" {
		cols += `,"created"`
		cells = `"own","` + pickOwnAddr + `","own.agents.whisper.online.",` + created
	}
	return `{"ok":true,"status":200,"result":{"columns":[` + cols + `],"rows":[[` + cells + `]]}}`
}

func runOnEmptyAccount(t *testing.T, identityReply string) (connects []string, stderr string) {
	t.Helper()
	pickHarness(t)
	clearNewborn(t)
	stubPins(t, nil)
	p := &pickPlane{identityReply: identityReply}
	srv := p.serve(t)
	stderr, err := runRoot(t, srv.URL, "run", "--agent-file", filepath.Join(t.TempDir(), "a"), "--tier", "wireguard", "--", "true")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	return p.bodies("connect"), stderr
}

func TestAnIdentityTheServiceSaysItCreatedIsBornWithThisHostsKey(t *testing.T) {
	c, _ := runOnEmptyAccount(t, identityAnswer("true"))
	if len(c) != 1 || !strings.Contains(c[0], "adopt_identity_key:true") || !spkiArgRE.MatchString(c[0]) {
		t.Fatalf("created:true is a birth, so the first routed connect publishes this host's key: %v", c)
	}
}

func TestAnIdentityTheServiceSaysItReusedIsNeverRePinned(t *testing.T) {
	c, stderr := runOnEmptyAccount(t, identityAnswer("false"))
	if len(c) != 1 {
		t.Fatalf("the reused agent still connects, once: %v", c)
	}
	if strings.Contains(c[0], "adopt_identity_key") || spkiArgRE.MatchString(c[0]) {
		t.Fatalf("created:false is not a birth, even though the listing before the call was empty: %s", c[0])
	}
	if !strings.Contains(stderr, "reusing existing agent") {
		t.Fatalf("a reuse the service names is said, not reported as a create: %s", stderr)
	}
}

func TestAnOlderServiceIsJudgedByTheSnapshotAsBefore(t *testing.T) {
	// No `created` column: the listing before the call answered and did not hold the address, so it is a birth.
	c, _ := runOnEmptyAccount(t, identityAnswer(""))
	if len(c) != 1 || !strings.Contains(c[0], "adopt_identity_key:true") {
		t.Fatalf("an older service's fresh identity keeps the birth pin it had: %v", c)
	}
}

func TestIdentityOutcomeTrustsTheColumnOverTheSnapshot(t *testing.T) {
	cases := []struct {
		name         string
		created      string
		pre          map[string]string
		reused, born bool
	}{
		{"created true, snapshot says seen", "true", map[string]string{pickOwnAddr: "own"}, false, true},
		{"created false, snapshot empty", "false", map[string]string{}, true, false},
		{"no column, snapshot empty", "", map[string]string{}, false, true},
		{"no column, snapshot holds it", "", map[string]string{pickOwnAddr: "own"}, true, false},
		{"no column, no snapshot proves nothing", "", nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := &client.Result{Columns: []string{"label", "address"}, Rows: [][]any{{"own", pickOwnAddr}}}
			if tc.created != "" {
				res.Columns = append(res.Columns, "created")
				res.Rows[0] = append(res.Rows[0], tc.created == "true")
			}
			env := &client.Envelope{Ok: true, Status: 200, Result: res}
			reused, born := identityOutcome(env, tc.pre, pickOwnAddr)
			if reused != tc.reused || born != tc.born {
				t.Fatalf("got reused=%v born=%v, want %v %v", reused, born, tc.reused, tc.born)
			}
		})
	}
}
