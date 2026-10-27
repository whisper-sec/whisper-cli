// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"os"
	"testing"
)

// TestMain clears the opt-in a developer may have exported, so no test of the name service reads
// this machine's shell: with WHISPER_RESOLVE_ON_HOST=1 set, names would resolve on the host and
// every "names stay in the tunnel" assertion would fail for a reason that is not the code's.
func TestMain(m *testing.M) {
	_ = os.Unsetenv(ResolveOnHostEnv)
	os.Exit(m.Run())
}
