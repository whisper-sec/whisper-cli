// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import "os"

// geteuidFn is the seam tests stub for "this process is root". On Windows it is -1.
var geteuidFn = os.Geteuid
