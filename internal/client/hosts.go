// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

// DefaultReportFallbackBases are the public Whisper hosts a client falls back to, in order.
// They are the active/active pair the monitor stream rides: both answer identically, so the
// first reachable one wins and there is nothing to choose between them.
var DefaultReportFallbackBases = []string{
	"https://ns1.whisper.online",
	"https://ns2.whisper.online",
}
