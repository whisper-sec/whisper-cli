// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package projcfg

import "encoding/json"

// endpoint.go carries configuration sections this library does not interpret.
//
// A project config may be written by a tool that understands more sections than this one
// does. json.RawMessage holds those bytes as they arrived and writes them back unchanged,
// so a round trip here never discards a section it did not understand, whatever shape a
// later release gives it. config.go declares the fields and reads none of them.
type (
	SensorConfig   = json.RawMessage
	EnforceConfig  = json.RawMessage
	ResponseConfig = json.RawMessage
	RespondConfig  = json.RawMessage
)
