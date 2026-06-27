// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package projcfg

import "encoding/json"

// endpoint.go, in a build that has no endpoint half.
//
// The `whisper` binaries Whisper publishes also carry an endpoint sensor, and that sensor
// reads four sections of this config document: sensor, enforce, response and respond. This
// build has no sensor in it and does not interpret any of them.
//
// It must not silently DROP them either. The config file belongs to the project, not to one
// binary, and a host can have both this build and a released one. A client that rewrote the
// file without those sections would quietly disarm whatever an operator had configured, and
// would do it during an unrelated command. So they are carried verbatim: read in, written
// back out, byte for byte.
//
// config.go declares the four fields and reads none of them. This file only gives them a
// type, which is the whole of the difference between the two builds.
type (
	SensorConfig   = json.RawMessage
	EnforceConfig  = json.RawMessage
	ResponseConfig = json.RawMessage
	RespondConfig  = json.RawMessage
)
