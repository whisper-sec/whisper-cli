// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !unix && !windows

package testenv

import "syscall"

// hold has no sockets to bind here; RefusedPort and NumberedPort skip the test.
func hold(bool, bool, int) (int, func(), error) { return 0, nil, errUnsupported }

func inUse(error) bool { return false }

func noIPv6(error) bool { return false }

// canHold is false: RefusedPort and NumberedPort skip the test here.
const canHold = false

const dualStackHold = false

func connRefused(error) bool { return false }

var exclusiveUse func(network, address string, c syscall.RawConn) error
