// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !windows && !darwin

package cli

import "log/syslog"

// sshAuthzSystemLog sends the decision to the local syslog as an auth-facility datagram, which
// journald and rsyslog both read from /dev/log. A DENY is notice, an ADMIT is info.
func sshAuthzSystemLog(admit bool, msg string) {
	prio := syslog.LOG_AUTH | syslog.LOG_NOTICE
	if admit {
		prio = syslog.LOG_AUTH | syslog.LOG_INFO
	}
	if w, err := syslog.New(prio, sshAuthzTag); err == nil {
		_, _ = w.Write([]byte(msg)) // Write keeps the severity chosen above; Notice would override it
		_ = w.Close()
	}
}
