// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build darwin

package cli

// sshAuthzLoggerPath is logger(1) on every macOS install; an absolute path, so the
// AuthorizedKeysCommand's PATH, whatever sshd gives it, plays no part.
const sshAuthzLoggerPath = "/usr/bin/logger"

// sshAuthzSystemLog writes the decision to the unified log through logger(1). macOS 15
// accepts a syslog datagram on /var/run/syslog and then drops it, so Go's log/syslog left the
// decision nowhere: not in `log show`, not in /var/log/system.log. logger(1) goes through
// os_log, and its line reads back with
//
//	log show --last 10m --predicate 'eventMessage CONTAINS "whisper-ssh-authz"'
//
// Exec rather than cgo keeps the binary pure Go and cross-compiled like every other platform.
func sshAuthzSystemLog(_ bool, msg string) {
	_ = runSSHAuthzLogger(sshAuthzLoggerPath, sshAuthzLoggerArgs(msg))
}
