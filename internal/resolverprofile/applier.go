// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package resolverprofile

// Applier executes a rendered plan on THIS machine. One implementation per GOOS,
// self-registered from its build-tagged file (apply_linux.go registers "linux",
// apply_windows.go "windows", apply_darwin.go "darwin") - the registry is the
// seam, so adding an OS never touches shared code.
type Applier interface {
	// DetectHost returns the real facts about this machine (forwarder on PATH,
	// systemd-resolved active, elevation) for an accurate render. It never needs
	// privileges.
	DetectHost() Host
	// Apply executes r.Apply in order. Returns ErrNeedsRoot (wrapped) when the
	// plan mutates system state and the process is not privileged - the caller
	// then prints the exact block instead.
	Apply(r Rendered) error
	// Revert executes r.Revert in order; guards make it idempotent (safe twice,
	// safe when nothing was ever applied).
	Revert(r Rendered) error
}

var appliers = map[string]Applier{}

// Register wires the applier for one GOOS (called from build-tagged init funcs).
func Register(goos string, a Applier) { appliers[goos] = a }

// For returns the applier registered for goos, if any. A missing applier is not
// an error path: the caller falls back to printing the exact plan (Postel - the
// user always gets a working next step).
func For(goos string) (Applier, bool) {
	a, ok := appliers[goos]
	return a, ok
}
