// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"path/filepath"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// enroll_identity_target.go answers one question for every verb that writes a host's
// identity: where does the installed host service read it, and can this process write
// there?
//
// The three platforms split the same way and settle it in different places:
//
//   - Linux and macOS: the unit is pinned to the HOME of the shell that installed it.
//     Under a sudo that resets HOME, the Ubuntu default, that is /root, and a plain
//     user's enroll used to write ~/.config/whisper/bound, which the root sensor never
//     reads, and say nothing. The unix half reads the unit's HOME and account
//     from its registration (`systemctl show`, the launchd plist), which any account
//     may read, and compares it with this process's home. A process that owns that
//     home binds there; any other refuses and names the sudo line that reaches it.
//     Root never writes into a home a user owns: that is a link a user can plant.
//   - Windows: the service runs as LocalSystem and reads %USERPROFILE% of that
//     account, the SYSTEM profile. An administrator's elevated PowerShell is their own
//     account, so a bind run there used to land in their profile, where the sensor
//     never looks, and nothing said so. There is no built-in way to open a SYSTEM
//     shell, but an elevated one CAN write the SYSTEM profile (it grants SYSTEM and
//     Administrators full control), so the bind goes there.
//
// The rule on every platform is the same sentence: the bind lands where the host
// service reads it, or the command refuses and names the one that does. It never
// writes silently to a place the service cannot see.

// serviceIdentityContext is what the platform half found.
type serviceIdentityContext struct {
	// Installed is true when a host service that reads this machine's identity is
	// installed. False means "no split": the verb writes where it always has.
	Installed bool
	// Service is the service that decided it, for the messages.
	Service string
	// Account is the account it runs as ("LocalSystem", "root").
	Account string
	// Dir is the directory the service reads its key, agent and marker from.
	Dir string
	// Self is true when this process already runs as that account, so the ordinary
	// per-account paths ARE the service's. The Intune install runs as SYSTEM.
	Self bool
	// Elevated is true when this process can write Dir. On unix that means this
	// process's uid owns the directory chain; root holding a user's home is not.
	Elevated bool
	// CanRead is true when this process can read Dir, so a readiness check may judge
	// what the service sees. False is "cannot tell from here", never "missing".
	CanRead bool
	// Reach is the command prefix that runs a verb as the account that may write Dir,
	// on unix ("sudo ", "sudo -H -u alice "). Empty on Windows, whose refusal names
	// an elevated PowerShell instead.
	Reach string
	// Err is a service that is installed but whose reading place could not be
	// determined, for example one moved off LocalSystem onto an account whose profile
	// this binary does not know. A bind then refuses rather than guess.
	Err error
	// ConnectionService is true when this host's connection is installed as a system
	// service. That service keeps its own binding, which a person's identity fix does not
	// rewrite, so the fix says so. Read from the service manager's registration (systemd,
	// launchd, the Service Control Manager), never from a file only the service can read.
	ConnectionService bool
}

// split reports whether the service reads from somewhere this process does not
// write by default.
func (c serviceIdentityContext) split() bool { return c.Installed && !c.Self }

// serviceIdentityContextFn answers "no split" until a build that installs the host
// service sets the real probe, which asks the service manager. A build without that
// service has no service whose profile could differ from this one, so its enroll
// writes where it always has. Tests stub it too: the real probe reads the machine's
// service manager, which a hermetic test must never depend on.
var serviceIdentityContextFn = func() serviceIdentityContext { return serviceIdentityContext{} }

// sudoInvokerKeyForFn names the invoking user's key file when a sudo enroll in an installed
// service's own context, which has no key yet, may bind with it. Without a host service
// there is no such context, so the default declines; the build that installs the host
// service sets the real one beside the probe.
var sudoInvokerKeyForFn = func(identityTarget) (from, path string, ok bool) { return "", "", false }

// identityTarget is where a bind writes, and whether that is the service's copy.
type identityTarget struct {
	marker string
	key    string // "" outside the service context: the key ladder's own default
	agent  string // "" outside the service context: client.DefaultAgentFile()
	// service is true when the files are the service's copies, written from another
	// account (an administrator's elevated shell, or root under sudo). The key this run binds with is then
	// carried there too, or the sensor would hold a marker and no key to report with.
	service bool
	ctx     serviceIdentityContext
}

// resolveIdentityTarget decides where `whisper enroll` writes. retry is the command
// line a refusal names, already pasteable.
func resolveIdentityTarget(ctx serviceIdentityContext, retry string) (identityTarget, error) {
	if !ctx.split() {
		return identityTarget{marker: client.DefaultBoundFile(), ctx: ctx}, nil
	}
	if ctx.Err != nil {
		return identityTarget{}, &usageError{msg: fmt.Sprintf("the %s service is installed, but where it "+
			"reads its identity could not be determined (%v), so nothing was written. Run '%s' as the "+
			"account that service runs as", ctx.Service, ctx.Err, retry)}
	}
	if !ctx.Elevated {
		if ctx.Reach != "" {
			return identityTarget{}, &usageError{msg: fmt.Sprintf("the %s service runs as %s and reads its "+
				"identity from %s, which this shell cannot write, so nothing was written. Run '%s%s'",
				ctx.Service, ctx.Account, ctx.Dir, ctx.Reach, retry)}
		}
		return identityTarget{}, &usageError{msg: fmt.Sprintf("the %s service runs as %s and reads its "+
			"identity from %s, which this shell cannot write, so nothing was written. Run '%s' from an "+
			"elevated PowerShell (Run as administrator)", ctx.Service, ctx.Account, ctx.Dir, retry)}
	}
	return identityTarget{
		marker:  filepath.Join(ctx.Dir, "bound"),
		key:     filepath.Join(ctx.Dir, "key"),
		agent:   filepath.Join(ctx.Dir, "agent"),
		service: true,
		ctx:     ctx,
	}, nil
}

// enrollRetryLine is the command a refusal names: this same enroll, ready to paste.
func enrollRetryLine(name string, force bool) string {
	line := "whisper enroll"
	if force {
		line += " --force"
	}
	if name != "" {
		line += " --name " + pasteWord(name)
	}
	return line
}
