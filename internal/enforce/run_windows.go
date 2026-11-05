// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// run_windows.go is `whisper run --enforce` on Windows: the agent runs under a token
// of its own, whose only permitted connection is TCP to the local egress proxy, inside a job that
// dies with the CLI, while a watch kills it if any of its filters disappears.

var (
	procCreateProcessWithTokenW = advapi32.NewProc("CreateProcessWithTokenW")
	user32                      = windows.NewLazySystemDLL("user32.dll")
	procGetProcessWindowStation = user32.NewProc("GetProcessWindowStation")
	procGetThreadDesktop        = user32.NewProc("GetThreadDesktop")
)

// watchInterval is how often the watch asks the engine for every filter the run depends on.
const watchInterval = 500 * time.Millisecond

// exitFilterLost is the agent's exit code when the watch killed it; exitInterrupted is
// STATUS_CONTROL_C_EXIT, what Windows reports for a program ended by Ctrl-C.
const (
	exitFilterLost  = 0xE0F1
	exitInterrupted = 0xC000013A
)

// WindowsSpec is what the CLI hands over: the agent's command and environment, and the port of
// the local proxy that is its only door.
type WindowsSpec struct {
	Path      string
	Args      []string
	Env       []string
	Dir       string
	ProxyPort uint16
	Logf      func(string, ...any)
}

// WindowsResult is how the run ended.
type WindowsResult struct {
	Code int
	// Killed says why the CLI ended the agent itself, empty when it exited on its own.
	Killed string
}

// RunWindows runs spec enforced and returns when the agent's process and its whole tree are
// gone and the filters are removed. ready is called once the filters are in place and before
// the agent exists, so the CLI can say what is enforced.
func RunWindows(spec WindowsSpec, ready func()) (res WindowsResult, err error) {
	logf := spec.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if !Elevated() {
		return res, errors.New("adding filters to the Windows Filtering Platform needs an elevated terminal")
	}
	plan, err := AgentPlan(spec.ProxyPort)
	if err != nil {
		return res, err
	}
	self, err := selfTag()
	if err != nil {
		return res, err
	}

	static, err := openEngine(false, "whisper run --enforce")
	if err != nil {
		return res, fmt.Errorf("opening the Windows filter engine: %w", err)
	}
	defer static.close()
	if err := static.ensureProviderAndSublayer(); err != nil {
		return res, fmt.Errorf("registering Whisper with the Windows filter engine: %w", err)
	}
	if n, serr := sweepStale(static); serr != nil {
		logf("whisper: could not sweep filters left by an earlier run (%v); they name a logon session that is gone, so they refuse nothing alive", serr)
	} else if n > 0 {
		logf("whisper: removed %d filter(s) an earlier enforced run left behind", n)
	}

	tok, err := newAgentToken()
	if err != nil {
		return res, err
	}
	defer tok.close()
	sds, err := securityDescriptors(tok.logonSID)
	if err != nil {
		return res, err
	}

	// The agent's own filters, in a static session so they outlive a crashed CLI (and then
	// refuse a logon session nobody is in any more).
	var agentIDs []uint64
	if err := static.inTxn(func() error {
		for _, spec := range plan {
			w, berr := buildFilter(spec, sds, self.String())
			if berr != nil {
				return berr
			}
			id, aerr := static.addFilter(w)
			if aerr != nil {
				return fmt.Errorf("%s: %w", spec.Name, aerr)
			}
			agentIDs = append(agentIDs, id)
		}
		return nil
	}); err != nil {
		return res, fmt.Errorf("adding the agent's filters: %w", err)
	}
	defer func() {
		if derr := static.inTxn(func() error {
			for _, id := range agentIDs {
				if e := static.deleteFilter(id); e != nil {
					return e
				}
			}
			return nil
		}); derr != nil {
			logf("whisper: could not remove the agent's filters (%v); they refuse only a logon session that has ended, and the next enforced run removes them", derr)
		}
	}()

	// ICMP echo from SYSTEM, host-wide, in a dynamic session: if the CLI dies the engine removes
	// these at once, so a crash can never leave the host without ping.
	dyn, err := openEngine(true, "whisper run --enforce (ICMP, this run)")
	if err != nil {
		return res, fmt.Errorf("opening the Windows filter engine: %w", err)
	}
	defer dyn.close()
	var icmpIDs []uint64
	if err := dyn.inTxn(func() error {
		for _, spec := range HostICMPPlan() {
			w, berr := buildFilter(spec, sds, self.String())
			if berr != nil {
				return berr
			}
			id, aerr := dyn.addFilter(w)
			if aerr != nil {
				return fmt.Errorf("%s: %w", spec.Name, aerr)
			}
			icmpIDs = append(icmpIDs, id)
		}
		return nil
	}); err != nil {
		return res, fmt.Errorf("adding the ICMP filters: %w", err)
	}

	revoke, err := grantWindowAccess(tok.logonSID)
	if err != nil {
		return res, err
	}
	defer revoke()

	job, err := killOnCloseJob()
	if err != nil {
		return res, err
	}
	defer windows.CloseHandle(job) //nolint:errcheck

	if ready != nil {
		ready()
	}

	// Ctrl-C (or a console close) ends the agent through the job, then the CLI tears down. The
	// CLI must not die first: the job would still kill the agent, but the filters would stay.
	intr := make(chan os.Signal, 2)
	signal.Notify(intr, os.Interrupt)
	defer signal.Stop(intr)

	proc, err := spawnInJob(tok.tok, job, spec)
	if err != nil {
		return res, err
	}
	defer windows.CloseHandle(proc) //nolint:errcheck

	var killOnce sync.Once
	kill := func(why string, code uint32) {
		killOnce.Do(func() {
			res.Killed = why
			_ = windows.TerminateJobObject(job, code)
		})
	}
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(watchInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-intr:
				kill("interrupted", exitInterrupted)
			case <-t.C:
				if why := checkFilters(static, agentIDs, dyn, icmpIDs); why != "" {
					logf("whisper: %s, so the agent was stopped (it is never left running unfiltered)", why)
					kill(why, exitFilterLost)
				}
			}
		}
	}()

	_, werr := windows.WaitForSingleObject(proc, windows.INFINITE)
	close(done)
	var code uint32
	if werr == nil {
		werr = windows.GetExitCodeProcess(proc, &code)
	}
	// The agent's tree goes before its filters: nothing it started may outlive them.
	_ = windows.TerminateJobObject(job, 1)
	waitJobEmpty(job, 5*time.Second)
	if werr != nil {
		return res, fmt.Errorf("waiting for the agent: %w", werr)
	}
	res.Code = int(code)
	return res, nil
}

// checkFilters returns why the run must stop, or "" while every filter is in place.
func checkFilters(static *engine, agentIDs []uint64, dyn *engine, icmpIDs []uint64) string {
	for _, id := range agentIDs {
		if err := static.filterPresent(id); err != nil {
			return fmt.Sprintf("one of the agent's filters is gone or the filter engine stopped answering (%v)", err)
		}
	}
	for _, id := range icmpIDs {
		if err := dyn.filterPresent(id); err != nil {
			return fmt.Sprintf("the ICMP filter is gone or the filter engine stopped answering (%v)", err)
		}
	}
	return ""
}

// securityDescriptors builds the two descriptors the filters match against.
func securityDescriptors(logonSID string) (SecurityDescriptors, error) {
	out := SecurityDescriptors{}
	for who, sid := range map[Who]string{WhoAgent: logonSID, WhoSystem: "S-1-5-18"} {
		sddl, err := MatchSDDL(sid)
		if err != nil {
			return nil, err
		}
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return nil, fmt.Errorf("building the filter's security descriptor: %w", err)
		}
		b := unsafe.Slice((*byte)(unsafe.Pointer(sd)), sd.Length())
		out[who] = append([]byte(nil), b...)
	}
	return out, nil
}

// selfTag is this CLI's RunTag: its pid and creation time.
func selfTag() (RunTag, error) {
	created, err := processCreated(windows.CurrentProcess())
	if err != nil {
		return RunTag{}, fmt.Errorf("reading this process's start time: %w", err)
	}
	return RunTag{PID: uint32(os.Getpid()), Created: created}, nil
}

func processCreated(h windows.Handle) (uint64, error) {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return 0, err
	}
	return uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime), nil
}

// runAlive says whether the run that wrote tag is still going. Only a pid that does not exist,
// or one whose process started at another time, is gone; anything this process cannot read is
// treated as alive, so a sweep never removes a live run's filters.
func runAlive(tag RunTag) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, tag.PID)
	if err != nil {
		return !errors.Is(err, windows.ERROR_INVALID_PARAMETER)
	}
	defer windows.CloseHandle(h) //nolint:errcheck
	var code uint32
	if windows.GetExitCodeProcess(h, &code) == nil && code != 259 { // STILL_ACTIVE
		return false
	}
	created, err := processCreated(h)
	if err != nil {
		return true
	}
	return created == tag.Created
}

// sweepStale removes filters under the CLI's provider whose run has ended.
func sweepStale(e *engine) (int, error) {
	var stale []uint64
	for _, l := range allLayers {
		fs, err := e.providerFilters(l)
		if err != nil {
			return 0, err
		}
		for _, f := range fs {
			if tag, ok := ParseRunTag(f.desc); ok && !runAlive(tag) {
				stale = append(stale, f.id)
			}
		}
	}
	if len(stale) == 0 {
		return 0, nil
	}
	err := e.inTxn(func() error {
		for _, id := range stale {
			if derr := e.deleteFilter(id); derr != nil {
				return derr
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(stale), nil
}

// grantWindowAccess gives the agent's logon SID access to this process's window station and
// desktop, which a process in another logon session needs to start at all, and returns how to
// take it away again. Only the ACEs naming that SID are removed, so a concurrent run's are kept.
func grantWindowAccess(logonSID string) (func(), error) {
	sid, err := windows.StringToSid(logonSID)
	if err != nil {
		return nil, err
	}
	ws, _, _ := procGetProcessWindowStation.Call()
	desk, _, _ := procGetThreadDesktop.Call(uintptr(windows.GetCurrentThreadId()))
	var granted []windows.Handle
	for _, h := range []windows.Handle{windows.Handle(ws), windows.Handle(desk)} {
		if h == 0 {
			continue
		}
		if err := editWindowACL(h, sid, windows.GRANT_ACCESS); err != nil {
			for _, g := range granted {
				_ = editWindowACL(g, sid, windows.REVOKE_ACCESS)
			}
			return nil, fmt.Errorf("granting the agent its window station and desktop: %w", err)
		}
		granted = append(granted, h)
	}
	return func() {
		for _, g := range granted {
			_ = editWindowACL(g, sid, windows.REVOKE_ACCESS)
		}
	}, nil
}

func editWindowACL(h windows.Handle, sid *windows.SID, mode windows.ACCESS_MODE) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	old, _, err := sd.DACL()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        mode,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}}, old)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(h, windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// killOnCloseJob is a job whose processes die when its last handle closes, which is the CLI's
// handle: the agent cannot outlive the CLI, however the CLI ends. No breakaway is allowed.
func killOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("creating the agent's job: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job) //nolint:errcheck
		return 0, fmt.Errorf("setting the agent's job to die with the CLI: %w", err)
	}
	return job, nil
}

// spawnInJob creates the agent suspended under tok, puts it in job, and only then lets it run,
// so not one instruction of the agent executes outside the job.
func spawnInJob(tok windows.Token, job windows.Handle, spec WindowsSpec) (windows.Handle, error) {
	app, err := windows.UTF16PtrFromString(spec.Path)
	if err != nil {
		return 0, err
	}
	cmd, err := windows.UTF16FromString(windows.ComposeCommandLine(spec.Args))
	if err != nil {
		return 0, err
	}
	var dir *uint16
	if spec.Dir != "" {
		if dir, err = windows.UTF16PtrFromString(spec.Dir); err != nil {
			return 0, err
		}
	}
	env := envBlock(spec.Env)
	si := windows.StartupInfo{
		Cb:        uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Flags:     windows.STARTF_USESTDHANDLES,
		StdInput:  windows.Handle(os.Stdin.Fd()),
		StdOutput: windows.Handle(os.Stdout.Fd()),
		StdErr:    windows.Handle(os.Stderr.Fd()),
	}
	var pi windows.ProcessInformation
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_UNICODE_ENVIRONMENT)
	if r, _, e := procCreateProcessWithTokenW.Call(uintptr(tok), 0, uintptr(unsafe.Pointer(app)),
		uintptr(unsafe.Pointer(&cmd[0])), uintptr(flags), uintptr(unsafe.Pointer(&env[0])),
		uintptr(unsafe.Pointer(dir)), uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi))); r == 0 {
		return 0, fmt.Errorf("starting the agent under its own token: %w", e)
	}
	defer windows.CloseHandle(pi.Thread) //nolint:errcheck
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Process) //nolint:errcheck
		return 0, fmt.Errorf("putting the agent in its job: %w", err)
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		windows.CloseHandle(pi.Process) //nolint:errcheck
		return 0, fmt.Errorf("starting the agent: %w", err)
	}
	return pi.Process, nil
}

// waitJobEmpty waits, bounded, until no process is left in the job.
func waitJobEmpty(job windows.Handle, bound time.Duration) {
	deadline := time.Now().Add(bound)
	for time.Now().Before(deadline) {
		var info jobBasicAccounting
		if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil || info.ActiveProcesses == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// jobBasicAccounting is JOBOBJECT_BASIC_ACCOUNTING_INFORMATION (48 bytes), which x/sys does not
// define.
type jobBasicAccounting struct {
	TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime int64
	TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses     uint32
}
