// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wfp_windows.go is the thin layer over the user-mode filter engine (fwpuclnt.dll). Every
// structure it passes is built and tested in wfpabi.go; this file only makes the calls.

var (
	fwpuclnt                      = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0           = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0          = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmTransactionBegin0     = fwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0    = fwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0     = fwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmProviderAdd0          = fwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmSubLayerAdd0          = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0            = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteByID0     = fwpuclnt.NewProc("FwpmFilterDeleteById0")
	procFwpmFilterGetByID0        = fwpuclnt.NewProc("FwpmFilterGetById0")
	procFwpmFilterCreateEnumHndl0 = fwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	procFwpmFilterEnum0           = fwpuclnt.NewProc("FwpmFilterEnum0")
	procFwpmFilterDestroyEnumHnd0 = fwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
	procFwpmFreeMemory0           = fwpuclnt.NewProc("FwpmFreeMemory0")
)

const (
	rpcCAuthnWinNT = 10

	fwpEAlreadyExists  = 0x80320009
	fwpEFilterNotFound = 0x80320003
)

// wfpErr names a failed engine call. The engine answers with a DWORD that is either a Win32
// error or an FWP_E_* code; both print through Errno.
type wfpErr struct {
	call string
	code uint32
}

func (e *wfpErr) Error() string {
	return fmt.Sprintf("%s: %v (0x%08X)", e.call, windows.Errno(e.code), e.code)
}

func wfpCall(name string, p *windows.LazyProc, args ...uintptr) error {
	if err := p.Find(); err != nil {
		return fmt.Errorf("the Windows Filtering Platform is not available here (%s: %w)", name, err)
	}
	r, _, _ := p.Call(args...)
	if r != 0 {
		return &wfpErr{call: name, code: uint32(r)}
	}
	return nil
}

// engine is an open session with the filter engine.
type engine struct {
	h windows.Handle
}

// openEngine opens a session. A dynamic one removes every object it added when the handle
// closes, a crash included; a static one leaves them until they are deleted or the machine
// boots.
func openEngine(dynamic bool, name string) (*engine, error) {
	n := utf16z(name)
	s := fwpmSession0{displayData: fwpmDisplayData0{name: &n[0]}, txnWaitTimeoutInMSec: 5000}
	if dynamic {
		s.flags = fwpmSessionFlagDynamic
	}
	var h windows.Handle
	err := wfpCall("FwpmEngineOpen0", procFwpmEngineOpen0, 0, rpcCAuthnWinNT, 0,
		uintptr(unsafe.Pointer(&s)), uintptr(unsafe.Pointer(&h)))
	runtime.KeepAlive(n)
	if err != nil {
		return nil, err
	}
	return &engine{h: h}, nil
}

func (e *engine) close() {
	if e != nil && e.h != 0 {
		_, _, _ = procFwpmEngineClose0.Call(uintptr(e.h))
		e.h = 0
	}
}

// inTxn runs fn in one transaction, so a partial set of filters is never left behind.
func (e *engine) inTxn(fn func() error) error {
	if err := wfpCall("FwpmTransactionBegin0", procFwpmTransactionBegin0, uintptr(e.h), 0); err != nil {
		return err
	}
	if err := fn(); err != nil {
		_, _, _ = procFwpmTransactionAbort0.Call(uintptr(e.h))
		return err
	}
	return wfpCall("FwpmTransactionCommit0", procFwpmTransactionCommit0, uintptr(e.h))
}

// ensureProviderAndSublayer adds the CLI's provider and sublayer, or finds them already there.
// Neither is persistent: a reboot removes them, and with them every filter a crashed run left.
func (e *engine) ensureProviderAndSublayer() error {
	pn, pd := utf16z("Whisper"), utf16z("Whisper enforced egress (whisper run --enforce)")
	prov := fwpmProvider0{providerKey: guidProvider, displayData: fwpmDisplayData0{name: &pn[0], description: &pd[0]}}
	err := wfpCall("FwpmProviderAdd0", procFwpmProviderAdd0, uintptr(e.h), uintptr(unsafe.Pointer(&prov)), 0)
	if err != nil && !isWFPCode(err, fwpEAlreadyExists) {
		return err
	}
	sn := utf16z("Whisper enforced egress")
	pk := guidProvider
	sub := fwpmSublayer0{subLayerKey: guidSublayer, displayData: fwpmDisplayData0{name: &sn[0], description: &pd[0]},
		providerKey: &pk, weight: sublayerWeight}
	err = wfpCall("FwpmSubLayerAdd0", procFwpmSubLayerAdd0, uintptr(e.h), uintptr(unsafe.Pointer(&sub)), 0)
	runtime.KeepAlive(pn)
	runtime.KeepAlive(sn)
	if err != nil && !isWFPCode(err, fwpEAlreadyExists) {
		return err
	}
	return nil
}

func isWFPCode(err error, code uint32) bool {
	var we *wfpErr
	return errors.As(err, &we) && we.code == code
}

// addFilter adds one built filter and returns its id.
func (e *engine) addFilter(w *wfpFilter) (uint64, error) {
	var id uint64
	err := wfpCall("FwpmFilterAdd0", procFwpmFilterAdd0, uintptr(e.h), uintptr(unsafe.Pointer(&w.f)), 0,
		uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(w)
	return id, err
}

// deleteFilter removes a filter; one that is already gone is not an error.
func (e *engine) deleteFilter(id uint64) error {
	err := wfpCall("FwpmFilterDeleteById0", procFwpmFilterDeleteByID0, uintptr(e.h), uintptr(id))
	if err != nil && isWFPCode(err, fwpEFilterNotFound) {
		return nil
	}
	return err
}

// filterPresent reports whether the engine still holds the filter. Any failure to ask is an
// error, which the watch treats exactly like a missing filter.
func (e *engine) filterPresent(id uint64) error {
	var p *fwpmFilter0
	if err := wfpCall("FwpmFilterGetById0", procFwpmFilterGetByID0, uintptr(e.h), uintptr(id),
		uintptr(unsafe.Pointer(&p))); err != nil {
		return err
	}
	freeWFP(unsafe.Pointer(&p))
	return nil
}

// freeWFP releases memory the engine allocated; pp is the address of the pointer it returned.
func freeWFP(pp unsafe.Pointer) {
	_, _, _ = procFwpmFreeMemory0.Call(uintptr(pp))
}

// ourFilter is a filter found under the CLI's provider, with the description a run wrote.
type ourFilter struct {
	id   uint64
	desc string
}

// providerFilters lists every filter under the CLI's provider on layer l.
func (e *engine) providerFilters(l Layer) ([]ourFilter, error) {
	key, ok := l.key()
	if !ok {
		return nil, errors.New("enforce: unknown layer")
	}
	pk := guidProvider
	tmpl := fwpmFilterEnumTemplate0{providerKey: &pk, layerKey: key, actionMask: 0xFFFFFFFF}
	var eh windows.Handle
	if err := wfpCall("FwpmFilterCreateEnumHandle0", procFwpmFilterCreateEnumHndl0, uintptr(e.h),
		uintptr(unsafe.Pointer(&tmpl)), uintptr(unsafe.Pointer(&eh))); err != nil {
		return nil, err
	}
	defer procFwpmFilterDestroyEnumHnd0.Call(uintptr(e.h), uintptr(eh)) //nolint:errcheck
	var out []ourFilter
	for {
		var entries **fwpmFilter0
		var n uint32
		if err := wfpCall("FwpmFilterEnum0", procFwpmFilterEnum0, uintptr(e.h), uintptr(eh), 64,
			uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&n))); err != nil {
			return out, err
		}
		if n == 0 {
			if entries != nil {
				freeWFP(unsafe.Pointer(&entries))
			}
			return out, nil
		}
		for _, f := range unsafe.Slice(entries, n) {
			if f == nil || f.providerKey == nil || *f.providerKey != guidProvider {
				continue
			}
			desc := ""
			if f.displayData.description != nil {
				desc = windows.UTF16PtrToString(f.displayData.description)
			}
			out = append(out, ourFilter{id: f.filterID, desc: desc})
		}
		freeWFP(unsafe.Pointer(&entries))
		if n < 64 {
			return out, nil
		}
	}
}
