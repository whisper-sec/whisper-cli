// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The seccomp filter the enforced agent runs under, installed by init after no_new_privs and
// before the agent is forked, so the agent and everything it starts inherit it and cannot remove it.
//
// What it closes, and why each one:
//
//   - socket(AF_VSOCK) -> EAFNOSUPPORT. A vsock is not network-namespaced: on a hypervisor guest whose
//     host offers vsock services (Firecracker, Cloud Hypervisor, QEMU with vhost-vsock) it is a way
//     off the box that never touches the agent's namespace.
//   - io_uring_setup / io_uring_enter / io_uring_register -> ENOSYS. IORING_OP_SOCKET (5.19+) creates a
//     socket without the socket() call the rule above inspects, so io_uring would walk around it.
//     ENOSYS is what a kernel without io_uring answers, so every runtime already falls back.
//   - any syscall number with the x32 bit (0x40000000) on x86_64 -> the process is killed. x32 shares
//     AUDIT_ARCH_X86_64, so the architecture check alone would let x32 calls past every number below.
//   - any other syscall ABI (the i386 int 0x80 one on x86_64, aarch32 on arm64) -> the process is
//     killed, because the numbers below mean nothing there.
//
// With mode "strict" it also refuses new user namespaces: unshare or clone with CLONE_NEWUSER -> EPERM,
// and clone3 -> ENOSYS (its flags live behind a pointer BPF cannot read; glibc and Go then fall back to
// clone, whose flags it can). A nested user namespace is not a way out today, since its only network
// is loopback, so this only narrows the kernel surface the agent can reach.
const (
	SeccompDefault = "default"
	SeccompStrict  = "strict"
	SeccompOff     = "off"

	x32SyscallBit = 0x40000000
	afVsock       = 40 // AF_VSOCK, include/linux/socket.h
	secDataNR     = 0  // offsetof(struct seccomp_data, nr)
	secDataArch   = 4  // offsetof(struct seccomp_data, arch)
	secDataArg0   = 16 // offsetof(struct seccomp_data, args[0]), low 32 bits on little-endian
	retAllow      = unix.SECCOMP_RET_ALLOW
	retKill       = unix.SECCOMP_RET_KILL_PROCESS
)

// NormalizeSeccomp maps a flag value to a mode, liberally: empty means the default.
func NormalizeSeccomp(v string) (string, error) {
	switch v {
	case "", SeccompDefault, "on":
		return SeccompDefault, nil
	case SeccompStrict:
		return SeccompStrict, nil
	case SeccompOff, "none", "false":
		return SeccompOff, nil
	}
	return "", fmt.Errorf("--seccomp takes default, strict or off, not %q", v)
}

type sysnums struct {
	arch                                                    uint32
	x32                                                     bool
	socket, ioSetup, ioEnter, ioReg, unshare, clone, clone3 uint32
}

func archNumbers(goarch string) (sysnums, error) {
	switch goarch {
	case "amd64":
		return sysnums{unix.AUDIT_ARCH_X86_64, true, 41, 425, 426, 427, 272, 56, 435}, nil
	case "arm64":
		return sysnums{unix.AUDIT_ARCH_AARCH64, false, 198, 425, 426, 427, 97, 220, 435}, nil
	}
	return sysnums{}, fmt.Errorf("the enforced-agent seccomp filter is defined for amd64 and arm64, not %s; "+
		"run with --seccomp=off to start the agent without it", goarch)
}

// insn is one classic BPF instruction with symbolic jump targets, resolved by assemble.
type insn struct {
	code   uint16
	k      uint32
	jt, jf string // labels; "" falls through
	label  string // this instruction's own label
}

const (
	bpfLdW  = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	bpfJeq  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	bpfJset = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
	bpfRet  = unix.BPF_RET | unix.BPF_K
)

func errnoRet(e unix.Errno) uint32 { return unix.SECCOMP_RET_ERRNO | uint32(e)&unix.SECCOMP_RET_DATA }

// seccompProgram builds the filter for goarch.
func seccompProgram(goarch, mode string) ([]unix.SockFilter, error) {
	n, err := archNumbers(goarch)
	if err != nil {
		return nil, err
	}
	p := []insn{
		{code: bpfLdW, k: secDataArch},
		{code: bpfJeq, k: n.arch, jf: "kill"},
		{code: bpfLdW, k: secDataNR},
	}
	if n.x32 {
		p = append(p, insn{code: bpfJset, k: x32SyscallBit, jt: "kill"})
	}
	p = append(p,
		insn{code: bpfJeq, k: n.ioSetup, jt: "enosys"},
		insn{code: bpfJeq, k: n.ioEnter, jt: "enosys"},
		insn{code: bpfJeq, k: n.ioReg, jt: "enosys"},
		insn{code: bpfJeq, k: n.socket, jt: "socket"},
	)
	if mode == SeccompStrict {
		p = append(p,
			insn{code: bpfJeq, k: n.clone3, jt: "enosys"},
			insn{code: bpfJeq, k: n.unshare, jt: "nsflags"},
			insn{code: bpfJeq, k: n.clone, jt: "nsflags"},
		)
	}
	p = append(p,
		insn{code: bpfRet, k: retAllow},
		insn{label: "socket", code: bpfLdW, k: secDataArg0},
		insn{code: bpfJeq, k: afVsock, jt: "eafnosupport", jf: "allow"},
		insn{label: "nsflags", code: bpfLdW, k: secDataArg0},
		insn{code: bpfJset, k: unix.CLONE_NEWUSER, jt: "eperm", jf: "allow"},
		insn{label: "allow", code: bpfRet, k: retAllow},
		insn{label: "enosys", code: bpfRet, k: errnoRet(unix.ENOSYS)},
		insn{label: "eafnosupport", code: bpfRet, k: errnoRet(unix.EAFNOSUPPORT)},
		insn{label: "eperm", code: bpfRet, k: errnoRet(unix.EPERM)},
		insn{label: "kill", code: bpfRet, k: retKill},
	)
	return assemble(p)
}

func assemble(p []insn) ([]unix.SockFilter, error) {
	at := map[string]int{}
	for i, in := range p {
		if in.label != "" {
			at[in.label] = i
		}
	}
	skip := func(i int, l string) (uint8, error) {
		if l == "" {
			return 0, nil
		}
		t, ok := at[l]
		if !ok || t <= i || t-i-1 > 255 {
			return 0, fmt.Errorf("seccomp: bad jump to %q from %d", l, i)
		}
		return uint8(t - i - 1), nil
	}
	out := make([]unix.SockFilter, len(p))
	for i, in := range p {
		jt, err := skip(i, in.jt)
		if err != nil {
			return nil, err
		}
		jf, err := skip(i, in.jf)
		if err != nil {
			return nil, err
		}
		out[i] = unix.SockFilter{Code: in.code, Jt: jt, Jf: jf, K: in.k}
	}
	return out, nil
}

// seccompSyscall is the seccomp(2) call, a var so a test can return what a partial TSYNC returns.
var seccompSyscall = func(op, flags, args uintptr) (uintptr, uintptr, unix.Errno) {
	return unix.Syscall(unix.SYS_SECCOMP, op, flags, args)
}

// installSeccomp puts the filter on every thread of this process (TSYNC), so whatever it forks next
// inherits it. no_new_privs must already be set; the caller does that and checks it.
func installSeccomp(mode string) error {
	if mode == SeccompOff {
		return nil
	}
	prog, err := seccompProgram(runtime.GOARCH, mode)
	if err != nil {
		return err
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	r1, _, errno := seccompSyscall(unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(prog)
	if errno == 0 && r1 != 0 {
		// With TSYNC, a thread that could not be synchronised is reported as its TID with no errno: the filter
		// is then on some threads and not others, which is not a filter at all.
		return fmt.Errorf("the seccomp filter could not be synchronised to thread %d; the agent was not started", r1)
	}
	if errno != 0 {
		if errno == unix.EINVAL || errno == unix.ENOSYS {
			return errors.New("this kernel cannot install a seccomp filter; run with --seccomp=off to start the agent without it")
		}
		return fmt.Errorf("cannot install the seccomp filter: %w", errno)
	}
	return nil
}
