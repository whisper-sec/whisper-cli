// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// netns_thread_root_linux_test.go holds Namespace.run and CreateNamespace to the return-home rule: the thread
// that goes into the agent's namespace comes back to the host's and is handed to the runtime there, never ended
// inside and never parked. These run as root, since they make a real namespace; unprivileged they skip. The
// unprivileged half, which CI runs, is in netns_linux_test.go, with the helpers both use.

// The thread Namespace.run used is alive and back in the host's namespace the moment run returns, every time. A
// version that ended it inside leaves no thread to read; one that answered before going home is read in the agent's
// namespace.
func TestTheThreadThatRanInTheAgentsNamespaceComesBack(t *testing.T) {
	needRoot(t)
	ns, err := CreateNamespace(tSelf)
	if err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	defer ns.Close()
	home := homeNS(t)
	for i := 0; i < 20; i++ {
		tid := 0
		var inside unix.Stat_t
		if err := ns.run(func() error {
			tid = unix.Gettid()
			return unix.Stat("/proc/thread-self/ns/net", &inside)
		}); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if inside.Ino == home.Ino {
			t.Fatal("control: run did not execute in the agent's namespace")
		}
		if st, ok := atHome(t, tid, home); !ok {
			t.Fatalf("run %d: thread %d is not home after run (now %d)", i, tid, st.Ino)
		}
	}
}

// The thread that built the namespace is handed back the same way. createNamespace runs onThread on the very thread
// that will unshare, before it leaves home, so the test can name it and then find it at home again.
func TestTheThreadThatBuiltTheNamespaceComesBack(t *testing.T) {
	needRoot(t)
	home := homeNS(t)
	for i := 0; i < 20; i++ {
		tid := 0
		ns, err := createNamespace(tSelf, func() { tid = unix.Gettid() })
		if err != nil {
			t.Fatalf("createNamespace %d: %v", i, err)
		}
		inode := ns.Inode
		st, ok := atHome(t, tid, home)
		ns.Close()
		if inode == home.Ino {
			t.Fatal("control: the namespace built is the host's own")
		}
		if !ok {
			t.Fatalf("build %d: thread %d is not home after createNamespace (now %d)", i, tid, st.Ino)
		}
	}
}

// Many runs and builds at once leave no thread of this process in another namespace, and end none: a child with a
// parent-death signal, started on a pool thread, lives through them. A thread an earlier test parked somewhere is
// not this test's business, so only a thread this test moved, or a new one that is not home, counts.
func TestTheAgentsNamespaceLeavesNoThreadInIt(t *testing.T) {
	needRoot(t)
	ns, err := CreateNamespace(tSelf)
	if err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	defer ns.Close()
	home := homeNS(t)
	before := threadNS(t)
	// Tied by the kernel to the thread that forks it: an ended thread kills it. Before the threads went home, they
	// ended theirs, which killed a child like this one in most runs.
	sleeper := exec.Command("sleep", "60")
	sleeper.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := sleeper.Start(); err != nil {
		t.Skipf("needs sleep(1): %v", err)
	}
	defer func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() }()
	var wg sync.WaitGroup
	var ran atomic.Int32
	for w := 0; w < 64; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ns.run(func() error { return nil }) == nil {
				ran.Add(1)
			}
		}()
	}
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if built, err := CreateNamespace(tSelf); err == nil {
				ran.Add(1)
				built.Close()
			}
		}()
	}
	wg.Wait()
	if ran.Load() != 68 {
		t.Fatalf("%d of 68 runs and builds completed", ran.Load())
	}
	if err := sleeper.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("the child with a parent-death signal died while threads went away and back: %v", err)
	}
	if strays := strayThreads(t, before, home); len(strays) > 0 {
		t.Fatalf("threads %v were left in another namespace", strays)
	}
}
