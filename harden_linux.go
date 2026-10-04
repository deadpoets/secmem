//go:build linux

package secmem

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// hardenProcess applies Linux process hardening via prctl(2).
//
// Applied in order:
//  1. PR_SET_DUMPABLE=0 — disables /proc/self/core and ptrace attach
//  2. PR_SET_NO_NEW_PRIVS=1 on every thread — prevents privilege escalation
//     via setuid/capabilities
//  3. seccomp BPF — reserved; not yet implemented (needs a per-binary policy)
func hardenProcess() (HardenLevel, error) {
	var level HardenLevel

	// L1a: Disable core dumps and ptrace-based secret extraction. The
	// dumpable flag belongs to the address space, so one call covers the
	// process.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return level, fmt.Errorf("harden: PR_SET_DUMPABLE: %w", err)
	}
	level |= HardenNoDump

	// L1b: Prevent privilege escalation — no new capabilities via execve.
	//
	// no_new_privs is a THREAD attribute, inherited by the threads and child
	// processes that thread creates. The runtime has several threads before
	// main runs and forks a child from whichever one the calling goroutine is
	// on, so a plain prctl here would leave os/exec able to start a setuid
	// binary from any other thread. AllThreadsSyscall runs the call on every
	// thread the runtime owns and fails as a whole if they disagree.
	_, _, errno := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0)
	switch {
	case errno == 0:
		level |= HardenNoNewPriv
	case errors.Is(errno, syscall.ENOTSUP):
		// A binary that links cgo: the runtime cannot reach threads that C
		// code started, so it refuses to try. Set the attribute on this
		// thread, which covers what it goes on to create, and do NOT report
		// HardenNoNewPriv: the process as a whole does not have it.
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return level, fmt.Errorf("harden: PR_SET_NO_NEW_PRIVS: %w", err)
		}
	default:
		return level, fmt.Errorf("harden: PR_SET_NO_NEW_PRIVS: %w", errno)
	}

	// L1c: seccomp BPF filter — not yet implemented. A useful filter needs a
	// syscall allowlist generated for the specific host binary, which a library
	// cannot know for its caller; adding one here without that policy would only
	// risk killing the process on a legitimate syscall.

	return level, nil
}
