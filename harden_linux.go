//go:build linux

package secmem

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// hardenProcess applies Linux process hardening via prctl(2).
//
// Applied in order:
//  1. PR_SET_DUMPABLE=0 — disables /proc/self/core and ptrace attach
//  2. PR_SET_NO_NEW_PRIVS=1 — prevents privilege escalation via setuid/capabilities
//  3. seccomp BPF — reserved; not yet implemented (needs a per-binary policy)
func hardenProcess() (HardenLevel, error) {
	var level HardenLevel

	// L1a: Disable core dumps and ptrace-based secret extraction.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return level, fmt.Errorf("harden: PR_SET_DUMPABLE: %w", err)
	}
	level |= HardenNoDump

	// L1b: Prevent privilege escalation — no new capabilities via execve.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return level, fmt.Errorf("harden: PR_SET_NO_NEW_PRIVS: %w", err)
	}
	level |= HardenNoNewPriv

	// L1c: seccomp BPF filter — not yet implemented. A useful filter needs a
	// syscall allowlist generated for the specific host binary, which a library
	// cannot know for its caller; adding one here without that policy would only
	// risk killing the process on a legitimate syscall.

	return level, nil
}
