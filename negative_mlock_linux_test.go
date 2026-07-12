//go:build linux

// The headline failure-mode contrast with memguard (issue #119: mlock failure
// panics). Here a constructor faced with an impossible lock budget must return
// an error and leave the process running. RLIMIT_MEMLOCK is lowered to zero,
// which poisons every later allocation, so the assertion runs in a re-exec'd
// child that lowers the limit, tries to allocate, checks for a clean error,
// and exits.

package secmem

import (
	"os"
	"os/exec"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// TestMlockFailure_ReturnsErrorNotPanic re-execs a child with RLIMIT_MEMLOCK
// pinned to zero.
func TestMlockFailure_ReturnsErrorNotPanic(t *testing.T) {
	if os.Getenv("SECMEM_MLOCK_CHILD") == "1" {
		return // work happens in init()
	}
	cmd := exec.Command(os.Args[0], "-test.run", "TestMlockFailure_ReturnsErrorNotPanic", "-test.v")
	cmd.Env = append(os.Environ(), "SECMEM_MLOCK_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mlock-failure child failed (a panic or wrong outcome):\n%s", out)
	}
}

// dropCapIPCLock removes CAP_IPC_LOCK from the calling thread's effective,
// permitted, and inheritable sets. Without this, a process holding the
// capability — every root process, including the "root" inside a default
// container — bypasses RLIMIT_MEMLOCK entirely, so the zero budget below would
// be silently ignored and this negative test would assert nothing. Dropping it
// makes the fail-closed contract genuinely testable under root, which is the
// most common real deployment (root containers, rootless userns "root").
//
// Capabilities are per-thread and Go schedules goroutines across threads, so
// the caller MUST runtime.LockOSThread() first and perform the mlock attempts
// on the same locked thread; otherwise the allocation may run on a sibling
// thread that still holds the capability.
func dropCapIPCLock() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0} // 0 = self
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return err
	}
	const word, bit = unix.CAP_IPC_LOCK / 32, unix.CAP_IPC_LOCK % 32 // 14 → word 0, bit 14
	mask := ^(uint32(1) << bit)
	data[word].Effective &= mask
	data[word].Permitted &= mask
	data[word].Inheritable &= mask
	return unix.Capset(&hdr, &data[0])
}

//nolint:gochecknoinits // deterministic child dispatch for the rlimit-poisoning test.
func init() {
	if os.Getenv("SECMEM_MLOCK_CHILD") != "1" {
		return
	}

	// The capability drop and every mlock attempt below must run on one OS
	// thread (capabilities are per-thread; see dropCapIPCLock).
	runtime.LockOSThread()

	// Pin the locked-memory budget to zero, hard and soft: no page can be
	// mlock'd (and secretmem, which also counts against this limit, is
	// likewise refused). Every secure allocation must now fail.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		os.Stderr.WriteString("setrlimit(RLIMIT_MEMLOCK,0): " + err.Error() + "\n")
		os.Exit(1)
	}

	// Drop CAP_IPC_LOCK so the zero budget is actually enforced for this
	// process. If it cannot be dropped (capset refused), we cannot force mlock
	// to fail here, so the assertion would be meaningless — report and pass
	// rather than assert something the kernel will not enforce.
	if err := dropCapIPCLock(); err != nil {
		os.Stderr.WriteString("mlock-failure test inconclusive: cannot drop CAP_IPC_LOCK: " + err.Error() + "\n")
		os.Exit(0)
	}

	// A panic here fails the child (non-zero exit) and the parent reports it.
	// NewSyscallSafeBuffer forces the mmap+mlock path (no memfd), so mlock is
	// unavoidably attempted.
	if buf, err := NewSyscallSafeBuffer([]byte("must-fail-cleanly")); err == nil {
		_ = buf.Destroy()
		os.Stderr.WriteString("NewSyscallSafeBuffer succeeded under RLIMIT_MEMLOCK=0 — expected an error\n")
		os.Exit(1)
	}

	// NewBuffer (may try memfd first) must also fail closed, never panic.
	if buf, err := NewBuffer([]byte("must-fail-cleanly")); err == nil {
		_ = buf.Destroy()
		os.Stderr.WriteString("NewBuffer succeeded under RLIMIT_MEMLOCK=0 — expected an error\n")
		os.Exit(1)
	}

	// Reaching here means both returned errors and the process is still
	// alive — the exact contract memguard #119 violates.
	os.Exit(0)
}
