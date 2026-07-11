//go:build linux

// A constructor faced with an impossible lock budget must return an error
// and leave the process running, never panic — a fail-closed guarantee as
// load-bearing as any feature. RLIMIT_MEMLOCK is lowered to zero, which
// poisons every later allocation, so the assertion runs in a re-exec'd
// child that lowers the limit, tries to allocate, checks for a clean error,
// and exits.

package secmem

import (
	"os"
	"os/exec"
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

//nolint:gochecknoinits // deterministic child dispatch for the rlimit-poisoning test.
func init() {
	if os.Getenv("SECMEM_MLOCK_CHILD") != "1" {
		return
	}

	// Pin the locked-memory budget to zero, hard and soft: no page can be
	// mlock'd (and secretmem, which also counts against this limit, is
	// likewise refused). Every secure allocation must now fail.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		os.Stderr.WriteString("setrlimit(RLIMIT_MEMLOCK,0): " + err.Error() + "\n")
		os.Exit(1)
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
	// alive — the fail-closed contract this test exists to enforce.
	os.Exit(0)
}
