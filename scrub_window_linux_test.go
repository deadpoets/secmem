//go:build linux

package secmem

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// sigBlkMask reads SigBlk from /proc/thread-self/status — the kernel's own
// record of the CALLING THREAD's blocked signal mask. Asking the kernel is the
// point: a nil return from PthreadSigmask proves the syscall was accepted, not
// that the signal is actually blocked while fn runs.
//
// It must be thread-self, not /proc/self. A signal mask is a per-thread
// property, but /proc/<pid>/status reports the THREAD GROUP LEADER — the main
// thread — so /proc/self/status answers about a thread that is almost never the
// one running the window. That reads as "not blocked" no matter what the window
// did. It is a convincing false negative: it passes when the test happens to run
// on the main thread (a short targeted run) and fails once the suite has spawned
// enough threads that it does not, which is exactly how it was caught.
func sigBlkMask(t *testing.T) uint64 {
	t.Helper()
	f, err := os.Open("/proc/thread-self/status")
	if err != nil {
		t.Skipf("cannot read /proc/thread-self/status: %v", err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "SigBlk:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			t.Fatalf("malformed SigBlk line: %q", line)
		}
		m, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			t.Fatalf("parsing SigBlk %q: %v", fields[1], err)
		}
		return m
	}
	t.Skip("no SigBlk line in /proc/thread-self/status")
	return 0
}

func sigBit(sig unix.Signal) uint64 { return 1 << (uint(sig) - 1) }

// TestScrub_BlocksPreemptionSignalInsideWindow is the efficacy test: it asserts
// the kernel reports SIGURG blocked for the calling thread WHILE fn runs, and
// not before or after.
//
// SIGURG is Go's non-cooperative preemption signal, and its handler
// (runtime.asyncPreempt) spills the entire register file onto this goroutine's
// stack. Blocking it is the only thing that prevents that copy; this test is
// what distinguishes "we called pthread_sigmask" from "the signal is masked".
//
// The goroutine must be locked to its thread for any of this to mean anything —
// a mask is a thread property, and an unpinned goroutine can migrate mid-window
// to a thread where it was never set. That is asserted too.
func TestScrub_BlocksPreemptionSignalInsideWindow(t *testing.T) {
	before := sigBlkMask(t)
	if before&sigBit(unix.SIGURG) != 0 {
		t.Skip("SIGURG already blocked on this thread before the window; test would be vacuous")
	}

	var inside uint64
	var lockedTID, outerTID int
	outerTID = unix.Gettid()

	Scrub(func() {
		inside = sigBlkMask(t)
		lockedTID = unix.Gettid()
	})

	after := sigBlkMask(t)

	if inside&sigBit(unix.SIGURG) == 0 {
		t.Errorf("SIGURG NOT blocked inside the Scrub window (SigBlk=%016x): "+
			"runtime.asyncPreempt can still spill the whole register file to the stack", inside)
	}
	if inside&sigBit(unix.SIGPROF) == 0 {
		t.Errorf("SIGPROF not blocked inside the Scrub window (SigBlk=%016x)", inside)
	}
	if after != before {
		t.Errorf("signal mask not restored: before=%016x after=%016x — "+
			"a leaked block would leave this thread unpreemptible for its whole life", before, after)
	}
	if lockedTID != outerTID {
		t.Errorf("goroutine ran on tid %d but entered on %d: without LockOSThread the mask "+
			"can be set on one thread and the window run on another", lockedTID, outerTID)
	}
}

// TestScrub_NestedWindowsRestoreExactly checks that a nested Scrub restores the
// OUTER window's mask rather than unblocking outright. Nesting is realistic —
// secmem-crypto wraps a Scrub around a callback that may itself Scrub — and an
// inner window that unblocked unconditionally would silently reopen the
// register-dump hole for the remainder of the outer one.
func TestScrub_NestedWindowsRestoreExactly(t *testing.T) {
	before := sigBlkMask(t)
	if before&sigBit(unix.SIGURG) != 0 {
		t.Skip("SIGURG already blocked before the window; test would be vacuous")
	}

	var outerAfterInner uint64
	Scrub(func() {
		Scrub(func() {})
		outerAfterInner = sigBlkMask(t)
	})

	if outerAfterInner&sigBit(unix.SIGURG) == 0 {
		t.Errorf("inner Scrub unblocked SIGURG for the rest of the outer window (SigBlk=%016x)", outerAfterInner)
	}
	if got := sigBlkMask(t); got != before {
		t.Errorf("nested windows did not restore the original mask: before=%016x after=%016x", before, got)
	}
}

// TestScrub_ConcurrentWindowsUnderGCPressure is the safety test for the one
// hazard blocking SIGURG introduces: suspendG drives a goroutine to a
// preemption point and retries, so if a window offered NO cooperative
// preemption point either, the collector would spin waiting for it.
//
// Real windows do make function calls, which trip the poisoned stack guard and
// yield. This runs many concurrent windows against a deliberately GC-heavy
// workload and requires the whole thing to finish — a regression that made
// windows unpreemptible would hang here rather than fail quietly.
// The churn goroutine and the workers are on SEPARATE WaitGroups on purpose.
// Putting the churner in the same group deadlocks the test itself: it runs until
// stop closes, stop closes after the wait, and the wait includes the churner. An
// earlier version did exactly that and looked, convincingly, like the library
// hanging — the traceback is what told them apart (all eight workers had
// finished; only the churner and the waiter remained).
func TestScrub_ConcurrentWindowsUnderGCPressure(t *testing.T) {
	var workers, churn sync.WaitGroup
	stop := make(chan struct{})

	// Churn the heap so the collector runs repeatedly and needs to scan the
	// stacks of the workers while they are inside windows.
	churn.Add(1)
	go func() {
		defer churn.Done()
		for {
			select {
			case <-stop:
				return
			default:
				sink := make([][]byte, 0, 64)
				for i := 0; i < 64; i++ {
					sink = append(sink, make([]byte, 4096))
				}
				runtime.KeepAlive(sink)
			}
		}
	}()

	for g := 0; g < 8; g++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < 200; i++ {
				Scrub(func() {
					// Function calls inside the window are what keep it
					// cooperatively preemptible while SIGURG is masked.
					buf := make([]byte, 64)
					SecureWipe(buf)
					runtime.Gosched()
				})
			}
		}()
	}

	// The assertion is that this returns at all: a window that could not be
	// preempted would leave the collector spinning in suspendG and the test
	// would die on its timeout.
	workers.Wait()
	close(stop)
	churn.Wait()
}
