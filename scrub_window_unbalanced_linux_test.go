//go:build linux

package secmem

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// unbalancedUnlockChildEnv marks the subprocess that performs the misuse.
const unbalancedUnlockChildEnv = "SECMEM_TEST_UNBALANCED_UNLOCK_CHILD"

// TestScrub_UnbalancedUnlockOSThreadFailsLoudly is the regression test for a
// window whose fn unbalances runtime.LockOSThread.
//
// The window pins the goroutine to its OS thread and blocks SIGURG/SIGPROF on
// THAT thread. An UnlockOSThread inside fn that fn did not itself pair with a
// LockOSThread decrements the same counter the window incremented: the goroutine
// is unpinned mid-window and can be rescheduled onto another thread before
// restore runs. Unfixed, restore then wrote the saved mask onto whatever thread
// it landed on and left the entry thread with SIGURG and SIGPROF blocked for the
// rest of the process — silently, because UnlockOSThread on a zero count is a
// documented no-op. Fixed, restore notices it is on the wrong thread, leaves the
// stranger's mask alone, and panics with a message naming the cause.
//
// The leak itself is NOT repairable — there is no syscall that sets another
// thread's signal mask — so the test asserts three things: the goroutine really
// did move (else the scenario is vacuous), the entry thread really is left
// blocked (the premise the panic exists for), and the panic happened.
//
// It runs in a subprocess because whichever process performs the misuse keeps
// the damaged thread; the rest of the suite should not run on it.
func TestScrub_UnbalancedUnlockOSThreadFailsLoudly(t *testing.T) {
	if os.Getenv(unbalancedUnlockChildEnv) == "1" {
		unbalancedUnlockChild(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestScrub_UnbalancedUnlockOSThreadFailsLoudly$", "-test.v")
	cmd.Env = append(os.Environ(), unbalancedUnlockChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("child output:\n%s", out)
	if strings.Contains(string(out), "--- SKIP") {
		t.Skip("child could not set the scenario up; see its output")
	}
	if err != nil {
		t.Fatalf("child failed: %v", err)
	}
}

// unbalancedWindow is one run of the misuse.
type unbalancedWindow struct {
	entryTID  int // thread the window was opened on
	exitTID   int // thread fn finished on
	helperTID int // thread the helper pinned itself to; must equal entryTID
	panicked  any // what restore panicked with, nil if it returned
	release   chan struct{}
}

// runUnbalancedWindow opens a window, unbalances the pin from inside it, and
// forces the goroutine onto another thread before restore runs.
//
// The migration is forced rather than raced for. After the unbalancing
// UnlockOSThread, fn spawns a helper: `go` puts it in the CURRENT P's runnext,
// so when fn parks on the channel the entry thread runs the helper next. The
// helper locks itself to that thread — the entry thread — readies fn, and parks.
// A thread whose locked goroutine parks cannot run anything else: it hands its P
// off to another M (stoplockedm/handoffp) and sleeps until its own goroutine is
// runnable again. fn is therefore resumed by some other thread, deterministically
// — provided the helper did land on the entry thread, which helperTID records so
// the caller can tell a forced migration from a lucky one.
func runUnbalancedWindow() (r unbalancedWindow) {
	r.release = make(chan struct{})
	helper := make(chan int)
	defer func() { r.panicked = recover() }()
	Scrub(func() {
		r.entryTID = unix.Gettid()
		runtime.UnlockOSThread() // the misuse: pairs with the window's own LockOSThread, not one of fn's

		go func() {
			runtime.LockOSThread()
			helper <- unix.Gettid()
			<-r.release
		}()
		r.helperTID = <-helper
		r.exitTID = unix.Gettid()
	})
	return r
}

func unbalancedUnlockChild(t *testing.T) {
	const attempts = 20
	for attempt := 1; attempt <= attempts; attempt++ {
		r := runUnbalancedWindow()
		if r.exitTID == r.entryTID {
			// The helper was stolen off the entry P before it ran there, so
			// nothing forced the move. Nothing leaked either: restore ran on
			// the thread it saved. Let the helper go and try again.
			t.Logf("attempt %d: goroutine stayed on tid %d (helper pinned tid %d); retrying",
				attempt, r.entryTID, r.helperTID)
			close(r.release)
			continue
		}
		t.Logf("attempt %d: window entered on tid %d, fn finished on tid %d, helper holds tid %d",
			attempt, r.entryTID, r.exitTID, r.helperTID)

		// The premise: the entry thread is still alive (the helper is parked on
		// it) and still has the window's signals blocked. Nothing can undo that
		// from another thread; the fix is the loud failure, not a repair.
		if m := sigBlkMaskAt(t, fmt.Sprintf("/proc/self/task/%d/status", r.entryTID)); m&sigBit(unix.SIGURG) == 0 || m&sigBit(unix.SIGPROF) == 0 {
			t.Errorf("entry thread tid %d does NOT have SIGURG/SIGPROF blocked (SigBlk=%016x): "+
				"the leak this test exists for did not happen — re-examine the scenario before trusting a pass", r.entryTID, m)
		}

		// The fix: restore must refuse, loudly, rather than write the saved mask
		// onto a thread it was never taken from and return as if nothing happened.
		if r.panicked == nil {
			t.Errorf("Scrub returned normally after fn unbalanced LockOSThread and the goroutine migrated: "+
				"tid %d is left with SIGURG and SIGPROF blocked for the rest of the process, silently", r.entryTID)
		} else if msg := fmt.Sprint(r.panicked); !strings.Contains(msg, "UnlockOSThread") {
			t.Errorf("Scrub panicked, but not with the unbalanced-lock diagnosis: %v", r.panicked)
		} else {
			t.Logf("Scrub panicked as required: %s", msg)
		}

		close(r.release) // the helper exits locked, which terminates the damaged thread
		return
	}
	t.Skipf("could not force the goroutine off its entry thread in %d attempts", attempts)
}
