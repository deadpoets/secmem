//go:build linux || darwin || windows

// Regression test for the get-then-set window in ensureMemlockLimit: a
// caller that raises the budget between another caller's read and write must
// not have its raise overwritten by the other caller's smaller absolute
// value. The interleaving is forced through memlockTestHook, not raced for.
//
// Runs in a re-exec'd child on every platform: the unix setup LOWERS the soft
// limit to open a raise path, and the raises themselves should not leak into
// the rest of the suite either way.

package secmem

import (
	"os"
	"os/exec"
	"testing"
)

const memlockRaceChildEnv = "SECMEM_MEMLOCK_RACE_CHILD"

func TestEnsureMemlockLimit_CompetingRaiseNotLowered(t *testing.T) {
	if os.Getenv(memlockRaceChildEnv) == "1" {
		memlockCompetingRaiseChild(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestEnsureMemlockLimit_CompetingRaiseNotLowered$", "-test.v")
	cmd.Env = append(os.Environ(), memlockRaceChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated child failed: %v\n%s", err, out)
	}
}

// memlockCompetingRaiseChild is the in-child body. G1 asks for small. At the
// seam between G1's read and G1's write a competitor G2 asks for big and runs
// to completion — if nothing serializes the window. G2 is then the writer G1
// never saw: an unserialized G1 goes on to set the budget to small, below
// what G2 was just told it achieved.
//
// Under the fix the seam fires with memlockMu held, where a synchronous G2
// would deadlock rather than interleave. The hook tells the two apart with
// TryLock: held means the window is closed, and G2 runs after G1 instead.
// Either way the outcome is decided by the lock, not by scheduling.
func memlockCompetingRaiseChild(t *testing.T) {
	small, big := memlockRaceBudgets(t)

	var fired, competitorRan bool
	memlockTestHook = func() {
		memlockTestHook = nil
		fired = true
		if !memlockMu.TryLock() {
			return // serialized: the window between get and set is closed.
		}
		memlockMu.Unlock()
		competitorRan = true
		memlockRaceRaise(t, big)
	}
	t.Cleanup(func() { memlockTestHook = nil })

	got, err := EnsureMemlockLimit(small)
	if err != nil {
		t.Fatalf("EnsureMemlockLimit(%d) = %d, %v", small, got, err)
	}
	if !fired {
		t.Fatalf("EnsureMemlockLimit(%d) never reached the get/set window: the budget was already sufficient, so the setup is wrong", small)
	}
	if !competitorRan {
		memlockRaceRaise(t, big)
	}

	if cur := memlockBudgetInForce(t); cur < big {
		t.Fatalf("budget in force is %d: EnsureMemlockLimit(%d) lowered the %d that a competing EnsureMemlockLimit achieved between its read and its write",
			cur, small, big)
	}
}

// memlockRaceRaise is the competitor. It must get exactly what it asks for;
// anything less means there was no headroom to raise into and the test would
// prove nothing.
func memlockRaceRaise(t *testing.T, big uint64) {
	t.Helper()
	got, err := EnsureMemlockLimit(big)
	if err != nil {
		t.Skipf("competing EnsureMemlockLimit(%d) = %d, %v: no headroom to raise into", big, got, err)
	}
	if got != big {
		t.Fatalf("competing EnsureMemlockLimit(%d) = %d, nil: not the requested budget", big, got)
	}
}
