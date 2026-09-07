//go:build linux || darwin

package secmem

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// memlockRaceBudgets opens a raise window by lowering the RLIMIT_MEMLOCK soft
// limit well below both budgets it returns. big stays within the hard limit
// so the competitor's raise needs no privilege. Child process only: the
// parent suite must never see a shrunken budget.
func memlockRaceBudgets(t *testing.T) (small, big uint64) {
	t.Helper()
	if os.Getenv(memlockRaceChildEnv) != "1" {
		t.Fatal("memlockRaceBudgets lowers RLIMIT_MEMLOCK: child process only")
	}
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	big = 64 << 20
	if rl.Max < big {
		big = rl.Max
	}
	small = big / 2
	low := 16 * uint64(os.Getpagesize())
	if small <= 2*low {
		t.Skipf("RLIMIT_MEMLOCK hard limit %d leaves no room for two distinct raises", rl.Max)
	}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: low, Max: rl.Max}); err != nil {
		t.Fatalf("setrlimit(soft=%d): %v", low, err)
	}
	return small, big
}

// memlockBudgetInForce reads the soft limit directly, independent of the
// code under test.
func memlockBudgetInForce(t *testing.T) uint64 {
	t.Helper()
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	return rl.Cur
}
