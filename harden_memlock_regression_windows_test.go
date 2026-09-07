//go:build windows

package secmem

import (
	"math"
	"math/bits"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// TestEnsureMemlockLimit_RejectsRequestBeyondUintptr pins the SIZE_T bound: a
// request that cannot be represented, headroom included, is refused with the
// budget still in force — never truncated and reported as met.
//
// math.MaxUint64 overflows at every width once the headroom is added: the
// unfixed code wrapped it to a few pages, took the never-lower branch and
// returned the old budget with a nil error. The 4 GiB cases truncate only on
// 386, where uintptr(1<<32) is 0 and the same branch reported a 4 GiB budget
// as met; on amd64 they are ordinary raises that would really be attempted,
// so they are gated. 6 GiB on 386 truncated to 2 GiB, which the kernel
// accepted, and the unfixed code echoed 6 GiB back as achieved.
func TestEnsureMemlockLimit_RejectsRequestBeyondUintptr(t *testing.T) {
	requests := []uint64{math.MaxUint64}
	if bits.UintSize == 32 {
		requests = append(requests, 1<<32, 1<<32+4096, 6<<30)
	}
	for _, bytes := range requests {
		got, err := EnsureMemlockLimit(bytes)
		if err == nil {
			t.Errorf("EnsureMemlockLimit(%d) = %d, nil: a request beyond uintptr was reported as met", bytes, got)
			continue
		}
		if got >= bytes {
			t.Errorf("EnsureMemlockLimit(%d) = %d, %v: achieved value is not below the refused request", bytes, got, err)
		}
		// The value alongside the error must be a budget that is in force,
		// not the request. The budget never lowers, so it is at most the
		// current one even if a parallel test raised it in between.
		if cur := memlockBudgetInForce(t); got > cur {
			t.Errorf("EnsureMemlockLimit(%d) = %d, %v: reported more than the %d in force", bytes, got, err, cur)
		}
	}
}

// memlockRaceBudgets: the default minimum working set is a few hundred KiB,
// so two distinct raises above it need no setup beyond reading it.
func memlockRaceBudgets(t *testing.T) (small, big uint64) {
	t.Helper()
	base := memlockBudgetInForce(t)
	return base + 1<<20, base + 8<<20
}

// memlockBudgetInForce reads the working-set minimum directly and subtracts
// the same eight pages of headroom ensureMemlockLimit adds, so the number is
// comparable with what EnsureMemlockLimit reports without going through it.
func memlockBudgetInForce(t *testing.T) uint64 {
	t.Helper()
	var curMin, curMax uintptr
	var flags uint32
	windows.GetProcessWorkingSetSizeEx(windows.CurrentProcess(), &curMin, &curMax, &flags)
	overhead := 8 * uintptr(os.Getpagesize())
	if curMin <= overhead {
		t.Fatalf("minimum working set %d is not above the %d headroom", curMin, overhead)
	}
	return uint64(curMin - overhead)
}
