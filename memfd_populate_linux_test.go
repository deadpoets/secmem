//go:build linux

// Proofs for the populate step on the memfd_secret tier.
//
// Kernels carrying "mm/secretmem: properly account locked pages" charge a
// secretmem page against RLIMIT_MEMLOCK when it is first faulted and answer a
// fault over the limit with SIGBUS. An allocation whose pages are left to
// fault lazily then crashes the process at a later write instead of failing at
// the constructor. allocMemfdSecret therefore faults every page in before it
// returns, through a syscall, so a refusal is an errno.
//
// Two properties, each of which fails against the allocator without the
// populate step on any kernel that has memfd_secret:
//
//   - every page of the secret area is resident when the allocation returns;
//   - a refused page fails the tier cleanly: the mapping is released whole
//     and the allocation falls through to mmap+mlock.
//
// The kernel-side refusal itself (a real over-budget fault) is exercised by
// TestMlockFailure_ReturnsErrorNotPanic, TestNewBuffer_WipesInputOnFailure and
// TestAllocFailure_UnmapsOnlyOwnedAddressSpace on a kernel with the per-fault
// accounting; without the populate step the first two die of SIGBUS there.

package secmem

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// residentPages returns, for each page of b, whether mincore(2) reports it in
// core. For a secretmem mapping that is whether the file has a folio at that
// offset, which is exactly what a fault allocates and charges.
func residentPages(t *testing.T, b []byte) []bool {
	t.Helper()
	pageSize := os.Getpagesize()
	vec := make([]byte, (len(b)+pageSize-1)/pageSize)
	//nolint:gosec // G103: mincore takes the range address and a result vector.
	_, _, errno := unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&vec[0])))
	if errno != 0 {
		t.Fatalf("mincore: %v", errno)
	}
	out := make([]bool, len(vec))
	for i, v := range vec {
		out[i] = v&1 != 0
	}
	return out
}

func TestMemfdSecret_PopulatedAtAllocation(t *testing.T) {
	pageSize := os.Getpagesize()
	const pages = 8
	region, data, info, err := allocSecretMem(pages * pageSize)
	if err != nil {
		t.Skipf("allocSecretMem: %v (an mlock refusal is an environment condition)", err)
	}
	defer func() { _ = freeSecretMem(region) }()
	if !info.memfdSecret {
		t.Skip("memfd_secret not in force on this kernel — the mmap+mlock tier is populated by mlock itself")
	}
	for i, in := range residentPages(t, region.inner) {
		if !in {
			t.Errorf("page %d of %d is not resident after allocation: its first touch, and its memlock charge, are still to come", i, pages)
		}
	}
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d is %#x after allocation; the populate step must leave the area zeroed", i, b)
		}
	}
}

func TestMemfdSecret_PopulateRefusalFallsThrough(t *testing.T) {
	pageSize := os.Getpagesize()
	const pages = 8
	probe, _, probeInfo, err := allocSecretMem(pages * pageSize)
	if err != nil {
		t.Skipf("allocSecretMem: %v (an mlock refusal is an environment condition)", err)
	}
	_ = freeSecretMem(probe)
	if !probeInfo.memfdSecret {
		t.Skip("memfd_secret not in force on this kernel — the tier under test is never attempted")
	}

	// Refuse the fourth page the way a fault over the budget is reported to a
	// syscall, with three pages already faulted and charged.
	realTouch := populateTouch
	touched := 0
	populateTouch = func(b []byte) (int, error) {
		if touched == 3 {
			return 0, unix.EFAULT
		}
		touched++
		return realTouch(b)
	}
	var unmapped [][]byte
	unmapOnErrorTestHook = func(target []byte) { unmapped = append(unmapped, target) }
	restore := func() { populateTouch, unmapOnErrorTestHook = realTouch, nil }
	defer restore()

	region, data, info, err := allocSecretMem(pages * pageSize)
	restore()
	if err != nil {
		// The fall-through tier refused too. That is the constructor's error
		// path, which is the outcome this test exists to guarantee.
		t.Logf("allocation failed cleanly after the refused populate: %v", err)
	} else {
		defer func() { _ = freeSecretMem(region) }()
		if info.memfdSecret {
			t.Fatal("allocation reports memfd_secret although populating it was refused")
		}
		if !info.mlocked {
			t.Fatal("fall-through allocation is not mlocked")
		}
		for i := range data {
			data[i] = 0xA5 // every byte is writable without a fault
		}
	}
	if len(unmapped) == 0 {
		t.Fatal("the refused memfd_secret mapping was not released through unmapOnError")
	}
	if got, want := len(unmapped[0]), (pages+2)*pageSize; got != want {
		t.Fatalf("error path unmapped %d bytes, want the whole %d-byte reservation (guards included)", got, want)
	}
}
