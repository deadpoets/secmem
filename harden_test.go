//go:build linux

package secmem

import (
	"os"
	"testing"
)

// HardenProcess itself is tested in a re-executed child
// (harden_threads_linux_test.go, harden_isolated_test.go): it is irreversible,
// and a test process left non-dumpable loses access to its own /proc/self/mem,
// which the isolation proofs read on a second -count pass.

func TestAllocMemfdSecret_OrFallback(t *testing.T) {
	t.Parallel()

	// This test verifies that allocMemfdSecret either succeeds on Linux 5.14+
	// kernels or returns a non-nil error that causes graceful fallback to mmap.
	// On older kernels (ENOSYS) or lockdown mode (EPERM) the error is expected.
	const size = 64
	pageSize := os.Getpagesize()
	roundedSize := ((size + pageSize - 1) / pageSize) * pageSize
	region, noFork, err := allocMemfdSecret(pageSize, roundedSize, roundedSize+2*pageSize)
	if err != nil {
		// Not an error — just not supported on this kernel.
		t.Logf("allocMemfdSecret unavailable on this kernel: %v (fallback to mmap)", err)
		return
	}
	defer func() { _ = freeSecretMem(region) }()

	// MADV_DONTFORK is reported, not assumed. A kernel that refuses it on a
	// secretmem VMA is a real (and load-bearing) result: the mapping is
	// MAP_SHARED, so a child would share the live secret pages.
	if !noFork {
		t.Logf("MADV_DONTFORK not in force on this memfd_secret mapping — forked children inherit it")
	}

	if len(region.inner) != roundedSize {
		t.Errorf("len(inner) = %d, want %d", len(region.inner), roundedSize)
	}
	if len(region.outer) != roundedSize+2*pageSize {
		t.Errorf("len(outer) = %d, want %d (inner + two guard pages)", len(region.outer), roundedSize+2*pageSize)
	}

	// Write and read back to confirm the MAP_FIXED region is accessible.
	buf := region.inner[:size]
	buf[0] = 0xca
	buf[size-1] = 0xfe
	if buf[0] != 0xca || buf[size-1] != 0xfe {
		t.Error("memfd_secret region not writable")
	}
}
