//go:build linux

package secmem

import (
	"context"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHardenProcess_DisablesDumpable(t *testing.T) {
	t.Parallel()

	_, err := HardenProcess(context.Background())
	if err != nil {
		t.Fatalf("HardenProcess: %v", err)
	}

	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("PR_GET_DUMPABLE: %v", err)
	}
	if dumpable != 0 {
		t.Errorf("PR_GET_DUMPABLE = %d, want 0 (disabled)", dumpable)
	}
}

// TestHardenProcess_SetsNoNewPrivs checks the attribute where the level claims
// it: on every thread. Asking PR_GET_NO_NEW_PRIVS answers for one thread only,
// and not necessarily the one HardenProcess ran on.
func TestHardenProcess_SetsNoNewPrivs(t *testing.T) {
	t.Parallel()

	level, err := HardenProcess(context.Background())
	if err != nil {
		t.Fatalf("HardenProcess: %v", err)
	}
	if level&HardenNoNewPriv == 0 {
		if allThreadsSyscallAvailable() {
			t.Fatal("HardenNoNewPriv not reported although every thread can be reached")
		}
		return // a cgo binary: per-thread only, and correctly not claimed
	}
	missing, total, err := threadsWithoutNoNewPrivs()
	if err != nil {
		t.Fatalf("reading /proc/self/task: %v", err)
	}
	if len(missing) > 0 {
		t.Errorf("HardenNoNewPriv reported, but %d of %d threads do not have no_new_privs: %v", len(missing), total, missing)
	}
}

func TestHardenProcess_ReturnsExpectedLevel(t *testing.T) {
	t.Parallel()

	level, err := HardenProcess(context.Background())
	if err != nil {
		t.Fatalf("HardenProcess: %v", err)
	}

	// On Linux we expect NoDump always, and NoNewPriv exactly when the
	// attribute could be set on every thread (not in a cgo binary).
	if level&HardenNoDump == 0 {
		t.Error("HardenNoDump bit not set")
	}
	if got, want := level&HardenNoNewPriv != 0, allThreadsSyscallAvailable(); got != want {
		t.Errorf("HardenNoNewPriv reported = %v, want %v (all-threads syscall available = %v)", got, want, want)
	}
}

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
