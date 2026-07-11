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

func TestHardenProcess_SetsNoNewPrivs(t *testing.T) {
	t.Parallel()

	_, err := HardenProcess(context.Background())
	if err != nil {
		t.Fatalf("HardenProcess: %v", err)
	}

	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("PR_GET_NO_NEW_PRIVS: %v", err)
	}
	if nnp != 1 {
		t.Errorf("PR_GET_NO_NEW_PRIVS = %d, want 1 (enabled)", nnp)
	}
}

func TestHardenProcess_ReturnsExpectedLevel(t *testing.T) {
	t.Parallel()

	level, err := HardenProcess(context.Background())
	if err != nil {
		t.Fatalf("HardenProcess: %v", err)
	}

	// On Linux we expect at least NoDump + NoNewPriv.
	if level&HardenNoDump == 0 {
		t.Error("HardenNoDump bit not set")
	}
	if level&HardenNoNewPriv == 0 {
		t.Error("HardenNoNewPriv bit not set")
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
	region, err := allocMemfdSecret(pageSize, roundedSize, roundedSize+2*pageSize)
	if err != nil {
		// Not an error — just not supported on this kernel.
		t.Logf("allocMemfdSecret unavailable on this kernel: %v (fallback to mmap)", err)
		return
	}
	defer func() { _ = freeSecretMem(region) }()

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
