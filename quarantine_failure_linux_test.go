//go:build linux

package secmem

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestQuarantine_FailedReplaceLeavesTheRangeAlone pins the error path of the
// Linux quarantine. A failed MAP_FIXED is not atomic: the kernel removes the
// old range before it builds the new mapping, so the failure can leave a hole,
// and another thread's mmap can fill it before the error returns. The
// quarantine used to fall back to unmapping the region's range, which then
// destroyed that other mapping (the shape #136 fixed on the allocation path).
//
// The replace is made to fail the way the kernel can — the region unmapped
// and a page planted at its base, standing in for the other thread — and the
// planted page has to survive Destroy.
func TestQuarantine_FailedReplaceLeavesTheRangeAlone(t *testing.T) {
	if !platformHasSecureMemory || !quarantineInForce() {
		t.Skip("the quarantine is not in force here")
	}
	buf, err := NewBuffer([]byte("quarantine replace failure"))
	if err != nil {
		t.Skipf("NewBuffer: %v (an mlock refusal is an environment condition)", err)
	}
	outer := buf.region.outer
	page := os.Getpagesize()

	var planted []byte
	prev := quarantineReplace
	t.Cleanup(func() { quarantineReplace = prev })
	quarantineReplace = func(base unsafe.Pointer, _ uintptr) (unsafe.Pointer, error) {
		// The raw call, not unix.Munmap: the kernel's partial work does not
		// touch x/sys's record of the mapping, and neither may this.
		if err := unix.MunmapPtr(base, uintptr(len(outer))); err != nil {
			t.Errorf("simulating the failed replace: munmap: %v", err)
			return nil, unix.ENOMEM
		}
		// NOREPLACE: if the runtime took the address first, plant nothing
		// rather than clobber it.
		p, err := unix.MmapPtr(-1, 0, base, uintptr(page), unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED_NOREPLACE)
		if err == nil && p == base {
			planted = unsafe.Slice((*byte)(p), page)
			planted[0] = 0xA5
		} else if err == nil {
			_ = unix.MunmapPtr(p, uintptr(page))
		}
		return nil, unix.ENOMEM
	}

	derr := buf.Destroy()
	if planted == nil {
		t.Skip("could not plant a page in the hole (address taken or MAP_FIXED_NOREPLACE unsupported)")
	}
	t.Cleanup(func() { _ = unix.MunmapPtr(unsafe.Pointer(&planted[0]), uintptr(len(planted))) })

	// MADV_NORMAL fails with ENOMEM on a range that is not mapped.
	if err := unix.Madvise(planted, unix.MADV_NORMAL); err != nil {
		t.Fatalf("the mapping planted in the hole was unmapped by Destroy (madvise: %v)", err)
	}
	if planted[0] != 0xA5 {
		t.Fatalf("the planted page was replaced: first byte %#x, want 0xa5", planted[0])
	}
	if derr == nil {
		t.Error("Destroy returned nil after the quarantine replace failed; the leftover range should be reported")
	}
}
