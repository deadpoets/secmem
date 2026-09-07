//go:build darwin

// Proof tests for the zero-wired-pages backstop: instead of trusting that
// madvise returned 0, watch the frames through a second mapping of the same
// object and require the kernel to have zeroed them when freeSecretMem
// deallocated the wired mapping. A private anonymous mapping (what
// allocSecretMem hands out) cannot be aliased from user space without Mach
// APIs, so the alias here is a MAP_SHARED file mapping; the map-entry
// machinery under test (vm_map_delete -> vm_fault_unwire) is the same.

package secmem

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// aliasedPages maps a fresh file twice: front (the mapping under test, RW)
// and back (a read-only witness of the same frames). The witness is mlocked so
// the frames stay resident after front is torn down — the check must observe
// the frames, not a re-fault from the file. Cleanup releases the witness only;
// the caller owns front.
func aliasedPages(t *testing.T, pages int) (front, back []byte) {
	t.Helper()
	size := pages * unix.Getpagesize()

	f, err := os.Create(filepath.Join(t.TempDir(), "frames"))
	if err != nil {
		t.Fatalf("create backing file: %v", err)
	}
	defer func() { _ = f.Close() }() // the mappings hold their own references
	if err := f.Truncate(int64(size)); err != nil {
		t.Fatalf("truncate backing file: %v", err)
	}

	front, err = unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("mmap front: %v", err)
	}
	back, err = unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(front)
		t.Fatalf("mmap witness: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Munlock(back)
		_ = unix.Munmap(back)
	})
	if err := unix.Mlock(back); err != nil {
		_ = unix.Munmap(front)
		t.Skipf("mlock witness refused: %v", err)
	}
	return front, back
}

// pageIsZero reports whether every byte of b is zero.
func pageIsZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// TestDarwin_FreeSecretMem_ZeroesWiredFrames pins the teardown order that
// makes the allocation-time advice worth anything: freeSecretMem must let
// munmap do the unwiring. With the advice in force and the mapping still
// wired, the kernel zeroes the frames as it deletes the entry, so the witness
// reads zeros where the pattern was written. Against the previous
// freeSecretMem (munlock, then munmap) the witness keeps the pattern: the
// munlock clears the advice without zeroing — the companion test below runs
// that exact sequence.
//
// Only the first page is required: kernels up to xnu-11215 (macOS 15) reset
// the flag inside vm_fault_unwire's per-page loop and zero one page per map
// entry, xnu-12377 (macOS 26) zeroes them all. Which one ran is logged.
func TestDarwin_FreeSecretMem_ZeroesWiredFrames(t *testing.T) {
	const pages = 4
	pageSize := unix.Getpagesize()
	front, back := aliasedPages(t, pages)
	for i := range front {
		front[i] = 0xA5
	}
	if err := unix.Mlock(front); err != nil {
		_ = unix.Munmap(front)
		t.Skipf("mlock refused: %v", err)
	}
	if err := adviseZeroWiredPages(front); err != nil {
		_ = unix.Munmap(front)
		t.Fatalf("adviseZeroWiredPages on a writable, wired mapping: %v", err)
	}

	// No guards here, so outer and inner alias — as on the stub platforms.
	if err := freeSecretMem(secRegion{outer: front, inner: front}); err != nil {
		t.Fatalf("freeSecretMem: %v", err)
	}

	if !pageIsZero(back[:pageSize]) {
		t.Fatalf("first page still holds the pattern after freeSecretMem — the kernel did not " +
			"zero the wired frames at munmap (advice not in force, or an unlock ran before the " +
			"munmap and cleared it)")
	}
	zeroed := pages
	for p := 1; p < pages; p++ {
		if !pageIsZero(back[p*pageSize : (p+1)*pageSize]) {
			zeroed = p
			break
		}
	}
	if zeroed < pages {
		t.Logf("kernel zeroed %d of %d pages: pre-macOS 26 vm_fault_unwire zeroes only the first page of a wired entry", zeroed, pages)
	} else {
		t.Logf("kernel zeroed all %d pages", pages)
	}
}

// TestDarwin_MunlockClearsZeroWiredAdvice pins the kernel contract behind
// that ordering: an explicit munlock consumes the advice without zeroing
// (vm_map_unwire_nested clears the flag before unwiring), so munlock-then-
// munmap — the teardown freeSecretMem used to run — leaves every frame
// intact. If this ever fails the kernel changed, not freeSecretMem: the
// comments in mlock_darwin.go are then due for a revisit.
func TestDarwin_MunlockClearsZeroWiredAdvice(t *testing.T) {
	const pages = 2
	pageSize := unix.Getpagesize()
	front, back := aliasedPages(t, pages)
	for i := range front {
		front[i] = 0xA5
	}
	if err := unix.Mlock(front); err != nil {
		_ = unix.Munmap(front)
		t.Skipf("mlock refused: %v", err)
	}
	if err := adviseZeroWiredPages(front); err != nil {
		_ = unix.Munmap(front)
		t.Fatalf("adviseZeroWiredPages on a writable, wired mapping: %v", err)
	}

	if err := unix.Munlock(front); err != nil {
		t.Fatalf("munlock: %v", err)
	}
	if err := unix.Munmap(front); err != nil {
		t.Fatalf("munmap: %v", err)
	}

	for p := 0; p < pages; p++ {
		if pageIsZero(back[p*pageSize : (p+1)*pageSize]) {
			t.Errorf("page %d was zeroed although munlock ran before munmap — this kernel zeroes on "+
				"unlock, so the advice no longer depends on freeSecretMem's ordering", p)
		}
	}
}
