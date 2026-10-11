//go:build linux

// Regression test: an allocation error path must only unmap address space the
// allocator still owns.
//
// The memfd_secret tier used to reserve [guard|middle|guard] as one PROT_NONE
// mapping and then mmap the secretmem file MAP_FIXED over the middle. When
// that mmap fails (EAGAIN once the RLIMIT_MEMLOCK budget is exhausted), the
// kernel has already removed the middle, so the reservation has a hole. The
// error path then unmapped the whole reservation, destroying anything another
// thread had mapped into the hole in the meantime — in practice the Go
// runtime's own heap metadata, which crashed the GC.
//
// The interleaving is forced, not raced for: unmapOnErrorTestHook runs just
// before each error-path munmap, and the hook plays the other thread by
// mapping a page into any hole it finds in the range about to be unmapped.

package secmem

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

const allocErrorUnmapChildEnv = "SECMEM_ALLOC_ERROR_UNMAP_CHILD"

func TestAllocFailure_UnmapsOnlyOwnedAddressSpace(t *testing.T) {
	if os.Getenv(allocErrorUnmapChildEnv) == "1" {
		allocErrorUnmapChild(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestAllocFailure_UnmapsOnlyOwnedAddressSpace$", "-test.v")
	cmd.Env = append(os.Environ(), allocErrorUnmapChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated child failed: %v\n%s", err, out)
	}
	if reason, skipped := childSkipReason(out); skipped {
		t.Skipf("child skipped: %s", reason)
	}
}

// allocErrorUnmapChild lowers the memlock budget below one allocation so the
// memfd_secret tier and the mlock tier both refuse it, then checks every range
// the error paths unmap for holes.
func allocErrorUnmapChild(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("memfd_secret is 64-bit only; the tier this test covers is never attempted")
	}
	fd, _, errno := unix.Syscall(sysMemfdSecret, uintptr(unix.O_CLOEXEC), 0, 0)
	if errno != 0 {
		t.Skipf("memfd_secret unavailable (%v); the tier this test covers is never attempted", errno)
	}
	_ = unix.Close(int(fd))

	pageSize := os.Getpagesize()
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	low := uint64(16 * pageSize)
	if rl.Cur > low {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: low, Max: rl.Max}); err != nil {
			t.Fatalf("setrlimit(soft=%d): %v", low, err)
		}
	}

	var (
		calls   int
		planted []byte // a page the hook mapped into a hole, standing in for another thread
	)
	unmapOnErrorTestHook = func(target []byte) {
		calls++
		for off := 0; off+pageSize <= len(target); off += pageSize {
			page := target[off : off+pageSize]
			if err := pageMapped(page); !errors.Is(err, unix.ENOMEM) {
				continue // mapped, or the probe itself failed: not a hole
			}
			//nolint:gosec // G103: placing a page at the hole's address is the point of the test.
			p, err := unix.MmapPtr(-1, 0, unsafe.Pointer(&page[0]), uintptr(pageSize),
				unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE|unix.MAP_FIXED_NOREPLACE)
			if err != nil {
				t.Errorf("hole at %p but could not map into it: %v", &page[0], err)
				return
			}
			planted = unsafe.Slice((*byte)(p), pageSize)
			t.Errorf("an error path is about to unmap %d bytes at %p that include a hole at offset %d — address space it no longer owns",
				len(target), &target[0], off)
			return
		}
	}
	defer func() { unmapOnErrorTestHook = nil }()

	const size = 1 << 20 // far past the 16-page budget
	region, _, _, err := allocSecretMem(size)
	if err == nil {
		_ = freeSecretMem(region)
		t.Skip("allocation succeeded under a 16-page RLIMIT_MEMLOCK (CAP_IPC_LOCK?); the error paths were not reached")
	}
	if calls == 0 {
		t.Fatalf("allocSecretMem failed (%v) without any error-path unmap; the seam is not wired", err)
	}

	if planted != nil {
		if merr := pageMapped(planted); merr != nil {
			t.Fatalf("the page mapped into the hole was destroyed by the allocator's cleanup (mincore: %v)", merr)
		}
		_ = unix.MunmapPtr(unsafe.Pointer(&planted[0]), uintptr(pageSize))
	}
}

// pageMapped probes one page with mincore(2), which fails with ENOMEM when
// any part of the range is unmapped and succeeds for a mapped page whatever
// its protection. It never touches the memory.
func pageMapped(page []byte) error {
	var vec [1]byte
	//nolint:gosec // G103: mincore takes the page address and a result vector.
	_, _, errno := unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&page[0])), uintptr(len(page)), uintptr(unsafe.Pointer(&vec[0])))
	if errno != 0 {
		return errno
	}
	return nil
}
