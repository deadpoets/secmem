//go:build darwin

// Darwin secure memory: guarded mmap + mlock (L3). memfd_secret and the
// MADV_DONTDUMP/DONTFORK flags are Linux-only.
//
// Every allocation is bracketed by PROT_NONE guard pages (reserved address
// space, no backing frames, not mlocked): reserve the whole
// [guard|middle|guard] range PROT_NONE, mprotect the middle RW, mlock it, and
// advise MADV_ZERO_WIRED_PAGES on it. Destroy unmaps the outer range in one
// munmap — with no munlock first, see freeSecretMem.

package secmem

import (
	"fmt"
	"math"

	"golang.org/x/sys/unix"
)

// platformHasSecureMemory: Darwin provides mmap+mlock — constructors never
// need the insecure-fallback gate here.
const platformHasSecureMemory = true

// allocSecretMem allocates a guarded, page-aligned, locked, non-swappable
// region. Returns region (outer = unmap target, inner = wipe/lock/protect
// target), data = inner[:size:size] (capacity-clamped so it cannot be
// re-sliced into the canary slack), and the allocation's protection record:
// off-heap, mlocked, and guard pages — Darwin has no memfd_secret,
// MADV_DONTDUMP, or DONTFORK.
func allocSecretMem(size int) (region secRegion, data []byte, info allocInfo, err error) {
	if size <= 0 {
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("allocSecretMem: invalid size %d", size)
	}
	pageSize := unix.Getpagesize()
	if size > math.MaxInt-3*pageSize {
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("allocSecretMem: size %d too large (page rounding + guards overflow)", size)
	}
	rounded := ((size + pageSize - 1) / pageSize) * pageSize
	total := rounded + 2*pageSize

	outer, e := unix.Mmap(-1, 0, total, unix.PROT_NONE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if e != nil {
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("mmap guard reservation: %w", e)
	}
	inner := outer[pageSize : pageSize+rounded]

	if e := unix.Mprotect(inner, unix.PROT_READ|unix.PROT_WRITE); e != nil {
		_ = unix.Munmap(outer)
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("mprotect inner RW: %w", e)
	}
	if e := unix.Mlock(inner); e != nil {
		_ = unix.Munmap(outer)
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("mlock: %w", e)
	}
	// Best-effort backstop, swallowed like the Linux THP/KSM opt-outs: a
	// refusal leaves the wipe path exactly as it was. Applied here, while the
	// area is RW, because the kernel will not accept it later on a sealed
	// (PROT_NONE) or read-only region — see adviseZeroWiredPages.
	_ = adviseZeroWiredPages(inner)

	region = secRegion{outer: outer, inner: inner}
	return region, inner[:size:size], allocInfo{offHeap: true, mlocked: true, guardPages: true}, nil
}

// allocMapAnon allocates via the same guarded MAP_ANON + mlock layout.
// No memfd_secret exists on Darwin, so this is identical to allocSecretMem.
func allocMapAnon(size int) (region secRegion, data []byte, info allocInfo, err error) {
	return allocSecretMem(size)
}

// adviseZeroWiredPages asks the kernel to zero the secret area's frames itself
// if the mapping is deallocated while still mlocked — the one teardown that
// never passes through secureWipeSlice. That is the janitor's release-unwiped
// branch in wipeAndFree (mprotect back to RW failed, so the wipe cannot run),
// and the kernel tearing down the address space of a process that died
// without running the janitor at all (SIGKILL, OOM kill, a crash the
// termination handler never saw): vm_map_destroy walks the same
// vm_map_delete path.
//
// What the advice does and does not deliver, from XNU (osfmk/vm/vm_map.c,
// osfmk/vm/vm_fault.c; checked on xnu-7195 through xnu-12377 and main):
//
//   - It is a flag on the map entry (vm_map_behavior_set), honoured by
//     vm_fault_unwire when vm_map_delete unwires a still-wired entry. It
//     survives mprotect (seal / read-only), which clips entries by copy.
//   - An explicit munlock CLEARS the flag without zeroing
//     (vm_map_unwire_nested) — which is why freeSecretMem does not munlock.
//   - xnu-12377 (macOS 26) only accepts it on a writable range (EPERM
//     otherwise) and only zeroes entries that are still writable when they
//     are unwired. A sealed or read-only region released unwiped is therefore
//     NOT zeroed there; a region that was RW is zeroed in full.
//   - Kernels up to xnu-11215 (macOS 15) zero regardless of protection but
//     reset the flag inside vm_fault_unwire's per-page loop, so only the
//     FIRST page of each map entry is zeroed.
//
// So this is a backstop, not a wipe: full coverage for a writable region on
// macOS 26+, one page per entry on older kernels, nothing for a sealed region
// on new kernels. No Darwin mechanism zeroes frames behind a mapping the
// process cannot write — MADV_ZERO (xnu-12377) has the same write-access
// rule — so on the release-unwiped path this is the best the platform
// offers, and the slog.Error there stays the honest report.
func adviseZeroWiredPages(inner []byte) error {
	return unix.Madvise(inner, unix.MADV_ZERO_WIRED_PAGES)
}

// freeSecretMem unmaps the ENTIRE reservation — guards and middle in one
// munmap. Never unmap the fields separately.
//
// Deliberately no munlock first. munmap of a wired range unwires it as part
// of the deletion (vm_map_delete), and that is the only unwire that honours
// the zero-wired-pages advice from allocation: an explicit munlock clears the
// flag without zeroing (vm_map_unwire_nested), which would defeat the
// backstop on exactly the release-unwiped path it exists for. The wire count
// and the RLIMIT_MEMLOCK charge are released by the munmap either way.
func freeSecretMem(region secRegion) error {
	if region.outer == nil {
		return nil
	}
	return unix.Munmap(region.outer)
}

// madviseBeforeFree is a no-op on Darwin — MADV_DONTNEED behaviour differs
// from Linux and is not relied upon. The zero-on-release backstop is the
// map-entry flag set at allocation (adviseZeroWiredPages); re-advising here
// would be refused on the one path that needs it, where the region is still
// PROT_NONE or PROT_READ.
func madviseBeforeFree(_ secRegion) error { return nil }

// mprotectSecretMem applies prot to the secret area ONLY. The guards are
// permanently PROT_NONE and never touched.
func mprotectSecretMem(region secRegion, prot int) error {
	return unix.Mprotect(region.inner, prot)
}
