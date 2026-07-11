//go:build linux

// Linux secure memory: guarded allocations via memfd_secret (L4) or
// mmap+mlock (L3).
//
// Every allocation is bracketed by PROT_NONE guard pages:
//
//	[ guard | secret pages | guard ]
//
// The guards are reserved address space with no backing frames — they cost
// no RAM, are not mlocked (no RLIMIT_MEMLOCK charge), and any linear
// over/under-flow that reaches them faults instead of silently reading or
// writing whatever the kernel happened to place next to the secret.
//
// ⚠ SECURITY-CRITICAL ORDERING (do not "simplify"):
// The memfd_secret path CANNOT create its guards with mprotect — the guards
// and the secret belong to different kernel objects (anonymous memory vs the
// secretmem file). The only correct construction is:
//
//	1. reserve the ENTIRE range [guard|middle|guard] as one PROT_NONE
//	   anonymous mapping (nothing else can be placed inside it), then
//	2. mmap the memfd MAP_FIXED into the middle of that reservation.
//	   MAP_FIXED over our own reservation is an atomic replace — at no
//	   instant is the middle an unmapped hole another mmap could claim.
//
// Destroy unmaps the OUTER range in one munmap call, which the kernel
// splits across the anon guards and the secretmem middle. Unmapping only
// the middle would leak the guards; unmapping guards separately would risk
// leaving the secret mapped on a partial failure.

package secmem

import (
	"errors"
	"fmt"
	"math"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sysMemfdSecret is the memfd_secret(2) syscall number (asm-generic table,
// shared by amd64 and arm64). Linux 5.14+ with CONFIG_SECRETMEM only.
const sysMemfdSecret = 447

// platformHasSecureMemory: Linux provides mmap+mlock (and memfd_secret where
// available) — constructors never need the insecure-fallback gate here.
const platformHasSecureMemory = true

// guardedSizes validates size and returns (pageSize, rounded, total) where
// rounded is the page-rounded secret area and total = guard+rounded+guard.
func guardedSizes(size int) (pageSize, rounded, total int, err error) {
	if size <= 0 {
		return 0, 0, 0, fmt.Errorf("invalid size %d", size)
	}
	pageSize = unix.Getpagesize()
	if size > math.MaxInt-3*pageSize {
		return 0, 0, 0, fmt.Errorf("size %d too large (page rounding + guards overflow)", size)
	}
	rounded = ((size + pageSize - 1) / pageSize) * pageSize
	return pageSize, rounded, rounded + 2*pageSize, nil
}

// reserveGuarded mmaps one PROT_NONE reservation of total bytes and returns
// (outer, inner) where inner is the middle rounded-size window. The middle is
// still PROT_NONE — the caller makes it usable (mprotect for anon, MAP_FIXED
// for memfd).
func reserveGuarded(pageSize, rounded, total int) (outer, inner []byte, err error) {
	outer, err = unix.Mmap(-1, 0, total, unix.PROT_NONE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, nil, fmt.Errorf("mmap guard reservation: %w", err)
	}
	return outer, outer[pageSize : pageSize+rounded], nil
}

// allocSecretMem allocates a guarded, locked, non-swappable memory region.
//
// Returns:
//   - region: outer (full reservation, unmap target) and inner (page-rounded
//     secret area, wipe/lock/protect target). See secRegion.
//   - data: inner[:size:size] — the usable portion, capacity-clamped so it
//     cannot be re-sliced into the canary slack.
//   - info: which protections this allocation actually received.
//
// Attempts in order:
//   - L4: memfd_secret MAP_FIXED into a PROT_NONE reservation (Linux 5.14+)
//   - L3: PROT_NONE reservation, middle mprotect(RW) + mlock + madvise
func allocSecretMem(size int) (region secRegion, data []byte, info allocInfo, err error) {
	pageSize, rounded, total, err := guardedSizes(size)
	if err != nil {
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("allocSecretMem: %w", err)
	}

	// L4: memfd_secret — pages are kernel-locked (never swapped) and invisible
	// to core dumps by construction, so mlocked and noDump are inherently
	// true. The MAP_SHARED mapping IS inherited across fork — noFork is
	// honestly false. TODO(secmem): evaluate MADV_DONTFORK on the memfd
	// mapping.
	if r, e := allocMemfdSecret(pageSize, rounded, total); e == nil {
		return r, r.inner[:size:size], allocInfo{
			offHeap:     true,
			mlocked:     true,
			memfdSecret: true,
			noDump:      true,
			guardPages:  true,
		}, nil
	}

	// L3: guarded mmap + mlock + madvise.
	region, info, err = allocMapAnonGuarded(pageSize, rounded, total)
	if err != nil {
		return secRegion{}, nil, allocInfo{}, err
	}
	return region, region.inner[:size:size], info, nil
}

// allocMapAnonGuarded is the shared L3 body: reserve guards, open the middle
// RW, lock it, apply best-effort madvise. On ANY failure the whole
// reservation is unmapped — no partial layouts escape.
func allocMapAnonGuarded(pageSize, rounded, total int) (secRegion, allocInfo, error) {
	outer, inner, err := reserveGuarded(pageSize, rounded, total)
	if err != nil {
		return secRegion{}, allocInfo{}, err
	}

	if err := unix.Mprotect(inner, unix.PROT_READ|unix.PROT_WRITE); err != nil {
		_ = unix.Munmap(outer)
		return secRegion{}, allocInfo{}, fmt.Errorf("mprotect inner RW: %w", err)
	}
	if err := unix.Mlock(inner); err != nil {
		_ = unix.Munmap(outer)
		return secRegion{}, allocInfo{}, fmt.Errorf("mlock: %w", err)
	}

	// Best-effort — not all kernels support both flags. The outcome is not
	// swallowed: it is recorded in info so Capabilities can report the truth.
	noDump := unix.Madvise(inner, unix.MADV_DONTDUMP) == nil
	noFork := unix.Madvise(inner, unix.MADV_DONTFORK) == nil

	// Deny the kernel's page-copying optimizations — both can duplicate
	// secret bytes onto physical frames outside our wipe's reach:
	//   - NOHUGEPAGE: khugepaged collapses anon pages into a transparent
	//     hugepage by COPYING them and freeing the originals unwiped.
	//   - UNMERGEABLE: with PR_SET_MEMORY_MERGE (Linux 6.4+) a container
	//     runtime can opt a whole process into KSM, deduplicating identical
	//     secret pages across processes — a cross-process timing channel.
	// Failures are swallowed deliberately: they mean the kernel was built
	// without THP/KSM, i.e. the threat being disabled does not exist.
	_ = unix.Madvise(inner, unix.MADV_NOHUGEPAGE)
	_ = unix.Madvise(inner, unix.MADV_UNMERGEABLE)

	return secRegion{outer: outer, inner: inner}, allocInfo{
		offHeap:    true,
		mlocked:    true,
		noDump:     noDump,
		noFork:     noFork,
		guardPages: true,
	}, nil
}

// allocMemfdSecret attempts the L4 path: a memfd_secret file mapped MAP_FIXED
// into the middle of a pre-reserved PROT_NONE range. Returns an error
// (ENOSYS, EPERM, lockdown, disabled) if unavailable; the caller falls
// through to L3.
func allocMemfdSecret(pageSize, rounded, total int) (secRegion, error) {
	fd, _, errno := unix.Syscall(sysMemfdSecret, 0, 0, 0)
	if errno != 0 {
		return secRegion{}, errno // ENOSYS = kernel too old / not built; EPERM = lockdown
	}
	intFD := int(fd)

	if err := unix.Ftruncate(intFD, int64(rounded)); err != nil {
		_ = unix.Close(intFD)
		return secRegion{}, fmt.Errorf("ftruncate memfd_secret: %w", err)
	}

	outer, inner, err := reserveGuarded(pageSize, rounded, total)
	if err != nil {
		_ = unix.Close(intFD)
		return secRegion{}, err
	}

	// MAP_FIXED into the middle of OUR OWN reservation: an atomic replace of
	// [inner, inner+rounded) with the secretmem mapping. The guards stay anon
	// PROT_NONE. MAP_FIXED is only safe because we own the target range — it
	// would clobber arbitrary mappings otherwise.
	//nolint:gosec // G103: the pre-reserved middle's address is the MAP_FIXED target; audited above.
	mapped, err := unix.MmapPtr(intFD, 0, unsafe.Pointer(&inner[0]), uintptr(rounded),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_FIXED)
	// The fd is closed on every path — the mapping (if any) keeps the
	// secretmem file alive.
	_ = unix.Close(intFD)
	if err != nil {
		_ = unix.Munmap(outer)
		return secRegion{}, fmt.Errorf("mmap memfd_secret MAP_FIXED: %w", err)
	}
	//nolint:gosec // G103: comparing the returned mapping address against our reservation; verification only.
	if uintptr(mapped) != uintptr(unsafe.Pointer(&inner[0])) {
		// Cannot happen per MAP_FIXED semantics; checked anyway because a
		// mapping at the wrong address would put the secret outside the
		// guards. Unmap everything and refuse.
		_ = unix.MunmapPtr(mapped, uintptr(rounded))
		_ = unix.Munmap(outer)
		return secRegion{}, errors.New("mmap memfd_secret MAP_FIXED: kernel returned a different address")
	}

	// Best-effort THP opt-out, as on the anon path. secretmem folios are not
	// expected to be khugepaged candidates, but the call costs nothing and
	// removes the assumption. (KSM is anon-only — not applicable here.)
	_ = unix.Madvise(inner, unix.MADV_NOHUGEPAGE)

	return secRegion{outer: outer, inner: inner}, nil
}

// allocMapAnon allocates the guarded L3 layout only — no memfd_secret
// attempt. Used by NewSyscallSafeBuffer for ingestion paths where data
// arrives from a kernel-controlled channel.
func allocMapAnon(size int) (region secRegion, data []byte, info allocInfo, err error) {
	pageSize, rounded, total, err := guardedSizes(size)
	if err != nil {
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("allocMapAnon: %w", err)
	}
	region, info, err = allocMapAnonGuarded(pageSize, rounded, total)
	if err != nil {
		return secRegion{}, nil, allocInfo{}, err
	}
	return region, region.inner[:size:size], info, nil
}

// freeSecretMem unlocks the secret area and unmaps the ENTIRE reservation —
// guards and middle in one munmap, which the kernel splits across the anon
// and secretmem mappings. Never unmap the fields separately.
func freeSecretMem(region secRegion) error {
	if region.outer == nil {
		return nil
	}
	_ = unix.Munlock(region.inner) // best-effort: memfd_secret memory is not externally locked
	return unix.Munmap(region.outer)
}

// madviseBeforeFree advises the kernel to release the secret area's physical
// frames immediately. Called by Destroy before freeSecretMem as
// defense-in-depth. Guards have no frames to release.
func madviseBeforeFree(region secRegion) {
	_ = unix.Madvise(region.inner, unix.MADV_DONTNEED)
}

// mprotectSecretMem applies prot to the secret area ONLY. The guards are
// permanently PROT_NONE and are never touched — re-protecting them would
// defeat their purpose.
// prot: unix.PROT_READ, unix.PROT_READ|unix.PROT_WRITE, or unix.PROT_NONE (seal).
func mprotectSecretMem(region secRegion, prot int) error {
	return unix.Mprotect(region.inner, prot)
}
