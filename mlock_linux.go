//go:build linux

// Linux secure memory: guarded allocations via memfd_secret (L4) or
// mmap+mlock (L3).
//
// Every allocation is bracketed by PROT_NONE guard pages:
//
//	[ guard | secret pages | guard ]
//
// The guards are never faulted in, so they cost no RAM, and any linear
// over/under-flow that reaches them faults instead of silently reading or
// writing whatever the kernel happened to place next to the secret.
//
// ⚠ CONSTRUCTION (do not "simplify" back to MAP_FIXED):
//
//   - L3 (anon): one PROT_NONE anonymous mapping of the whole range, then
//     mprotect the middle RW and mlock it. The guards are not mlocked and
//     carry no RLIMIT_MEMLOCK charge.
//   - L4 (memfd_secret): the secretmem file is sized to the WHOLE range and
//     mapped once, PROT_NONE, at an address the kernel picks; the middle is
//     then mprotected RW. The guards are secretmem pages that are never
//     accessible. The kernel charges the whole mapping against
//     RLIMIT_MEMLOCK, so each L4 buffer costs two extra pages of budget.
//
// L4 used to reserve an anonymous range and mmap the file MAP_FIXED over its
// middle. That is not atomic on failure: when the MAP_FIXED mmap fails (for
// example EAGAIN once the memlock budget is spent), the kernel has already
// removed the middle, so the reservation has a hole another thread can map
// into. The error path then unmapped the whole reservation, destroying that
// thread's mapping — in practice the Go runtime's heap metadata, which
// crashed the GC. With a single mapping there is no hole at any instant and
// every error path unmaps only memory this call created.
//
// Destroy unmaps the OUTER range in one munmap call. Unmapping only the
// middle would leak the guards; unmapping guards separately would risk
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
// still PROT_NONE — the caller makes it usable with mprotect.
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
//   - L4: memfd_secret mapped once over the whole guarded range (Linux 5.14+)
//   - L3: PROT_NONE reservation, middle mprotect(RW) + mlock + madvise
func allocSecretMem(size int) (region secRegion, data []byte, info allocInfo, err error) {
	pageSize, rounded, total, err := guardedSizes(size)
	if err != nil {
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("allocSecretMem: %w", err)
	}

	// L4: memfd_secret — pages are kernel-locked (never swapped) and invisible
	// to core dumps by construction, so mlocked and noDump are inherently
	// true. noFork is whatever MADV_DONTFORK actually achieved on the memfd
	// mapping, reported and never assumed: the mapping is MAP_SHARED, so
	// without it a forked child does not merely inherit a copy-on-write
	// snapshot, it shares the live secret pages.
	if r, noFork, e := allocMemfdSecret(pageSize, rounded, total); e == nil {
		return r, r.inner[:size:size], allocInfo{
			offHeap:     true,
			mlocked:     true,
			memfdSecret: true,
			noDump:      true,
			noFork:      noFork,
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
		unmapOnError(outer)
		return secRegion{}, allocInfo{}, fmt.Errorf("mprotect inner RW: %w", err)
	}
	if err := unix.Mlock(inner); err != nil {
		unmapOnError(outer)
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

// allocMemfdSecret attempts the L4 path: one memfd_secret mapping covering the
// secret and both guards, with the guards left PROT_NONE. Returns an error
// (ENOSYS, EPERM, lockdown, disabled) if unavailable; the caller falls
// through to L3. noFork reports whether MADV_DONTFORK took effect on the
// mapping.
func allocMemfdSecret(pageSize, rounded, total int) (region secRegion, noFork bool, err error) {
	// This tier is attempted on 64-bit architectures only. That is a scope
	// decision, not a syscall-number hazard: 447 is memfd_secret on 386 as
	// well (and unassigned on 32-bit arm, where the call would just return
	// ENOSYS), but the isolation proofs have only ever been run on amd64 and
	// arm64, and a tier nobody has measured is not offered. 32-bit builds
	// fall through to the mmap+mlock path. The check is a compile-time
	// constant, so it costs nothing on 64-bit builds.
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return secRegion{}, false, errors.New("memfd_secret: requires a 64-bit architecture")
	}
	// Close-on-exec, asked for at creation. Without it the descriptor stays
	// inheritable for the whole window below — ftruncate and the mmap — and
	// a fork+exec from any other
	// goroutine during it hands the child a live descriptor to the secret
	// pages. secretmem is readable through that fd, so the strongest tier
	// would be the one that leaks across exec.
	//
	// The bit is O_CLOEXEC, not FD_CLOEXEC. memfd_secret(2)'s man page names
	// FD_CLOEXEC, but the kernel tests `flags & O_CLOEXEC` and returns EINVAL
	// for anything outside SECRETMEM_FLAGS_MASK|O_CLOEXEC. Passing FD_CLOEXEC
	// (bit 0) would therefore not merely fail to set close-on-exec — it would
	// fail the syscall outright and silently drop every allocation to the
	// weaker L3 path, which is worse than the leak being fixed.
	//
	// That distinction is kernel-version sensitive and this file cannot be
	// executed from the maintainer's platform, so EINVAL is not trusted to
	// mean "flag unsupported" and nothing else: it retries bare and sets
	// close-on-exec with fcntl instead. Slightly larger window than the
	// atomic form, still far smaller than none, and a tier downgrade is
	// impossible either way.
	fd, _, errno := unix.Syscall(sysMemfdSecret, uintptr(unix.O_CLOEXEC), 0, 0)
	if errno == unix.EINVAL {
		fd, _, errno = unix.Syscall(sysMemfdSecret, 0, 0, 0)
		if errno == 0 {
			if _, ferr := unix.FcntlInt(fd, unix.F_SETFD, unix.FD_CLOEXEC); ferr != nil {
				_ = unix.Close(int(fd))
				return secRegion{}, false, fmt.Errorf("memfd_secret: set FD_CLOEXEC: %w", ferr)
			}
		}
	}
	if errno != 0 {
		return secRegion{}, false, errno // ENOSYS = kernel too old / not built; EPERM = lockdown
	}
	intFD := int(fd)

	// The file covers the guards too: the whole [guard|middle|guard] range is
	// one secretmem mapping. See the file header for why there is no separate
	// anonymous reservation.
	if err := unix.Ftruncate(intFD, int64(total)); err != nil {
		_ = unix.Close(intFD)
		return secRegion{}, false, fmt.Errorf("ftruncate memfd_secret: %w", err)
	}

	// PROT_NONE everywhere first, so the guards are never accessible at any
	// instant; only the middle is opened below. The kernel picks the address,
	// so a failure here leaves nothing behind to clean up.
	outer, err := unix.Mmap(intFD, 0, total, unix.PROT_NONE, unix.MAP_SHARED)
	// The fd is closed on every path — the mapping (if any) keeps the
	// secretmem file alive.
	_ = unix.Close(intFD)
	if err != nil {
		return secRegion{}, false, fmt.Errorf("mmap memfd_secret: %w", err)
	}
	inner := outer[pageSize : pageSize+rounded]

	if err := unix.Mprotect(inner, unix.PROT_READ|unix.PROT_WRITE); err != nil {
		unmapOnError(outer)
		return secRegion{}, false, fmt.Errorf("mprotect memfd_secret inner RW: %w", err)
	}

	// Best-effort THP opt-out, as on the anon path. secretmem folios are not
	// expected to be khugepaged candidates, but the call costs nothing and
	// removes the assumption. (KSM is anon-only — not applicable here.)
	_ = unix.Madvise(inner, unix.MADV_NOHUGEPAGE)

	// Deny fork inheritance. This mapping is MAP_SHARED, so a child would not
	// get a copy-on-write snapshot but a live view of the secret pages —
	// making the strongest allocation tier the one with the weakest fork
	// posture without it. MADV_DONTFORK only sets VM_DONTCOPY on the VMA, so
	// it applies to a secretmem mapping like any other; the outcome is
	// reported rather than assumed, as on the anon path. It covers the guards
	// as well, since they are part of the same shared mapping.
	noFork = unix.Madvise(outer, unix.MADV_DONTFORK) == nil

	return secRegion{outer: outer, inner: inner}, noFork, nil
}

// allocMapAnon allocates the guarded L3 layout only — no memfd_secret
// attempt. Used for [WithoutMemfdSecret], whose buffers a kernel path that
// pins user pages must be able to use.
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
// guards and middle in one munmap. Never unmap the fields separately.
func freeSecretMem(region secRegion) error {
	if region.outer == nil {
		return nil
	}
	_ = unix.Munlock(region.inner) // best-effort: memfd_secret memory is not externally locked
	return unix.Munmap(region.outer)
}

// madviseBeforeFree asks the kernel to drop the secret area's physical frames
// ahead of the munmap in freeSecretMem, as defense-in-depth. Guards have no
// frames to drop.
//
// The area is still mlocked here — freeSecretMem does the munlock — and
// madvise(2) refuses plain MADV_DONTNEED on a range with locked pages
// (EINVAL), on both tiers: the anon tier via our own mlock, the memfd_secret
// tier because secretmem marks its VMA VM_LOCKED itself. The advice therefore
// has to be MADV_DONTNEED_LOCKED (Linux 5.18+), which discards without the
// pages being unlocked first. Unlocking first is not an alternative: munlock
// cannot clear VM_LOCKED on a secretmem VMA (mlock_fixup skips it), and on the
// anon tier it would leave the frames swappable for the instant before the
// advice — harmless after a wipe, not on the release-unwiped path. On a kernel
// older than 5.18 the advice is unknown, the call fails with EINVAL and the
// frames are simply released by the munmap that follows.
//
// What the advice buys differs per tier, and wipeAndFree's comments rely on
// exactly this:
//   - anon (L3): the frames are dropped now rather than at the munmap a few
//     instructions later; a later touch refaults a zero page. That is NOT a
//     wipe: the freed frames keep their contents on the free list until the
//     kernel zeroes them for their next user (or init_on_free does it sooner).
//   - memfd_secret (L4): only the page tables are zapped. The mapping is
//     MAP_SHARED, so the folios stay in the secretmem inode and hold the
//     secret until munmap drops the last reference, at which point the kernel
//     zeroes them itself (secretmem_free_folio). That, not this call, is the
//     backstop on this tier.
//
// The result is returned so the release-unwiped path can report it instead of
// assuming; the normal path discards it, because by then the area holds zeros
// and the munmap frees the frames either way.
func madviseBeforeFree(region secRegion) error {
	return unix.Madvise(region.inner, unix.MADV_DONTNEED_LOCKED)
}

// mprotectSecretMem applies prot to the secret area ONLY. The guards are
// permanently PROT_NONE and are never touched — re-protecting them would
// defeat their purpose.
// prot: unix.PROT_READ, unix.PROT_READ|unix.PROT_WRITE, or unix.PROT_NONE (seal).
func mprotectSecretMem(region secRegion, prot int) error {
	return unix.Mprotect(region.inner, prot)
}

// unmapOnErrorTestHook, when non-nil, runs inside unmapOnError just before
// the munmap, with the range about to be released. Tests use it to check that
// an error path only ever unmaps address space the allocator still owns.
var unmapOnErrorTestHook func(target []byte) //nolint:gochecknoglobals // test seam, nil in production.

// unmapOnError releases a mapping on an allocation error path. Every such
// path goes through here so the test seam sees all of them.
func unmapOnError(b []byte) {
	if unmapOnErrorTestHook != nil {
		unmapOnErrorTestHook(b)
	}
	_ = unix.Munmap(b)
}

// relockSecretMem is a no-op here: only Windows drops a page lock when the
// protection becomes no-access (see mlock_windows.go). mprotect(PROT_NONE)
// leaves mlock in force.
func relockSecretMem(_ secRegion) error { return nil }
