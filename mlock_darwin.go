//go:build darwin

// Darwin secure memory: guarded mmap + mlock (L3). memfd_secret and the
// MADV_DONTDUMP/DONTFORK flags are Linux-only.
//
// Every allocation is bracketed by PROT_NONE guard pages (reserved address
// space, no backing frames, not mlocked): reserve the whole
// [guard|middle|guard] range PROT_NONE, mprotect the middle RW, mlock it.
// Destroy unmaps the outer range in one munmap.

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

	region = secRegion{outer: outer, inner: inner}
	return region, inner[:size:size], allocInfo{offHeap: true, mlocked: true, guardPages: true}, nil
}

// allocMapAnon allocates via the same guarded MAP_ANON + mlock layout.
// No memfd_secret exists on Darwin, so this is identical to allocSecretMem.
func allocMapAnon(size int) (region secRegion, data []byte, info allocInfo, err error) {
	return allocSecretMem(size)
}

// freeSecretMem unlocks the secret area and unmaps the ENTIRE reservation —
// guards and middle in one munmap. Never unmap the fields separately.
func freeSecretMem(region secRegion) error {
	if region.outer == nil {
		return nil
	}
	_ = unix.Munlock(region.inner)
	return unix.Munmap(region.outer)
}

// madviseBeforeFree is a no-op on Darwin — MADV_DONTNEED behaviour differs
// from Linux and is not relied upon.
func madviseBeforeFree(_ secRegion) {}

// mprotectSecretMem applies prot to the secret area ONLY. The guards are
// permanently PROT_NONE and never touched.
func mprotectSecretMem(region secRegion, prot int) error {
	return unix.Mprotect(region.inner, prot)
}
