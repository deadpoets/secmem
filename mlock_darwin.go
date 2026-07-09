//go:build darwin

package secmem

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// allocSecretMem allocates a page-aligned, locked, non-swappable memory region on Darwin.
// MADV_DONTDUMP and memfd_secret are Linux-only; this uses mmap + mlock only.
//
// Returns (raw, data) where raw is the full page-rounded mapping and data is raw[:size].
func allocSecretMem(size int) (raw, data []byte, err error) {
	if size <= 0 {
		return nil, nil, fmt.Errorf("allocSecretMem: invalid size %d", size)
	}

	pageSize := unix.Getpagesize()
	roundedSize := ((size + pageSize - 1) / pageSize) * pageSize

	r, e := unix.Mmap(-1, 0, roundedSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANON|unix.MAP_PRIVATE,
	)
	if e != nil {
		return nil, nil, fmt.Errorf("mmap: %w", e)
	}

	if e = unix.Mlock(r); e != nil {
		_ = unix.Munmap(r)
		return nil, nil, fmt.Errorf("mlock: %w", e)
	}

	return r, r[:size], nil
}

// freeSecretMem unlocks and unmaps memory allocated by allocSecretMem.
// raw must be the full page-rounded slice from allocSecretMem, not the data sub-slice.
// madviseBeforeFree advises the kernel MADV_DONTNEED before unmapping.
// On Darwin this is a no-op stub — MADV_DONTNEED behaviour differs from Linux.
func madviseBeforeFree(_ []byte) {}

func freeSecretMem(raw []byte) error {
	_ = unix.Munlock(raw)
	return unix.Munmap(raw)
}

// mprotectSecretMem applies the given protection flags to the raw mapping.
//
//nolint:unused // Called by SecureBuffer.Destroy() in PR 2a Step 3 — pre-declared here for allocation symmetry.
func mprotectSecretMem(raw []byte, prot int) error {
	return unix.Mprotect(raw, prot)
}

// allocMapAnon allocates via MAP_ANON + mlock. No memfd_secret on Darwin.
// Returns (raw, data) with the same page-aligned contract as allocSecretMem.
func allocMapAnon(size int) (raw, data []byte, err error) {
	return allocSecretMem(size)
}
