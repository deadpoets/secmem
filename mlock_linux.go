//go:build linux

package secmem

import (
	"errors"
	"fmt"
	"math"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sysMemfdSecret is the memfd_secret(2) syscall number on x86_64 Linux.
// Linux 5.14+ only. Only available on amd64; other architectures fall through.
const sysMemfdSecret = 447

// allocSecretMem allocates a page-aligned, locked, non-swappable memory region.
//
// Returns:
//   - raw: the full page-rounded mmap region — use for all syscalls (Mprotect, Madvise, Munlock, Munmap).
//   - data: raw[:size] — the usable portion (caller's requested size).
//   - info: which protections this allocation actually received, for Capabilities.
//
// Attempts in order:
//   - L4: memfd_secret (Linux 5.14+, kernel-enforced isolation, amd64 only)
//   - L3: mmap(MAP_ANON|MAP_PRIVATE) + mlock + MADV_DONTDUMP + MADV_DONTFORK
//
// CRITICAL: Always pass raw (not data) to freeSecretMem and mprotect calls.
// Syscalls require the exact base address and page-aligned length of the mapping.
func allocSecretMem(size int) (raw, data []byte, info allocInfo, err error) {
	if size <= 0 {
		return nil, nil, allocInfo{}, fmt.Errorf("allocSecretMem: invalid size %d", size)
	}

	pageSize := unix.Getpagesize()
	if size > math.MaxInt-pageSize {
		return nil, nil, allocInfo{}, fmt.Errorf("allocSecretMem: size %d too large (would overflow page rounding)", size)
	}
	roundedSize := ((size + pageSize - 1) / pageSize) * pageSize

	// L4: memfd_secret — amd64 only (other arches fall through to L3).
	// memfd_secret pages are kernel-locked (never swapped) and invisible to
	// core dumps by construction, so mlocked and noDump are inherently true.
	// The MAP_SHARED mapping IS inherited across fork — noFork is honestly
	// false. TODO(secmem): evaluate MADV_DONTFORK on the memfd mapping.
	if r, d, e := allocMemfdSecret(size, roundedSize); e == nil {
		return r, d, allocInfo{
			offHeap:     true,
			mlocked:     true,
			memfdSecret: true,
			noDump:      true,
		}, nil
	}

	// L3: mmap + mlock + madvise.
	r, e := unix.Mmap(-1, 0, roundedSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANON|unix.MAP_PRIVATE,
	)
	if e != nil {
		return nil, nil, allocInfo{}, fmt.Errorf("mmap: %w", e)
	}

	if e = unix.Mlock(r); e != nil {
		_ = unix.Munmap(r)
		return nil, nil, allocInfo{}, fmt.Errorf("mlock: %w", e)
	}

	// Best-effort — not all kernels support both flags. The outcome is not
	// swallowed: it is recorded in info so Capabilities can report the truth.
	noDump := unix.Madvise(r, unix.MADV_DONTDUMP) == nil
	noFork := unix.Madvise(r, unix.MADV_DONTFORK) == nil

	return r, r[:size], allocInfo{
		offHeap: true,
		mlocked: true,
		noDump:  noDump,
		noFork:  noFork,
	}, nil
}

// freeSecretMem unlocks and unmaps memory allocated by allocSecretMem.
// MUST receive the raw (page-rounded) slice, not the data (user-sized) slice.
func freeSecretMem(raw []byte) error {
	_ = unix.Munlock(raw) // ignore: memfd_secret memory is not externally locked.
	return unix.Munmap(raw)
}

// madviseBeforeFree advises the kernel to release physical frames immediately.
// Called by SecureBuffer.Destroy() before freeSecretMem as defense-in-depth.
func madviseBeforeFree(raw []byte) {
	_ = unix.Madvise(raw, unix.MADV_DONTNEED)
}

// mprotectSecretMem applies the given protection flags to the raw mapping.
// prot should be unix.PROT_READ (read-only) or unix.PROT_READ|unix.PROT_WRITE.
func mprotectSecretMem(raw []byte, prot int) error {
	return unix.Mprotect(raw, prot)
}

// allocMapAnon allocates via MAP_ANON only — no memfd_secret attempt.
// Used by NewSyscallSafe for Layer 2 ingestion paths.
// Returns (raw, data, info) with the same page-aligned contract as allocSecretMem.
func allocMapAnon(size int) (raw, data []byte, info allocInfo, err error) {
	if size <= 0 {
		return nil, nil, allocInfo{}, fmt.Errorf("allocMapAnon: invalid size %d", size)
	}

	pageSize := unix.Getpagesize()
	if size > math.MaxInt-pageSize {
		return nil, nil, allocInfo{}, fmt.Errorf("allocMapAnon: size %d too large (would overflow page rounding)", size)
	}
	roundedSize := ((size + pageSize - 1) / pageSize) * pageSize

	r, e := unix.Mmap(-1, 0, roundedSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANON|unix.MAP_PRIVATE,
	)
	if e != nil {
		return nil, nil, allocInfo{}, fmt.Errorf("mmap: %w", e)
	}

	if e = unix.Mlock(r); e != nil {
		_ = unix.Munmap(r)
		return nil, nil, allocInfo{}, fmt.Errorf("mlock: %w", e)
	}

	noDump := unix.Madvise(r, unix.MADV_DONTDUMP) == nil
	noFork := unix.Madvise(r, unix.MADV_DONTFORK) == nil

	return r, r[:size], allocInfo{
		offHeap: true,
		mlocked: true,
		noDump:  noDump,
		noFork:  noFork,
	}, nil
}

// allocMemfdSecret attempts to allocate via memfd_secret(2) on 64-bit Linux.
// Returns an error (ENOSYS, EPERM, or pointer-width check) if unavailable.
// The caller falls through to the mmap+mlock Layer 3 path on any error.
func allocMemfdSecret(size, roundedSize int) (raw, data []byte, err error) {
	// Only mapped on 64-bit architectures where we know the syscall number.
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return nil, nil, errors.New("memfd_secret: requires 64-bit architecture")
	}

	fd, _, errno := unix.Syscall(sysMemfdSecret, 0, 0, 0)
	if errno != 0 {
		return nil, nil, errno // ENOSYS = unsupported kernel; EPERM = lockdown mode
	}

	intFD := int(fd)

	if e := unix.Ftruncate(intFD, int64(roundedSize)); e != nil {
		_ = unix.Close(intFD)
		return nil, nil, fmt.Errorf("ftruncate memfd_secret: %w", e)
	}

	r, e := unix.Mmap(intFD, 0, roundedSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED,
	)
	// Always close the fd — the mmap keeps the anonymous file alive.
	_ = unix.Close(intFD)
	if e != nil {
		return nil, nil, fmt.Errorf("mmap memfd_secret: %w", e)
	}

	return r, r[:size], nil
}

// platformHasSecureMemory: Linux provides mmap+mlock (and memfd_secret where
// available) — constructors never need the insecure-fallback gate here.
const platformHasSecureMemory = true
