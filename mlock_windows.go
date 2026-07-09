//go:build windows

// Windows secure memory via VirtualAlloc + VirtualLock.
// Provides L3 protection (off-heap, swap-proof, GC-invisible) — equivalent to
// Linux mmap+mlock. There is no Windows equivalent of memfd_secret (L4).
//
// Note on go vet unsafeptr (mlock_windows.go only):
// windows.VirtualAlloc returns a uintptr representing OS-managed memory that the
// GC will never move or collect. Converting it to unsafe.Pointer is safe here;
// the memory is owned by the Windows kernel, not the Go runtime.
// go vet has no exemption for non-stdlib syscall wrappers (only syscall.Syscall
// family is exempt), so the resulting false-positive is suppressed via:
//   - //nolint:govet at the call site
//   - path-scoped govet exclusion in .golangci.yml
//
// GOOS=windows go vet still fires; this is an accepted known gap. See:
//
//	https://github.com/golang/go/issues/19720
package secmem

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// allocSecretMem allocates a page-aligned, VirtualLock'd off-heap memory region.
//
// Returns:
//   - raw: full page-rounded region — pass to VirtualUnlock and VirtualFree.
//   - data: raw[:size] — the usable portion (caller's requested size).
//
// Protection: VirtualAlloc (off-heap) + VirtualLock (no swapping) = L3.
// No L4 equivalent exists on Windows.
func allocSecretMem(size int) (raw, data []byte, err error) {
	if size <= 0 {
		return nil, nil, fmt.Errorf("allocSecretMem: invalid size %d", size)
	}

	pageSize := os.Getpagesize()
	roundedSize := ((size + pageSize - 1) / pageSize) * pageSize

	addr, allocErr := windows.VirtualAlloc(0, uintptr(roundedSize),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if allocErr != nil {
		return nil, nil, fmt.Errorf("VirtualAlloc: %w", allocErr)
	}

	// addr is OS-managed memory outside the GC heap — VirtualAlloc returns a
	// uintptr for kernel-owned pages the GC will never move or collect.
	// unsafe.Pointer(addr) is valid here (Rule: OS allocation, not GC-tracked).
	// go vet unsafeptr fires as a false-positive because VirtualAlloc is not
	// in its syscall.Syscall exemption list. Suppressed in .golangci.yml.
	//
	//nolint:gosec // G103: unsafe.Slice over VirtualAlloc OS memory, not GC-managed.
	r := unsafe.Slice((*byte)(unsafe.Pointer(addr)), roundedSize) //nolint:govet // unsafeptr: OS memory, see file header

	if lockErr := windows.VirtualLock(addr, uintptr(roundedSize)); lockErr != nil {
		_ = windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		return nil, nil, fmt.Errorf("VirtualLock: %w", lockErr)
	}

	return r, r[:size], nil
}

// madviseBeforeFree is a no-op on Windows — there is no equivalent to MADV_DONTNEED.
func madviseBeforeFree(_ []byte) {}

// freeSecretMem unlocks and frees memory allocated by allocSecretMem.
// raw must be the full page-rounded slice, not the data sub-slice.
func freeSecretMem(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	//nolint:gosec // G103: recovering VirtualAlloc address for VirtualFree.
	addr := uintptr(unsafe.Pointer(&raw[0]))
	_ = windows.VirtualUnlock(addr, uintptr(len(raw)))
	return windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
}

// mprotectSecretMem toggles the protection on raw.
// prot follows unix conventions but maps to Windows PAGE_* constants:
//   - unix.PROT_READ (1)       → PAGE_READONLY
//   - unix.PROT_READ|WRITE (3) → PAGE_READWRITE
//
//nolint:unused // Called by SecureBuffer.Destroy() in PR 2a Step 3 — pre-declared here for allocation symmetry.
func mprotectSecretMem(raw []byte, prot int) error {
	if len(raw) == 0 {
		return nil
	}
	//nolint:gosec // G103: recovering VirtualAlloc address for VirtualProtect.
	addr := uintptr(unsafe.Pointer(&raw[0]))

	const protRead = 1 // unix.PROT_READ
	var protect uint32
	if prot == protRead {
		protect = windows.PAGE_READONLY
	} else {
		protect = windows.PAGE_READWRITE
	}

	var oldProtect uint32
	return windows.VirtualProtect(addr, uintptr(len(raw)), protect, &oldProtect)
}

// allocMapAnon allocates off-heap memory. On Windows this is identical to allocSecretMem.
func allocMapAnon(size int) (raw, data []byte, err error) {
	return allocSecretMem(size)
}
