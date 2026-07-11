//go:build windows

// Windows secure memory via VirtualAlloc + VirtualLock (L3), with guard
// pages. There is no Windows equivalent of memfd_secret (L4).
//
// Guard layout: the ENTIRE [guard|middle|guard] range is reserved in one
// VirtualAlloc(MEM_RESERVE) call, then only the middle is committed
// (MEM_COMMIT, PAGE_READWRITE) and VirtualLock'd. The guards stay
// reserved-but-uncommitted: touching them raises an access violation, they
// consume no RAM, and they are not locked. VirtualFree(MEM_RELEASE) on the
// reservation base releases the whole range — reserve base and commit base
// are different addresses, which is exactly why secRegion keeps them apart.
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
	"math"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// platformHasSecureMemory: Windows provides VirtualAlloc+VirtualLock —
// constructors never need the insecure-fallback gate here.
const platformHasSecureMemory = true

// WER dump exclusion — the Windows analog of MADV_DONTDUMP. Registered
// per-allocation; HONEST LIMITS: it covers WER-generated dumps (crash
// reporting, including full dumps) only. A debugger or an explicit
// MiniDumpWriteDump by another process still captures the pages — Seal's
// kernel-keyed cipher covers the dormant window there. Registration can fail
// (WER caps the number of excluded blocks per process); the outcome is
// recorded per-allocation in allocInfo.noDump, never assumed.
//
//nolint:gochecknoglobals // process-wide lazy handles to a System32 DLL.
var (
	procWerRegisterExcludedMemoryBlock   = windows.NewLazySystemDLL("kernel32.dll").NewProc("WerRegisterExcludedMemoryBlock")
	procWerUnregisterExcludedMemoryBlock = windows.NewLazySystemDLL("kernel32.dll").NewProc("WerUnregisterExcludedMemoryBlock")
)

// werExcludeFromDumps registers the secret area for exclusion from WER
// dumps. Returns whether the exclusion is in force (HRESULT S_OK == 0).
func werExcludeFromDumps(inner []byte) bool {
	if len(inner) == 0 || len(inner) > int(^uint32(0)) {
		return false
	}
	hr, _, _ := procWerRegisterExcludedMemoryBlock.Call(
		uintptr(unsafe.Pointer(&inner[0])),
		uintptr(uint32(len(inner))),
	)
	return hr == 0
}

// werUnexclude removes the exclusion before the region is freed, releasing
// the registration slot (WER caps them per process). Best-effort.
func werUnexclude(inner []byte) {
	if len(inner) == 0 {
		return
	}
	_, _, _ = procWerUnregisterExcludedMemoryBlock.Call(uintptr(unsafe.Pointer(&inner[0])))
}

// allocSecretMem allocates a guarded, page-aligned, VirtualLock'd off-heap
// region.
//
// Returns region (outer = the full reservation, the ONLY VirtualFree target;
// inner = the committed middle, the wipe/lock/protect target), data =
// inner[:size:size] (capacity-clamped so it cannot be re-sliced into the
// canary slack), and the protection record: off-heap, mlocked, guard pages —
// Windows has no core-dump or fork-inheritance controls.
func allocSecretMem(size int) (region secRegion, data []byte, info allocInfo, err error) {
	if size <= 0 {
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("allocSecretMem: invalid size %d", size)
	}
	pageSize := os.Getpagesize()
	if size > math.MaxInt-3*pageSize {
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("allocSecretMem: size %d too large (page rounding + guards overflow)", size)
	}
	rounded := ((size + pageSize - 1) / pageSize) * pageSize
	total := rounded + 2*pageSize

	// Reserve the whole guarded range. Reserved-uncommitted pages fault on
	// any access — the reservation itself IS the guard mechanism.
	base, allocErr := windows.VirtualAlloc(0, uintptr(total),
		windows.MEM_RESERVE, windows.PAGE_NOACCESS)
	if allocErr != nil {
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("VirtualAlloc reserve: %w", allocErr)
	}

	// Commit only the middle.
	innerAddr := base + uintptr(pageSize)
	if _, commitErr := windows.VirtualAlloc(innerAddr, uintptr(rounded),
		windows.MEM_COMMIT, windows.PAGE_READWRITE); commitErr != nil {
		_ = windows.VirtualFree(base, 0, windows.MEM_RELEASE)
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("VirtualAlloc commit: %w", commitErr)
	}

	// base/innerAddr are OS-managed memory outside the GC heap — VirtualAlloc
	// returns uintptrs for kernel-owned pages the GC will never move or
	// collect. unsafe.Pointer conversion is valid here (OS allocation, not
	// GC-tracked). go vet unsafeptr fires as a false-positive because
	// VirtualAlloc is not in its exemption list. Suppressed in .golangci.yml.
	//
	//nolint:gosec // G103: unsafe.Slice over VirtualAlloc OS memory, not GC-managed.
	outer := unsafe.Slice((*byte)(unsafe.Pointer(base)), total) //nolint:govet // unsafeptr: OS memory, see file header
	inner := outer[pageSize : pageSize+rounded]

	if lockErr := windows.VirtualLock(innerAddr, uintptr(rounded)); lockErr != nil {
		_ = windows.VirtualFree(base, 0, windows.MEM_RELEASE)
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("VirtualLock: %w", lockErr)
	}

	// Best-effort WER dump exclusion; the outcome is reported, not assumed.
	noDump := werExcludeFromDumps(inner)

	region = secRegion{outer: outer, inner: inner}
	return region, inner[:size:size], allocInfo{offHeap: true, mlocked: true, noDump: noDump, guardPages: true}, nil
}

// allocMapAnon allocates off-heap memory. On Windows this is identical to
// allocSecretMem (no memfd_secret variant exists to skip).
func allocMapAnon(size int) (region secRegion, data []byte, info allocInfo, err error) {
	return allocSecretMem(size)
}

// madviseBeforeFree is a no-op on Windows — there is no equivalent to MADV_DONTNEED.
func madviseBeforeFree(_ secRegion) {}

// freeSecretMem unlocks the committed middle and releases the ENTIRE
// reservation. VirtualFree(MEM_RELEASE) must receive the RESERVATION base
// (&outer[0]) with size 0 — passing the commit base or a nonzero size fails.
func freeSecretMem(region secRegion) error {
	if len(region.outer) == 0 {
		return nil
	}
	werUnexclude(region.inner) // release the WER registration slot
	//nolint:gosec // G103: recovering VirtualAlloc addresses for VirtualUnlock/VirtualFree.
	innerAddr := uintptr(unsafe.Pointer(&region.inner[0]))
	_ = windows.VirtualUnlock(innerAddr, uintptr(len(region.inner)))
	//nolint:gosec // G103: see above.
	base := uintptr(unsafe.Pointer(&region.outer[0]))
	return windows.VirtualFree(base, 0, windows.MEM_RELEASE)
}

// mprotectSecretMem toggles the protection on the committed middle ONLY —
// the guards are never touched (they are uncommitted and must stay so).
// prot follows unix conventions and maps to Windows PAGE_* constants:
//   - 0 (PROT_NONE)            → PAGE_NOACCESS  (seal)
//   - unix.PROT_READ (1)       → PAGE_READONLY
//   - unix.PROT_READ|WRITE (3) → PAGE_READWRITE
func mprotectSecretMem(region secRegion, prot int) error {
	if len(region.inner) == 0 {
		return nil
	}
	//nolint:gosec // G103: recovering VirtualAlloc address for VirtualProtect.
	addr := uintptr(unsafe.Pointer(&region.inner[0]))

	var protect uint32
	switch prot {
	case 0: // PROT_NONE — the sealed state. Previously mismapped to
		// PAGE_READWRITE, which left "sealed" buffers readable and writable;
		// PAGE_NOACCESS is what seal means.
		protect = windows.PAGE_NOACCESS
	case 1: // PROT_READ
		protect = windows.PAGE_READONLY
	default: // PROT_READ|PROT_WRITE
		protect = windows.PAGE_READWRITE
	}

	var oldProtect uint32
	return windows.VirtualProtect(addr, uintptr(len(region.inner)), protect, &oldProtect)
}
