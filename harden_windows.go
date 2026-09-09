//go:build windows

// Windows process hardening: SetProcessMitigationPolicy (strict handle
// checks + Arbitrary Code Guard) and the working-set analog of the memlock
// rlimit. Both mitigation policies are IRREVERSIBLE for the process lifetime
// once applied — that is their value: a compromised process cannot quietly
// switch them back off.

package secmem

import (
	"errors"
	"fmt"
	"math/bits"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PROCESS_MITIGATION_POLICY enum values (winnt.h).
const (
	processDynamicCodePolicy       = 2 // ProcessDynamicCodePolicy
	processStrictHandleCheckPolicy = 3 // ProcessStrictHandleCheckPolicy
)

// Policy bitfields. Each PROCESS_MITIGATION_*_POLICY struct is one DWORD of
// flag bits, passed by pointer.
const (
	// PROCESS_MITIGATION_DYNAMIC_CODE_POLICY.ProhibitDynamicCode: the process
	// can no longer create executable memory or re-protect memory executable.
	dynamicCodeProhibit = 0x1

	// PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY:
	// RaiseExceptionOnInvalidHandleReference + HandleExceptionsPermanentlyEnabled.
	strictHandleRaise     = 0x1
	strictHandlePermanent = 0x2
)

//nolint:gochecknoglobals // process-wide lazy handle to a System32 DLL.
var procSetProcessMitigationPolicy = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetProcessMitigationPolicy")

// setMitigationPolicy applies one DWORD-bitfield mitigation policy.
func setMitigationPolicy(policy uintptr, flags uint32) error {
	r1, _, callErr := procSetProcessMitigationPolicy.Call(
		policy,
		//nolint:gosec // G103: passing a stack local's address to a syscall wrapper; not OS memory.
		uintptr(unsafe.Pointer(&flags)),
		unsafe.Sizeof(flags),
	)
	if r1 == 0 {
		return callErr
	}
	return nil
}

// hardenProcess applies Windows process hardening.
//
// Applied in order:
//  1. Strict handle checks — a stale/invalid HANDLE raises an exception
//     instead of silently operating on whatever object now has that value
//     (classic use-after-close secret-disclosure primitive). Permanent.
//  2. Arbitrary Code Guard — no new executable memory. Pure Go generates no
//     code at runtime; a JIT inside a cgo dependency would break, which is
//     one reason HardenProcess is opt-in.
func hardenProcess() (HardenLevel, error) {
	var level HardenLevel

	if err := setMitigationPolicy(processStrictHandleCheckPolicy, strictHandleRaise|strictHandlePermanent); err != nil {
		return level, fmt.Errorf("harden: strict handle checks: %w", err)
	}
	level |= HardenStrictHandles

	if err := setMitigationPolicy(processDynamicCodePolicy, dynamicCodeProhibit); err != nil {
		return level, fmt.Errorf("harden: arbitrary code guard: %w", err)
	}
	level |= HardenNoDynamicCode

	return level, nil
}

// disableCoreDumps: Windows has no RLIMIT_CORE. The honest per-allocation
// equivalent — WER dump exclusion — is applied automatically by the
// allocator, so there is nothing process-wide left to do here.
func disableCoreDumps() error {
	return fmt.Errorf(
		"secmem.DisableCoreDumps: Windows has no process core-dump rlimit; per-allocation WER dump exclusion is applied automatically: %w",
		errors.ErrUnsupported)
}

// QUOTA_LIMITS_HARDWS_* flags for SetProcessWorkingSetSizeEx. Both limits
// are left SOFT (the *_DISABLE flags): under memory pressure the memory
// manager may trim the working set below the minimum, which matches rlimit
// semantics — a budget, not a reservation.
//
// The trade-off, stated because the name of the alternative suggests it
// would help the secrets: a hard minimum (QUOTA_LIMITS_HARDWS_MIN_ENABLE)
// stops the balance-set manager trimming the process below newMin, at the
// cost of pinning that much of the process's OTHER pages in RAM at the
// system's expense. Working-set trimming never touches VirtualLock'd pages
// in the first place — locked pages are exactly the ones the trimmer skips —
// so the hard flag buys the secrets nothing there. The one path that does
// write locked pages to the pagefile is the memory manager outswapping an
// idle process's ENTIRE working set (see Capabilities.Mlocked); whether a
// hard minimum exempts a process from that is not documented and has not
// been measured here, so it is not claimed, and the budget stays soft.
const quotaLimitsSoft = 0x2 | 0x8 // HARDWS_MIN_DISABLE | HARDWS_MAX_DISABLE

// ensureMemlockLimit raises the minimum working-set size so at least bytes of
// VirtualLock'd memory fit (the lockable ceiling on Windows is the minimum
// working-set size minus a small kernel overhead; 8 pages of headroom are
// added to cover it).
func ensureMemlockLimit(bytes uint64) (uint64, error) {
	// Get/SetProcessWorkingSetSizeEx is a read-check-write against
	// process-global state; without the lock a smaller concurrent request
	// can write its absolute value over a larger one's raise (see memlockMu).
	memlockMu.Lock()
	defer memlockMu.Unlock()

	h := windows.CurrentProcess()
	page := uintptr(os.Getpagesize())
	overhead := 8 * page

	var curMin, curMax uintptr
	var flags uint32
	windows.GetProcessWorkingSetSizeEx(h, &curMin, &curMax, &flags)

	// The budget in force: the minimum less the headroom this function
	// adds. Every path that leaves the working set untouched reports this,
	// not the raw minimum and not the request.
	var inForce uint64
	if curMin > overhead {
		inForce = uint64(curMin - overhead)
	}

	// SetProcessWorkingSetSizeEx takes SIZE_T, so the request plus the
	// headroom added below (overhead on the minimum, overhead again on the
	// maximum) has to fit uintptr. On windows/386 that is 32 bits: a 4 GiB
	// request would otherwise truncate to 0 and be reported as already met,
	// 6 GiB would set 2 GiB and be reported as 6, and a request within a few
	// pages of 2^64 wraps the same way on amd64. A lock budget beyond the
	// address space is unsatisfiable, so refuse it and report the budget
	// actually in force — the contract is the achieved value, never the ask.
	if bytes > uint64(^uintptr(0))-2*uint64(overhead) {
		return inForce, fmt.Errorf(
			"secmem.EnsureMemlockLimit: requested %d bytes does not fit a %d-bit working-set size; achieved %d",
			bytes, bits.UintSize, inForce)
	}

	newMin := uintptr(bytes) + overhead
	if newMin <= curMin {
		// Never LOWER an existing budget.
		return inForce, nil
	}
	newMax := curMax
	if newMax < newMin+overhead {
		newMax = newMin + overhead
	}

	if memlockTestHook != nil {
		memlockTestHook()
	}

	if err := windows.SetProcessWorkingSetSizeEx(h, newMin, newMax, quotaLimitsSoft); err != nil {
		return inForce, fmt.Errorf("secmem.EnsureMemlockLimit: SetProcessWorkingSetSizeEx(min=%d): %w", newMin, err)
	}
	// Report what was set, not what was asked for. The bound check above
	// makes the two agree; the contract is still the achieved value.
	return uint64(newMin - overhead), nil
}
