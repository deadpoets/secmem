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

// QUOTA_LIMITS_HARDWS_* flags for SetProcessWorkingSetSizeEx: both limits
// soft (the memory manager may trim under pressure, matching rlimit
// semantics rather than pinning).
const quotaLimitsSoft = 0x2 | 0x8 // HARDWS_MIN_DISABLE | HARDWS_MAX_DISABLE

// setMemlockLimit raises the minimum working-set size so at least bytes of
// VirtualLock'd memory fit (the lockable ceiling on Windows is the minimum
// working-set size minus a small kernel overhead; 8 pages of headroom are
// added to cover it).
func setMemlockLimit(bytes uint64) (uint64, error) {
	h := windows.CurrentProcess()
	page := uintptr(os.Getpagesize())
	overhead := 8 * page

	var curMin, curMax uintptr
	var flags uint32
	windows.GetProcessWorkingSetSizeEx(h, &curMin, &curMax, &flags)

	newMin := uintptr(bytes) + overhead
	if newMin <= curMin {
		// Never LOWER an existing budget.
		return uint64(curMin - overhead), nil
	}
	newMax := curMax
	if newMax < newMin+overhead {
		newMax = newMin + overhead
	}

	if err := windows.SetProcessWorkingSetSizeEx(h, newMin, newMax, quotaLimitsSoft); err != nil {
		return uint64(curMin), fmt.Errorf("secmem.SetMemlockLimit: SetProcessWorkingSetSizeEx(min=%d): %w", newMin, err)
	}
	return bytes, nil
}
