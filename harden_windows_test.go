//go:build windows

package secmem

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The readback side of the mitigation API. hardenProcess only ever calls
// SetProcessMitigationPolicy and reports what that call returned; the
// child below asks the kernel what is in force through the sibling query,
// so the bits asserted are the process's, not the setter's return value.
//
//nolint:gochecknoglobals // process-wide lazy handle to a System32 DLL.
var procGetProcessMitigationPolicy = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessMitigationPolicy")

// getMitigationPolicy reads one DWORD-bitfield policy for this process.
func getMitigationPolicy(policy uintptr) (uint32, error) {
	var flags uint32
	r1, _, err := procGetProcessMitigationPolicy.Call(
		uintptr(windows.CurrentProcess()),
		policy,
		uintptr(unsafe.Pointer(&flags)),
		unsafe.Sizeof(flags),
	)
	if r1 == 0 {
		return 0, err
	}
	return flags, nil
}

// HRESULT_FROM_WIN32(ERROR_NOT_FOUND): what WerUnregisterExcludedMemoryBlock
// returns for an address it holds no registration for (measured on Windows
// 11; the documentation only says "an error code"). Typed: as an untyped
// constant it overflows int on windows/386 when passed to Logf.
const werENotFound uintptr = 0x80070490

// werUnregisterHR is the raw unregister call, HRESULT and all.
func werUnregisterHR(addr uintptr) uintptr {
	hr, _, _ := procWerUnregisterExcludedMemoryBlock.Call(addr)
	return hr
}

// TestWERExclusion_Reported verifies the WER dump exclusion is registered on
// a real allocation and surfaces through Capabilities.NoDump.
func TestWERExclusion_Reported(t *testing.T) {
	t.Parallel()
	buf, err := NewEmptyBuffer(64)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if !buf.Capabilities().NoDump {
		t.Error("Capabilities().NoDump = false on Windows — WerRegisterExcludedMemoryBlock did not take effect")
	}
}

// TestWERExclusion_RegisteredWithWER is the readback that exists for the WER
// exclusion. No independent oracle does — only a real WER dump would show
// the pages missing, and a test cannot crash the process into WER and read
// the file back — so the check is WER's own bookkeeping: the unregister call
// returns S_OK for a block WER holds and ERROR_NOT_FOUND for one it does
// not. A control block that was never registered pins the distinction; the
// secret area must then read as registered. This proves the registration
// exists, not that a dump would honour it; TESTING.md says so.
func TestWERExclusion_RegisteredWithWER(t *testing.T) {
	t.Parallel()
	page := uintptr(os.Getpagesize())

	// Control: a committed page nobody registered.
	ctrl, err := windows.VirtualAlloc(0, page, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		t.Fatalf("VirtualAlloc control: %v", err)
	}
	defer func() { _ = windows.VirtualFree(ctrl, 0, windows.MEM_RELEASE) }()
	if hr := werUnregisterHR(ctrl); hr == 0 {
		t.Fatal("control: WER reports a block that was never registered as registered — the readback distinguishes nothing")
	} else if hr != werENotFound {
		t.Logf("control: unregister of a never-registered block returned %#x (expected %#x); still non-zero, so the readback distinguishes", hr, werENotFound)
	}

	buf, err := NewEmptyBuffer(64)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()
	if !buf.Capabilities().NoDump {
		t.Fatal("Capabilities().NoDump = false; nothing to read back")
	}

	// Subject: the unregister must find the allocator's registration.
	inner := buf.region.inner
	if hr := werUnregisterHR(uintptr(unsafe.Pointer(&inner[0]))); hr != 0 {
		t.Fatalf("WER holds no exclusion for the secret area (unregister returned %#x) although the allocator reported one", hr)
	}
	// The readback consumed the registration; put it back so the buffer is
	// as the allocator left it for the rest of its life.
	if !werExcludeFromDumps(inner) {
		t.Fatal("re-registering the secret area after the readback failed")
	}
	if hr := werUnregisterHR(uintptr(unsafe.Pointer(&inner[0]))); hr != 0 {
		t.Fatalf("re-registration not visible to WER (unregister returned %#x)", hr)
	}
	if !werExcludeFromDumps(inner) {
		t.Fatal("re-registering the secret area failed")
	}
}

// TestHardenProcess_Windows runs HardenProcess in a re-exec'd child: it
// applies Arbitrary Code Guard, which is IRREVERSIBLE for the process
// lifetime and must not be imposed on the rest of the suite. The child reads
// the policies back through GetProcessMitigationPolicy before and after, so
// what is asserted is the state the kernel reports, not the setter's return.
func TestHardenProcess_Windows(t *testing.T) {
	if os.Getenv("SECMEM_HARDEN_CHILD") == "1" {
		return // child work happens in init()
	}
	cmd := exec.Command(os.Args[0], "-test.run", "TestHardenProcess_Windows", "-test.v")
	cmd.Env = append(os.Environ(), "SECMEM_HARDEN_CHILD=1")
	out, err := cmd.CombinedOutput()
	t.Logf("child output:\n%s", out)
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == hardenChildPreset {
		t.Skip("mitigations were already in force before HardenProcess ran (image or system policy) — the readback cannot attribute them to HardenProcess here")
	}
	if err != nil {
		t.Fatalf("HardenProcess child failed: %v", err)
	}
}

// hardenChildPreset is the child's exit status when the readback found the
// policies already set before hardenProcess ran.
const hardenChildPreset = 3

//nolint:gochecknoinits // deterministic child dispatch for the irreversible ACG test.
func init() {
	if os.Getenv("SECMEM_HARDEN_CHILD") != "1" {
		return
	}
	fail := func(msg string) {
		os.Stderr.WriteString(msg + "\n")
		os.Exit(1)
	}
	readBoth := func() (dyn, strict uint32) {
		var err error
		if dyn, err = getMitigationPolicy(processDynamicCodePolicy); err != nil {
			fail("GetProcessMitigationPolicy(dynamic code): " + err.Error())
		}
		if strict, err = getMitigationPolicy(processStrictHandleCheckPolicy); err != nil {
			fail("GetProcessMitigationPolicy(strict handle): " + err.Error())
		}
		return dyn, strict
	}

	// Before: neither policy may already be in force, or the readback after
	// cannot be credited to hardenProcess.
	dyn, strict := readBoth()
	if dyn&dynamicCodeProhibit != 0 || strict&(strictHandleRaise|strictHandlePermanent) != 0 {
		os.Stderr.WriteString("mitigations already in force before hardenProcess\n")
		os.Exit(hardenChildPreset)
	}

	level, err := hardenProcess()
	if err != nil {
		fail("hardenProcess: " + err.Error())
	}
	if level&HardenStrictHandles == 0 || level&HardenNoDynamicCode == 0 {
		fail("expected StrictHandles|NoDynamicCode bits")
	}

	// After: the kernel's own record of the process.
	dyn, strict = readBoth()
	if dyn&dynamicCodeProhibit == 0 {
		fail("Arbitrary Code Guard reported applied but GetProcessMitigationPolicy shows ProhibitDynamicCode clear")
	}
	if strict&strictHandleRaise == 0 || strict&strictHandlePermanent == 0 {
		fail("strict handle checks reported applied but GetProcessMitigationPolicy shows them clear or not permanent")
	}
	os.Stdout.WriteString("readback: ProhibitDynamicCode set; RaiseExceptionOnInvalidHandleReference and HandleExceptionsPermanentlyEnabled set\n")
	os.Exit(0)
}
