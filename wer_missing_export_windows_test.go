//go:build windows

package secmem

import (
	"testing"

	"golang.org/x/sys/windows"
)

// TestWerExclusion_MissingExportReportsNotExcluded stands in for a kernel32
// that does not export the WER exclusion calls (Wine, a trimmed image). A
// LazyProc panics when called for an export it cannot resolve, so every
// allocation panicked there, after the region was already committed and
// locked. Absence has to be the reported outcome instead: not excluded.
func TestWerExclusion_MissingExportReportsNotExcluded(t *testing.T) {
	origReg, origUnreg := procWerRegisterExcludedMemoryBlock, procWerUnregisterExcludedMemoryBlock
	defer func() {
		procWerRegisterExcludedMemoryBlock, procWerUnregisterExcludedMemoryBlock = origReg, origUnreg
	}()
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	procWerRegisterExcludedMemoryBlock = kernel32.NewProc("SecmemTestNoSuchExportRegister")
	procWerUnregisterExcludedMemoryBlock = kernel32.NewProc("SecmemTestNoSuchExportUnregister")

	area := make([]byte, 4096)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a missing WER export panicked the allocator path: %v", r)
		}
	}()
	if werExcludeFromDumps(area) {
		t.Error("werExcludeFromDumps reported the exclusion in force with no such export")
	}
	werUnexclude(area) // must be a no-op, not a panic

	// The whole constructor survives it and reports the truth.
	buf, err := NewEmptyBuffer(32)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()
	if buf.Capabilities().NoDump {
		t.Error("Capabilities().NoDump = true although the exclusion could not be registered")
	}
}
