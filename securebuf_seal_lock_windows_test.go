//go:build windows

package secmem

import (
	"bytes"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procQueryWorkingSetEx = windows.NewLazySystemDLL("psapi.dll").NewProc("QueryWorkingSetEx")

// pageLocked asks the kernel whether the page at addr is in the working set
// and locked there (PSAPI_WORKING_SET_EX_BLOCK: Valid is bit 0, Locked bit 22).
//
// The call goes through LazyProc.Call, which is //go:uintptrescapes, so the
// entry is on the heap when the kernel writes to it. windows.QueryWorkingSetEx
// takes a plain uintptr: the entry would stay on this goroutine's stack, and
// a stack move before the system call would leave this code reading zeros,
// which is "not valid, not locked" with a nil error.
func pageLocked(t *testing.T, addr uintptr) (valid, locked bool) {
	t.Helper()
	e := struct{ addr, attrs uintptr }{addr: addr}
	r, _, err := procQueryWorkingSetEx.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&e)), unsafe.Sizeof(e))
	if r == 0 {
		t.Fatalf("QueryWorkingSetEx: %v", err)
	}
	return e.attrs&1 != 0, e.attrs&(1<<22) != 0
}

// TestSeal_UnsealRestoresVirtualLock: PAGE_NOACCESS removes a page from the
// working set and with it the VirtualLock, and VirtualProtect back to
// PAGE_READWRITE does not restore it. Unseal has to lock again, or every
// buffer that was ever sealed holds its plaintext in a pageable page while
// Capabilities still reports it locked.
func TestSeal_UnsealRestoresVirtualLock(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5A}, 32)
	buf, err := NewBuffer(bytes.Clone(secret))
	if err != nil {
		t.Skipf("NewBuffer: %v", err)
	}
	defer buf.Destroy()
	addr := uintptr(unsafe.Pointer(&buf.region.inner[0]))
	if _, locked := pageLocked(t, addr); !locked {
		t.Fatal("a fresh buffer is not locked; the probe or the allocator is wrong")
	}
	for cycle := 1; cycle <= 2; cycle++ {
		if err := buf.Seal(); err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if err := buf.Unseal(); err != nil {
			t.Fatalf("Unseal: %v", err)
		}
		// Queried before any access: the contents must not be readable
		// plaintext in an unlocked page even momentarily after Unseal.
		if valid, locked := pageLocked(t, addr); !valid || !locked {
			t.Fatalf("cycle %d: after Seal then Unseal the page is valid=%v locked=%v, want both", cycle, valid, locked)
		}
	}
	if err := buf.WithBytes(func(b []byte) {
		if !bytes.Equal(b, secret) {
			t.Error("contents changed across the seal cycles")
		}
	}); err != nil {
		t.Fatal(err)
	}
}
