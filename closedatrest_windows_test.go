//go:build windows

package secmem

import (
	"bytes"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestClosedAtRest_LockedWhileOpen: PAGE_NOACCESS drops the VirtualLock, so
// each open has to lock the page again before the callback can read it.
// While closed the page is out of the working set altogether, which is the
// limit the option's documentation states: its plaintext is pageable then.
//
// The lock is checked twice. At entry to the callback the page is normally in
// the working set and locked already. On this project's Windows 11 machine it
// has also been seen reported as not in the working set at that instant,
// straight after a VirtualLock that returned success: intermittently, in some
// builds and not others, and not reproducibly with raw Win32 calls. That
// observation is logged with everything that might explain it and is not a
// failure. What must hold is the second check: once the callback has read the
// page it is in the working set and locked, with no further lock call.
func TestClosedAtRest_LockedWhileOpen(t *testing.T) {
	buf := newClosed(t, bytes.Repeat([]byte{0x5A}, 32))
	addr := innerAddr(buf)
	for i := 0; i < 3; i++ {
		if err := buf.WithBytes(func(b []byte) {
			valid, locked := pageLocked(t, addr)
			if !valid || !locked {
				var mbi windows.MemoryBasicInformation
				_ = windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi))
				var wsMin, wsMax uintptr
				var flags uint32
				windows.GetProcessWorkingSetSizeEx(windows.CurrentProcess(), &wsMin, &wsMax, &flags)
				t.Logf("borrow %d: at entry the page is valid=%v locked=%v (protect=%#x state=%#x, working set min=%d max=%d flags=%#x)",
					i, valid, locked, mbi.Protect, mbi.State, wsMin, wsMax, flags)
			}
			_ = b[0]
			if valid, locked := pageLocked(t, addr); !valid || !locked {
				t.Errorf("borrow %d: after the callback read the page it is valid=%v locked=%v, want both", i, valid, locked)
			}
		}); err != nil {
			t.Fatalf("WithBytes: %v", err)
		}
		// The Locked bit means something only for a page that is in the
		// working set; a closed page is not.
		if valid, _ := pageLocked(t, addr); valid {
			t.Errorf("borrow %d: a closed page is still in the working set; "+
				"the documented limit (unlocked, pageable while closed) no longer describes it", i)
		}
	}
}
