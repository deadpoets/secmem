//go:build windows

package secmem

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// addrState reports whether addr lies in address space this process has
// reserved or committed, and whether a read of it would succeed.
func addrState(t *testing.T, addr uintptr) (mapped, accessible bool) {
	t.Helper()
	var mbi windows.MemoryBasicInformation
	if err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
		t.Fatalf("VirtualQuery(%#x): %v", addr, err)
	}
	const memFree = 0x10000 // MEM_FREE
	if mbi.State == memFree {
		return false, false
	}
	readable := mbi.State == windows.MEM_COMMIT &&
		mbi.Protect&(windows.PAGE_NOACCESS|windows.PAGE_GUARD) == 0
	return true, readable
}
