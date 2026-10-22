//go:build windows

package secmem

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const quarantineSupported = true

// quarantineFailureKeepsRange is true: MEM_DECOMMIT never releases the
// reservation, so after a failed one the range is still this process's and
// retireSecretMem can fall back to freeing it.
const quarantineFailureKeepsRange = true

// quarantineSecretMem decommits the secret area and keeps the reservation.
// The guards were never committed, so afterwards the whole range is reserved
// address space with nothing behind it: any access is an access violation and
// VirtualAlloc cannot place anything there. Decommitting releases the frames
// and the working-set charge; the lock is dropped first, and the WER
// registration slot is given back, as on the plain free.
func quarantineSecretMem(region secRegion) error {
	werUnexclude(region.inner)
	//nolint:gosec // G103: recovering VirtualAlloc addresses for VirtualUnlock/VirtualFree.
	innerAddr := uintptr(unsafe.Pointer(&region.inner[0]))
	_ = windows.VirtualUnlock(innerAddr, uintptr(len(region.inner)))
	return windows.VirtualFree(innerAddr, uintptr(len(region.inner)), windows.MEM_DECOMMIT)
}

// releaseQuarantined returns an evicted reservation to the OS. As in
// freeSecretMem, MEM_RELEASE takes the reservation base and a zero size.
func releaseQuarantined(outer []byte) error {
	//nolint:gosec // G103: see quarantineSecretMem.
	return windows.VirtualFree(uintptr(unsafe.Pointer(&outer[0])), 0, windows.MEM_RELEASE)
}
