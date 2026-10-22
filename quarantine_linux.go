//go:build linux

package secmem

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

const quarantineSupported = true

// quarantineFailureKeepsRange is false: a failed MAP_FIXED is not atomic. The
// kernel unmaps the old range before it builds the new mapping, so an error
// can leave a hole that another thread's mmap may already have filled, and
// unmapping the range afterwards would destroy that mapping (the failure
// #136 fixed on the allocation path). retireSecretMem leaves it alone.
const quarantineFailureKeepsRange = false

// quarantineSecretMem replaces the whole reservation, guards and middle, with
// one anonymous PROT_NONE mapping. A successful MAP_FIXED over a range this
// process owns is an atomic replace: the kernel holds the mmap lock
// throughout, so at no instant is any part of it an unmapped hole that
// another mmap could claim. A failed one is not; see
// quarantineFailureKeepsRange. What was there is discarded exactly as munmap
// would discard it — the anon frames are freed, the lock is dropped with the
// mapping that carried it, and on the memfd_secret tier the last mapping of
// the secretmem file goes, at which point the kernel zeroes its folios. The
// result has no frames and no lock charge, and MAP_NORESERVE keeps it out of
// the commit accounting.
func quarantineSecretMem(region secRegion) error {
	//nolint:gosec // G103: the address of this process's own reservation is the MAP_FIXED target.
	base := unsafe.Pointer(&region.outer[0])
	got, err := quarantineReplace(base, uintptr(len(region.outer)))
	if err != nil {
		return err
	}
	if got != base {
		// Cannot happen per MAP_FIXED semantics; see allocMemfdSecret.
		return errors.New("secmem: quarantine: kernel mapped the reservation at a different address")
	}
	return nil
}

// quarantineReplace is the MAP_FIXED call, a package var so a test can make it
// fail the way the kernel can: after the old range is gone.
var quarantineReplace = func(base unsafe.Pointer, length uintptr) (unsafe.Pointer, error) { //nolint:gochecknoglobals // test seam.
	return unix.MmapPtr(-1, 0, base, length, unix.PROT_NONE,
		unix.MAP_FIXED|unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_NORESERVE)
}

// releaseQuarantined returns an evicted reservation to the OS.
func releaseQuarantined(outer []byte) error { return unix.Munmap(outer) }
