//go:build linux

package secmem

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

const quarantineSupported = true

// quarantineSecretMem replaces the whole reservation, guards and middle, with
// one anonymous PROT_NONE mapping. MAP_FIXED over a range this process owns is
// an atomic replace: at no instant is any part of it an unmapped hole that
// another mmap could claim. What was there is discarded exactly as munmap
// would discard it — the anon frames are freed, the lock is dropped with the
// mapping that carried it, and on the memfd_secret tier the last mapping of
// the secretmem file goes, at which point the kernel zeroes its folios. The
// result has no frames and no lock charge, and MAP_NORESERVE keeps it out of
// the commit accounting.
func quarantineSecretMem(region secRegion) error {
	//nolint:gosec // G103: the address of this process's own reservation is the MAP_FIXED target.
	base := unsafe.Pointer(&region.outer[0])
	got, err := unix.MmapPtr(-1, 0, base, uintptr(len(region.outer)), unix.PROT_NONE,
		unix.MAP_FIXED|unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_NORESERVE)
	if err != nil {
		return err
	}
	if got != base {
		// Cannot happen per MAP_FIXED semantics; see allocMemfdSecret.
		return errors.New("secmem: quarantine: kernel mapped the reservation at a different address")
	}
	return nil
}

// releaseQuarantined returns an evicted reservation to the OS.
func releaseQuarantined(outer []byte) error { return unix.Munmap(outer) }
