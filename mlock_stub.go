//go:build !linux && !darwin && !windows

// Stub for platforms without native secure memory APIs (e.g., FreeBSD, plan9).
// SECURITY DEGRADED: memory is heap-allocated, not locked, not excluded from core dumps,
// and is visible to the GC. Do not deploy to production on these platforms.
package secmem

import "fmt"

// allocSecretMem falls back to heap allocation on unsupported platforms.
// Returns (raw, data) with the same interface contract as the linux/darwin implementations.
// raw and data are the same slice (no page-rounding on heap allocations).
func allocSecretMem(size int) (raw, data []byte, err error) {
	if size <= 0 {
		return nil, nil, fmt.Errorf("allocSecretMem: invalid size %d", size)
	}
	// Page-round for API consistency — heap allocations don't need it but
	// the raw/data split contract must be maintained.
	pageSize := 4096
	roundedSize := ((size + pageSize - 1) / pageSize) * pageSize
	r := make([]byte, roundedSize)
	return r, r[:size], nil
}

// madviseBeforeFree is a no-op on platforms without madvise.
func madviseBeforeFree(_ []byte) {}

// freeSecretMem is a no-op on platforms without mmap.
func freeSecretMem(_ []byte) error {
	return nil
}

// mprotectSecretMem is a no-op on platforms without mprotect.
func mprotectSecretMem(_ []byte, _ int) error {
	return nil
}

// allocMapAnon falls back to heap allocation on unsupported platforms.
func allocMapAnon(size int) (raw, data []byte, err error) {
	return allocSecretMem(size)
}
