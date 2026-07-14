//go:build !linux && !darwin && !windows

// Stub for platforms without native secure memory APIs (e.g., FreeBSD, plan9).
// SECURITY DEGRADED: memory is heap-allocated, not locked, not excluded from
// core dumps, visible to the GC, and has NO guard pages — a heap slice has no
// address-space bracket to protect. Capabilities report all of this.
//
// Constructors on these platforms fail with ErrNoSecureMemory unless the
// caller opts in with WithInsecureFallback() — this file is reachable only
// through that explicit opt-in (see gateInsecure in options.go).
package secmem

import (
	"fmt"
	"log/slog"
	"math"
	"runtime"
	"sync"
)

// platformHasSecureMemory: no lockable off-heap memory here — constructors
// fail with ErrNoSecureMemory unless WithInsecureFallback() is passed.
const platformHasSecureMemory = false

// insecureWarnOnce backs the one-time LOUD warning on first fallback use.
var insecureWarnOnce sync.Once

// allocSecretMem falls back to heap allocation on unsupported platforms.
// Reachable only via WithInsecureFallback() — the constructor gate rejects
// un-opted-in callers before this runs. outer and inner alias the same heap
// slice (there are no guards to distinguish); data is capacity-clamped so it
// cannot be re-sliced into the canary slack. info.insecure is TRUE and
// guardPages FALSE: Capabilities and Warnings report the exposure, and the
// first allocation fires a one-time slog warning.
func allocSecretMem(size int) (region secRegion, data []byte, info allocInfo, err error) {
	if size <= 0 {
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("allocSecretMem: invalid size %d", size)
	}
	insecureWarnOnce.Do(func() {
		slog.Warn("secmem: INSECURE fallback in use — secrets are on the unprotected Go heap "+
			"(not locked, swappable, GC-visible, included in core dumps)",
			"GOOS", runtime.GOOS, "GOARCH", runtime.GOARCH)
	})
	// Page-round for API consistency — heap allocations don't need it but
	// the inner/data split contract (canary slack) must be maintained.
	pageSize := 4096
	// Guard the page-rounding against int overflow, matching the Linux/Darwin/
	// Windows allocators; without this a near-MaxInt size wraps negative and
	// make() panics instead of returning a clean error.
	if size > math.MaxInt-3*pageSize {
		return secRegion{}, nil, allocInfo{}, fmt.Errorf("allocSecretMem: size %d too large", size)
	}
	roundedSize := ((size + pageSize - 1) / pageSize) * pageSize
	r := make([]byte, roundedSize)
	return secRegion{outer: r, inner: r}, r[:size:size], allocInfo{insecure: true}, nil
}

// allocMapAnon falls back to heap allocation on unsupported platforms.
func allocMapAnon(size int) (region secRegion, data []byte, info allocInfo, err error) {
	return allocSecretMem(size)
}

// madviseBeforeFree is a no-op on platforms without madvise.
func madviseBeforeFree(_ secRegion) {}

// freeSecretMem is a no-op on platforms without mmap — the heap slice is
// reclaimed by the GC after the wipe.
func freeSecretMem(_ secRegion) error {
	return nil
}

// mprotectSecretMem is a no-op on platforms without mprotect. Seal and
// ReadOnly are therefore advisory-only here — the sealed flag blocks the API,
// but the OS enforces nothing. Capabilities.Insecure already says as much.
func mprotectSecretMem(_ secRegion, _ int) error {
	return nil
}
