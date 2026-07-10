//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && !amd64

// Non-amd64 stubs for the legacy wipe helpers.
//
// wipeScratchFrameFull is a no-op: we cannot safely zero stack memory without
// architecture-specific assembly, so SecretDo's frame scrub is a no-op here and
// secret hygiene relies on the Go runtime eventually zeroing freed goroutine
// stacks.
//
// wipeBytes uses crypto/subtle.ConstantTimeSelect to defeat compiler dead-store
// elimination: the optimizer cannot prove the zeros are unused because
// ConstantTimeSelect's result is data-dependent from its perspective.
package secmem

import "crypto/subtle"

// wipeScratchFrameFull is a no-op on non-amd64 platforms.
func wipeScratchFrameFull() {}

// wipeBytes zeros b using a constant-time loop.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = byte(subtle.ConstantTimeSelect(1, 0, int(b[i])))
	}
}
