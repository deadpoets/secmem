//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && !amd64

// Non-amd64 stubs for the legacy hardening layer.
//
// DO NOT REMOVE — required for Windows/Darwin. See hardened_legacy.go header.
//
// wipeScratchFrame and wipeScratchFrameFull are no-ops:
// we cannot safely zero stack memory without architecture-specific assembly.
// On these platforms, recover() isolation in SecureContext remains active;
// the Go GC eventually zeros freed goroutine stack frames.
//
// wipeBytes uses crypto/subtle.ConstantTimeSelect to defeat compiler
// dead-store elimination. The optimizer cannot prove the zeros are unused
// because ConstantTimeSelect's result is data-dependent from its perspective.
package secmem

import "crypto/subtle"

// wipeScratchFrame is a no-op on non-amd64 platforms.
func wipeScratchFrame() {}

// wipeScratchFrameFull is a no-op on non-amd64 platforms.
func wipeScratchFrameFull() {}

// wipeBytes zeros b using a constant-time loop.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = byte(subtle.ConstantTimeSelect(1, 0, int(b[i])))
	}
}
