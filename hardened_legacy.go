//go:build !goexperiment.runtimesecret || !(linux && (amd64 || arm64))

// Legacy wipe helpers, compiled on platforms and builds without
// GOEXPERIMENT=runtimesecret support (non-linux, non-amd64/arm64, or the
// experiment disabled). On the primary path this file is excluded by the build
// tag and runtime/secret handles scrubbing in hardware.
//
// The cross-platform secret-scrubbing entry point is SecretDo (secretdo_*.go),
// which applies the legacy frame wipe on these builds and hardware erasure on
// the primary path. This file provides only the WipeBytes / WipeArray helpers.

package secmem

// WipeBytes zeros b using the hardened wipe path for this platform.
//
// On amd64: REP STOSB + SFENCE — hardware-accelerated, compiler-defeat-resistant.
// On other platforms: constant-time loop via crypto/subtle.
//
// WipeBytes is intended for in-process (non-mmap) memory: Go stack buffers,
// heap allocations, etc. For mmap'd SecureBuffer memory, Destroy() applies the
// full architectural wipe (LFENCE + REP STOSB + SFENCE + CLFLUSH[OPT] loop).
func WipeBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	wipeBytes(b)
}

// WipeArray zeros b. It is an alias for WipeBytes for array-backed slices.
func WipeArray(b []byte) { WipeBytes(b) }
