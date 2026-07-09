//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && amd64

// Go prototypes for AMD64 legacy hardening assembly stubs.
// Implementations live in hardened_legacy_amd64.s.
//
// DO NOT REMOVE — required for Windows/Darwin. See hardened_legacy.go header.
package secmem

// wipeScratchFrame allocates a 2 KiB local frame and zeros it via REP STOSB + SFENCE.
// Must NOT be inlined — inlining would merge the frame into the caller's frame.
//
//go:noescape
//go:noinline
func wipeScratchFrame()

// wipeScratchFrameFull allocates a 32 KiB local frame and zeros it via REP STOSB + SFENCE.
// Used by SecureContext.Close for wider coverage on scope exit.
//
//go:noescape
//go:noinline
func wipeScratchFrameFull()

// wipeBytes zeros b using REP STOSB + SFENCE.
// Intentionally omits CLFLUSH — appropriate for Go slice memory (stack/heap),
// not mmap'd SecureBuffer pages (use secureWipe in wipe_amd64.s for those).
//
//go:noescape
func wipeBytes(b []byte)
