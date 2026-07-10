//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && amd64

// Go prototypes for the AMD64 legacy wipe assembly. Implementations live in
// hardened_legacy_amd64.s.
package secmem

// wipeScratchFrameFull allocates a 32 KiB local frame and zeros it via
// REP STOSB + SFENCE. SecretDo/SecretDoErr defer it on the legacy path to scrub
// register spills and callee frame data after a secret-touching call tree
// returns. Must NOT be inlined — inlining would merge the frame into the
// caller's frame.
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
