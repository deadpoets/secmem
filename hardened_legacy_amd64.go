//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && amd64

// Go prototype for the AMD64 legacy wipe assembly. The implementation lives in
// hardened_legacy_amd64.s.
package secmem

// wipeScratchFrameFull allocates a 32 KiB local frame and zeros it via
// REP STOSB + SFENCE. Scrub/ScrubErr call it on entry (reserve + pre-clean)
// and defer it on the legacy path to scrub register spills and callee frame
// data after a secret-touching call tree returns. Must NOT be inlined —
// inlining would merge the frame into the caller's frame.
//
//go:noescape
//go:noinline
func wipeScratchFrameFull()
