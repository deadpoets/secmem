//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && amd64

// Go prototype for the AMD64 scrub-frame assembly. The implementation lives in
// scrubframe_amd64.s.
package secmem

// wipeScratchFrameFull allocates a 32 KiB local frame and zeros it via
// REP STOSB + SFENCE. Scrub/ScrubErr call it on entry (reserve + pre-clean)
// and call it again on the legacy path once fn's frames are dead, to scrub
// register spills and callee frame data (scrub_legacy.go). Must NOT be inlined —
// inlining would merge the frame into the caller's frame.
//
//go:noescape
//go:noinline
func wipeScratchFrameFull()
