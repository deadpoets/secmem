//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && arm64

// Go prototype for the ARM64 scrub-frame assembly. The implementation lives in
// scrubframe_arm64.s.
package secmem

// zeroFrameSize is the byte count wipeScratchFrameFull clears, held in a
// package variable rather than an assembly immediate so the loop bound is
// loaded from memory. It is read by the assembly only and never written.
//
//nolint:gochecknoglobals // read-only loop bound for the scrub assembly.
var zeroFrameSize uint64 = 32768

// wipeScratchFrameFull allocates a 32 KiB local frame and zeros it with STP of
// the zero register, then DMB ISHST. Scrub/ScrubErr call it on entry (to
// reserve headroom and force any stack growth before secrets exist) and defer
// it (to burn the band fn's call tree used). Must NOT be inlined — inlining
// would merge the frame into the caller's and defeat both jobs.
//
//go:noescape
//go:noinline
func wipeScratchFrameFull()
