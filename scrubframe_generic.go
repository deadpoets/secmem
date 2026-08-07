//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && !amd64 && !arm64

// Stub for architectures with no scrub-frame assembly (everything except amd64
// and arm64, both of which have real implementations).
//
// wipeScratchFrameFull is a no-op: zeroing stack memory safely needs
// architecture-specific assembly, so Scrub's frame scrub does nothing here and
// secret hygiene relies on the Go runtime eventually reusing freed goroutine
// stacks. Capabilities reports this — see FrameScrub.
package secmem

// wipeScratchFrameFull is a no-op on architectures without scrub assembly.
func wipeScratchFrameFull() {}
