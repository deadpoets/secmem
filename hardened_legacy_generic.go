//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && !amd64

// Non-amd64 stub for the legacy frame wipe.
//
// wipeScratchFrameFull is a no-op: we cannot safely zero stack memory without
// architecture-specific assembly, so Scrub's frame scrub is a no-op here and
// secret hygiene relies on the Go runtime eventually zeroing freed goroutine
// stacks.
package secmem

// wipeScratchFrameFull is a no-op on non-amd64 platforms.
func wipeScratchFrameFull() {}
