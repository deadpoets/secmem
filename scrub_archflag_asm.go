//go:build amd64 || arm64

package secmem

// archFrameScrub: this architecture has a real wipeScratchFrameFull
// implementation (scrubframe_amd64.s / scrubframe_arm64.s), so Scrub reserves
// stack headroom and burns the band its call tree used.
const archFrameScrub = true
