//go:build amd64 || arm64

package secmem

// archFrameScrub: this architecture has a real wipeScratchFrameFull
// implementation (scrubframe_amd64.s / scrubframe_arm64.s), so Scrub reserves
// stack headroom and burns the band its call tree used.
const archFrameScrub = true

// archVectorClear: this architecture has a real clearVectorRegs implementation
// (vecclear_amd64.s / vecclear_arm64.s), so Scrub zeroes the vector register
// file on the working thread after fn returns.
const archVectorClear = true
