//go:build !amd64 && !arm64

package secmem

// archFrameScrub: no scrub-frame assembly exists for this architecture, so
// wipeScratchFrameFull is the no-op in scrubframe_generic.go and Scrub performs
// no stack erasure. Capabilities reports the gap rather than hiding it.
const archFrameScrub = false

// archVectorClear: no vector-clear assembly exists for this architecture, so
// clearVectorRegs is the no-op in vecclear_generic.go and whatever fn left in
// the vector register file survives the window. Reported, not hidden.
const archVectorClear = false
