//go:build !amd64 && !arm64

package secmem

// archFrameScrub: no scrub-frame assembly exists for this architecture, so
// wipeScratchFrameFull is the no-op in scrubframe_generic.go and Scrub performs
// no stack erasure. Capabilities reports the gap rather than hiding it.
const archFrameScrub = false
