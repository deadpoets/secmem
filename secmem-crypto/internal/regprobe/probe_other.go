//go:build !amd64 || purego || !gc

package regprobe

// DumpXMM has no implementation here; the tests that use it are
// amd64-only, matching the assembly they probe.
func DumpXMM(buf *[256]byte) { *buf = [256]byte{} }
