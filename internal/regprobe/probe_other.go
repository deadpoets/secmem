//go:build !amd64 && !arm64

// Package regprobe is a test-only helper: it copies the vector register file
// to memory, and memory into the vector register file, so a test can plant a
// known pattern in the registers and see what a scrub left behind. See
// probe_amd64.go for why it is a package of its own.
//
// No implementation here: the tests that use the probes are amd64- and
// arm64-only, matching the clear they prove. The stubs exist so the package
// builds everywhere and vet can walk it.
package regprobe

// DumpXMM is the amd64 probe; it has nothing to dump here.
func DumpXMM(buf *[256]byte) { *buf = [256]byte{} }

// FillXMM is the amd64 probe; it loads nothing here.
func FillXMM(*[256]byte) {}

// DumpZMMHi is the amd64 AVX-512 probe; it has nothing to dump here.
func DumpZMMHi(buf *[1024]byte) { *buf = [1024]byte{} }

// FillZMMHi is the amd64 AVX-512 probe; it loads nothing here.
func FillZMMHi(*[1024]byte) {}

// DumpV is the arm64 probe; it has nothing to dump here.
func DumpV(buf *[512]byte) { *buf = [512]byte{} }

// FillV is the arm64 probe; it loads nothing here.
func FillV(*[512]byte) {}
