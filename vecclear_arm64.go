// Vector-register clear for the ARM64 Scrub window. The implementation lives
// in vecclear_arm64.s; the _arm64.go filename suffix constrains this file to
// arm64 builds.
package secmem

// clearVectorRegs zeroes V0–V31 on the calling thread. See vecclear_amd64.go
// for the reasoning, which is the same here: vectorised crypto (the NEON AES
// and SHA paths, ChaCha20-Poly1305) leaves its working state in the vector
// file, nothing in the Go runtime clears it, and the frame wipe cannot reach
// it. The Go internal ABI on arm64 makes every vector register caller-saved —
// F0–F15 carry arguments and results, F16–F31 are permanent scratch — and has
// no fixed-value vector register, so zeroing all thirty-two destroys nothing
// live. Proven by scrub_vecclear_test.go, which loads V0–V31 with a pattern
// inside a Scrub window and reads them back zero after it; the same test
// carries the no-clear control.
//
//go:noescape
func clearVectorRegs()
