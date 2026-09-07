//go:build amd64 && gc && !purego

package argon2

import "golang.org/x/sys/cpu"

// clearVectorRegs zeroes X0–X15 (and the YMM/ZMM upper halves of those
// registers where AVX is present). The SSE blamka in blamka_amd64.s loads
// whole block rows into X0–X7 and BLAKE2b's AVX2 path keeps its state in
// YMM registers; neither the Go ABI nor the scheduler clears them, so on a
// thread that goes on to run something else they are readable residue.
//
// The Go ABI treats vector registers as caller-saved scratch and X15 as a
// fixed zero, so nothing live is destroyed. vecclear_amd64_test.go checks
// empirically that the registers hold block state after blamka and are
// zero after this call — the project rule for any register scrub.
func clearVectorRegs() {
	if cpu.X86.HasAVX {
		clearVectorRegsAVX()
	} else {
		clearVectorRegsSSE()
	}
}

//go:noescape
func clearVectorRegsAVX()

//go:noescape
func clearVectorRegsSSE()
