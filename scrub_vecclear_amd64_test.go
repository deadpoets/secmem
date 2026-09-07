package secmem

import (
	"testing"

	"golang.org/x/sys/cpu"

	"github.com/deadpoets/secmem/internal/regprobe"
)

// TestScrub_ClearsVectorRegisters proves the amd64 clear reaches X0–X15 (at
// XMM width; VZEROALL clears the YMM/ZMM upper halves of the same registers,
// which the probe does not separately observe). See runVecClearProof for the
// method. X15 is the ABI's fixed zero and is not planted, so 240 of the 256
// bytes are fillable.
func TestScrub_ClearsVectorRegisters(t *testing.T) {
	t.Logf("amd64 clear path: AVX=%v (VZEROALL) AVX512F=%v (Z16–Z31 via VPXORQ)", cpu.X86.HasAVX, cpu.X86.HasAVX512F)
	var p, got [256]byte
	runVecClearProof(t, p[:], got[:],
		func() { regprobe.FillXMM(&p) },
		func() { regprobe.DumpXMM(&got) },
		240)
}

// TestScrub_ClearsVectorRegistersZMMHi is the same proof for Z16–Z31, the
// registers VZEROALL does not reach. They exist only under AVX-512, so the
// proof runs only where cpu reports it; the probe routines execute AVX-512
// instructions unconditionally and must not be called otherwise.
func TestScrub_ClearsVectorRegistersZMMHi(t *testing.T) {
	if !cpu.X86.HasAVX512F {
		t.Skip("no AVX-512F: Z16–Z31 do not exist on this CPU; the proof runs where they do")
	}
	var p, got [1024]byte
	runVecClearProof(t, p[:], got[:],
		func() { regprobe.FillZMMHi(&p) },
		func() { regprobe.DumpZMMHi(&got) },
		1024)
}
