//go:build amd64 && gc && !purego

package argon2

import (
	"testing"

	"github.com/deadpoets/secmem/secmem-crypto/internal/argon2/regprobe"
)

// TestClearVectorRegs is the empirical check the project requires before
// any register scrub is trusted (see the TODO in secmem's scrub_legacy.go).
// It runs the real blamka on a block of non-zero data, dumps X0–X15, and
// requires that block state is visible there (the control), then clears
// and requires all zero. Nothing between the calls is allowed to touch the
// vector registers, so the calls are back to back and the block is filled
// before the sequence starts. A failed control is a failure, not a skip:
// if a build ever makes the residue unobservable this way, the test has to
// be rethought, not silently passed.
func TestClearVectorRegs(t *testing.T) {
	var s laneScratch
	for i := range s.in {
		s.in[i] = 0x0123456789abcdef ^ uint64(i)
	}
	var out block
	var before, after [256]byte

	processBlock(&out, &s.in, &zeroBlock, &s)
	regprobe.DumpXMM(&before)
	clearVectorRegs()
	regprobe.DumpXMM(&after)

	if isZero(before[:]) {
		t.Fatal("control failed: no vector-register residue observed after blamka, so the clear cannot be shown to reach anything")
	}
	if !isZero(after[:]) {
		t.Fatalf("vector registers hold residue after clearVectorRegs: %x", after)
	}
}
