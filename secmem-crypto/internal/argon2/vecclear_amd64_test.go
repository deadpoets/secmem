//go:build amd64 && gc && !purego

package argon2

import "testing"

//go:noescape
func dumpXMM(buf *[256]byte)

// TestClearVectorRegs is the empirical check the project requires before
// any register scrub is trusted (see the TODO in secmem's scrub_legacy.go).
// It runs the real blamka on a block of non-zero data, dumps X0–X15, and
// requires that block state is visible there (the control), then clears
// and requires all zero. Nothing between the calls is allowed to touch the
// vector registers, so the calls are back to back and the block is filled
// before the sequence starts.
func TestClearVectorRegs(t *testing.T) {
	var s laneScratch
	for i := range s.in {
		s.in[i] = 0x0123456789abcdef ^ uint64(i)
	}
	var out block
	var before, after [256]byte

	processBlock(&out, &s.in, &s.zero, &s)
	dumpXMM(&before)
	clearVectorRegs()
	dumpXMM(&after)

	if isZero(before[:]) {
		// The residue is real (blamka_amd64.s ends with MOVOU stores from
		// X0–X7) but its observability depends on nothing intervening; if
		// instrumentation (-race, coverage) breaks that, say so rather than
		// pass a vacuous assertion.
		t.Skip("control failed: no vector-register residue observed after blamka; cannot prove the clear reaches it under this build")
	}
	if !isZero(after[:]) {
		t.Fatalf("vector registers hold residue after clearVectorRegs: %x", after)
	}
}
