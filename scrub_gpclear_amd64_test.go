//go:build !race

package secmem

import (
	"testing"

	"github.com/deadpoets/secmem/internal/regprobe"
)

// TestScrub_ClearsGeneralPurposeRegisters proves the amd64 clear reaches BX,
// CX, DX, SI, DI, R8–R13 and R15. AX carries the probe's pointer and is not
// observed; clearGPRegs zeroes it with the rest. See runGPClearProof.
func TestScrub_ClearsGeneralPurposeRegisters(t *testing.T) {
	var p, got [96]byte
	runGPClearProof(t, p[:], got[:],
		[]string{"BX", "CX", "DX", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R15"},
		func() { regprobe.FillGP(&p) },
		func() { regprobe.DumpGP(&got) })
}

// archRegProbe is the amd64 probe for borrow_regclear_test.go: X0–X14 (X15 is
// the ABI's fixed zero and is not planted) and the general-purpose registers
// FillGP reaches.
func archRegProbe() *regProbe {
	var vp, vg [256]byte
	var gp, gg [96]byte
	return &regProbe{
		vPlanted: vp[:240], vGot: vg[:240],
		fillV: func() { regprobe.FillXMM(&vp) }, dumpV: func() { regprobe.DumpXMM(&vg) },
		gpPlanted: gp[:], gpGot: gg[:],
		gpNames: []string{"BX", "CX", "DX", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R15"},
		fillGP:  func() { regprobe.FillGP(&gp) }, dumpGP: func() { regprobe.DumpGP(&gg) },
	}
}
