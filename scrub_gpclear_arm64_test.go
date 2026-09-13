//go:build !race

package secmem

import (
	"fmt"
	"testing"

	"github.com/deadpoets/secmem/internal/regprobe"
)

// TestScrub_ClearsGeneralPurposeRegisters proves the arm64 clear reaches
// R1–R17 and R19–R27. R0 carries the probe's pointer and is not observed;
// clearGPRegs zeroes it with the rest. See runGPClearProof.
func TestScrub_ClearsGeneralPurposeRegisters(t *testing.T) {
	var names []string
	for r := 1; r <= 27; r++ {
		if r != 18 {
			names = append(names, fmt.Sprintf("R%d", r))
		}
	}
	var p, got [208]byte
	runGPClearProof(t, p[:], got[:], names,
		func() { regprobe.FillGP(&p) },
		func() { regprobe.DumpGP(&got) })
}

// archRegProbe is the arm64 probe for borrow_regclear_test.go: V0–V31 and the
// general-purpose registers FillGP reaches.
func archRegProbe() *regProbe {
	var vp, vg [512]byte
	var gp, gg [208]byte
	var names []string
	for r := 1; r <= 27; r++ {
		if r != 18 {
			names = append(names, fmt.Sprintf("R%d", r))
		}
	}
	return &regProbe{
		vPlanted: vp[:], vGot: vg[:],
		fillV: func() { regprobe.FillV(&vp) }, dumpV: func() { regprobe.DumpV(&vg) },
		gpPlanted: gp[:], gpGot: gg[:], gpNames: names,
		fillGP: func() { regprobe.FillGP(&gp) }, dumpGP: func() { regprobe.DumpGP(&gg) },
	}
}
