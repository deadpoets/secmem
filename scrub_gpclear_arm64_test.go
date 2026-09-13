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
