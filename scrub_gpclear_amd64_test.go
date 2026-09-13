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
