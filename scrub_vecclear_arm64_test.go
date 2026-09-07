package secmem

import (
	"testing"

	"github.com/deadpoets/secmem/internal/regprobe"
)

// TestScrub_ClearsVectorRegisters proves the arm64 clear reaches V0–V31. See
// runVecClearProof for the method. No arm64 vector register holds a fixed
// value under the Go ABI, so all 512 bytes are fillable.
func TestScrub_ClearsVectorRegisters(t *testing.T) {
	t.Log("arm64 clear path: VEOR V0–V31")
	var p, got [512]byte
	runVecClearProof(t, p[:], got[:],
		func() { regprobe.FillV(&p) },
		func() { regprobe.DumpV(&got) },
		512)
}
