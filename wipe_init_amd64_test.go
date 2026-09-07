//go:build amd64

package secmem

import (
	"slices"
	"testing"
)

// fakeCPUID models a processor whose maximum basic leaf is maxLeaf, following
// the SDM rule for out-of-range input: a query for a leaf above maxLeaf is
// answered with the data of leaf maxLeaf, not with zeros. leaves holds the
// EAX/EBX/ECX/EDX values of each implemented leaf (leaf 0's EAX is always
// maxLeaf); asked records every leaf queried so a test can assert leaf 7 was
// never requested from a processor that does not implement it.
type fakeCPUID struct {
	maxLeaf uint32
	leaves  map[uint32][4]uint32
	asked   []uint32
}

func (f *fakeCPUID) query(eax, _ uint32) (a, b, c, d uint32) {
	f.asked = append(f.asked, eax)
	if eax > f.maxLeaf {
		eax = f.maxLeaf
	}
	r := f.leaves[eax]
	if eax == 0 {
		r[0] = f.maxLeaf
	}
	return r[0], r[1], r[2], r[3]
}

// TestDetectCLFLUSHOPT_MaxLeafBelow7_ReportsAbsent pins the leaf-0 guard: on a
// processor that does not implement leaf 7, detection must report CLFLUSHOPT
// absent WITHOUT querying leaf 7, whatever the highest implemented leaf's EBX
// happens to hold in bit 23. Every case plants a 1 in that bit, so an
// unguarded query — which the SDM says is answered with that leaf's data —
// misreads it as the feature flag and selects the CLFLUSHOPT wipe path on a
// processor that has no such instruction.
func TestDetectCLFLUSHOPT_MaxLeafBelow7_ReportsAbsent(t *testing.T) {
	t.Parallel()

	const bit23 = uint32(1) << 23

	cases := []struct {
		name    string
		maxLeaf uint32
		ebx     uint32 // EBX of leaf maxLeaf, the leaf an out-of-range query returns
	}{
		// Leaf 1 EBX bits 23:16 are the addressable logical-processor count;
		// 128 is a spec-legal value that sets bit 23. Bits 15:8 carry the
		// CLFLUSH line size (8 * 8 = 64 bytes), as on real hardware. AMD K8
		// reports max basic leaf 1.
		{name: "K8-shaped, max leaf 1", maxLeaf: 1, ebx: 128<<16 | 8<<8},
		// AMD K10 reports max basic leaf 5 (MONITOR/MWAIT).
		{name: "K10-shaped, max leaf 5", maxLeaf: 5, ebx: bit23 | 0x40},
		// Boundary: one below the leaf being asked for.
		{name: "max leaf 6", maxLeaf: 6, ebx: bit23},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := &fakeCPUID{
				maxLeaf: tc.maxLeaf,
				leaves:  map[uint32][4]uint32{tc.maxLeaf: {0, tc.ebx, 0, 0}},
			}
			if got := detectCLFLUSHOPT(f.query); got {
				t.Errorf("detectCLFLUSHOPT = true on a processor with max basic leaf %d; "+
					"leaf 7 is not implemented, so CLFLUSHOPT must be reported absent", tc.maxLeaf)
			}
			if slices.Contains(f.asked, 7) {
				t.Errorf("leaf 7 was queried (leaves asked: %v) on a processor with max basic leaf %d; "+
					"the SDM answers that with leaf %d's data, not a feature word", f.asked, tc.maxLeaf, tc.maxLeaf)
			}
		})
	}
}

// TestDetectCLFLUSHOPT_MaxLeafAtLeast7_ReadsBit23 confirms the guard does not
// over-correct: once leaf 0 says leaf 7 exists, bit 23 of leaf 7's EBX is the
// answer, in both states, and at the boundary value maxLeaf == 7.
func TestDetectCLFLUSHOPT_MaxLeafAtLeast7_ReadsBit23(t *testing.T) {
	t.Parallel()

	const bit23 = uint32(1) << 23

	cases := []struct {
		name    string
		maxLeaf uint32
		ebx     uint32 // EBX of leaf 7
		want    bool
	}{
		{name: "max leaf 7, bit set", maxLeaf: 7, ebx: bit23, want: true},
		{name: "max leaf 7, bit clear", maxLeaf: 7, ebx: ^bit23, want: false},
		{name: "max leaf 0x1f, bit set", maxLeaf: 0x1f, ebx: bit23, want: true},
		{name: "max leaf 0x1f, bit clear", maxLeaf: 0x1f, ebx: ^bit23, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := &fakeCPUID{
				maxLeaf: tc.maxLeaf,
				leaves:  map[uint32][4]uint32{7: {0, tc.ebx, 0, 0}},
			}
			if got := detectCLFLUSHOPT(f.query); got != tc.want {
				t.Errorf("detectCLFLUSHOPT = %v, want %v (max leaf %#x, leaf 7 EBX %#08x)",
					got, tc.want, tc.maxLeaf, tc.ebx)
			}
			if !slices.Contains(f.asked, 7) {
				t.Errorf("leaf 7 was never queried (leaves asked: %v) although max basic leaf is %#x",
					f.asked, tc.maxLeaf)
			}
		})
	}
}

// TestDetectCLFLUSHOPT_MatchesInit pins the seam to the value init installed:
// running the detection again against the real CPUID must agree with
// HasCLFLUSHOPT, so the tested function is the one the wipe loop's flag came
// from and not a copy that could drift.
func TestDetectCLFLUSHOPT_MatchesInit(t *testing.T) {
	t.Parallel()

	maxLeaf, _, _, _ := cpuid(0, 0)
	got := detectCLFLUSHOPT(cpuid)
	t.Logf("CPUID(0).EAX (max basic leaf) = %#x; detectCLFLUSHOPT = %v; HasCLFLUSHOPT = %v",
		maxLeaf, got, HasCLFLUSHOPT())
	if got != HasCLFLUSHOPT() {
		t.Errorf("detectCLFLUSHOPT(cpuid) = %v but HasCLFLUSHOPT() = %v; init did not install this detection's result",
			got, HasCLFLUSHOPT())
	}
}
