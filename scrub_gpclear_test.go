//go:build amd64 || arm64

package secmem

import (
	"encoding/binary"
	"testing"
)

// runGPClearProof is the empirical check for clearGPRegs, the same rule the
// vector clear follows (see runVecClearProof): a register scrub ships only
// with a test showing the registers hold residue without it and do not with
// it. fill loads the probed registers from planted and dump stores them into
// got, one 8-byte word per register, named by names.
//
// General-purpose registers differ from the vector file in one way that shapes
// the test: ordinary Go code uses them all the time, so between a fill and a
// dump some are overwritten by the code in between regardless of any clear.
// The proof therefore reasons per register, never over the whole dump:
//
//  1. Probe sanity. Back to back, a fill must be observable in most of the
//     registers, or the probe observes nothing and the rest is vacuous.
//  2. Control. Scrub's window WITHOUT the register clear (legacyWindowNoClear,
//     pinned to Scrub's source by scrub_vecclear_control_pin_test.go) must let
//     at least one planted word survive to the dump — the residue a clear has
//     to remove. None surviving is a failure, not a skip: the clear would then
//     be unprovable, not proven.
//  3. Subjects. After Scrub, ScrubErr and a Scrub whose fn panics, no register
//     may still hold its planted word. The planted words are distinct, high-
//     entropy and never produced by the runtime, so a match is the pattern and
//     nothing else.
func runGPClearProof(t *testing.T, planted, got []byte, names []string, fill, dump func()) {
	t.Helper()
	if len(planted) != len(got) || len(planted) != 8*len(names) {
		t.Fatalf("probe geometry: planted %d, got %d, %d registers", len(planted), len(got), len(names))
	}
	for i := range names {
		// 0xC0DE5EC3 in the high half is a non-canonical address on both
		// architectures, so no pointer the runtime writes can equal it.
		binary.LittleEndian.PutUint64(planted[8*i:], 0xC0DE5EC3_00000000|uint64(i+1)*0x01010101)
	}
	survivors := func() []string {
		var s []string
		for i, n := range names {
			if binary.LittleEndian.Uint64(got[8*i:]) == binary.LittleEndian.Uint64(planted[8*i:]) {
				s = append(s, n)
			}
		}
		return s
	}

	// 1. Probe sanity.
	fill()
	dump()
	if s := survivors(); len(s) < len(names)/2 {
		t.Fatalf("probe sanity: only %v of %d planted registers read back straight after the fill; the probe cannot observe the registers, so nothing below can be trusted", s, len(names))
	} else {
		t.Logf("probe sanity: %d of %d registers read back after a back-to-back fill and dump", len(s), len(names))
	}

	// 2. Control.
	if vecClearControlAvailable {
		legacyWindowNoClear(fill)
		dump()
		s := survivors()
		if len(s) == 0 {
			t.Fatal("control failed: no planted general-purpose register survives the window's exit sequence without the clear, so the clear cannot be shown to remove anything")
		}
		t.Logf("control: without the clear, %v still hold their planted words after the window", s)
	} else {
		t.Log("runtime/secret active: control omitted, the legacy exit sequence it replicates does not exist on this build")
	}

	// 3. Subjects.
	Scrub(fill)
	dump()
	if s := survivors(); len(s) != 0 {
		t.Errorf("Scrub: %v still hold their planted words after the window", s)
	}
	if err := ScrubErr(func() error { fill(); return nil }); err != nil {
		t.Fatal(err)
	}
	dump()
	if s := survivors(); len(s) != 0 {
		t.Errorf("ScrubErr: %v still hold their planted words after the window", s)
	}
	func() {
		defer func() { _ = recover() }()
		Scrub(func() { fill(); panic("gpclear") })
	}()
	dump()
	if s := survivors(); len(s) != 0 {
		t.Errorf("Scrub (panicking fn): %v still hold their planted words after the unwind", s)
	}
}
