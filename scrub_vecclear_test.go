//go:build amd64 || arm64

package secmem

import "testing"

// allZero reports whether every byte of b is zero.
func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

// countEqual returns how many positions of a and b hold the same byte.
func countEqual(a, b []byte) int {
	n := 0
	for i := range a {
		if a[i] == b[i] {
			n++
		}
	}
	return n
}

// runVecClearProof is the empirical check the project requires before any
// register scrub is trusted: it shows that the clear at the end of a Scrub
// window reaches what fn left in the vector registers, on the thread that ran
// fn. The per-architecture tests (scrub_vecclear_amd64_test.go,
// scrub_vecclear_arm64_test.go) supply the probe: fill loads the registers
// from planted, dump stores them into got, and the first fillable bytes of
// planted are the ones a fill can be expected to plant (amd64 skips X15, the
// ABI's fixed zero). Three parts, in order, each meaningless without the one
// before it:
//
//  1. Probe sanity. A non-zero pattern planted in the registers must read back
//     exactly, or the probe observes nothing and the rest is vacuous.
//  2. Controls. Scrub's window WITHOUT the clear (legacyWindowNoClear: same
//     pin, same reserve-then-wipe, same defers, minus one line) must leave the
//     pattern visible after a normal return. This is what proves the ABI does
//     not reload the vector registers around the calls, i.e. that a clear
//     placed there has something to clear. A zero here is a failure, not a
//     skip: if a toolchain ever makes the residue unobservable this way, the
//     test has to be rethought, not silently passed. The same window with a
//     panicking fn measures what the unwind itself writes to the registers —
//     the runtime's stack walk (runtime.(*unwinder).initAt) copies its own
//     bookkeeping through a vector register between one frame's defers and the
//     next, so a dump after a recovered panic can never be all zero on any
//     toolchain — and proves that the unwind does not itself remove the
//     pattern. Legacy path only: runtime/secret erases registers itself and
//     the pieces the control replicates are build-tagged out there.
//  3. Subjects. After Scrub and ScrubErr the registers must read back all
//     zero. After a Scrub whose fn panics, no planted byte may survive and
//     every byte outside the unwind's measured footprint must be zero.
//
// Nothing between a fill and its dump is allowed to touch the vector
// registers, so the probe calls are back to back with only the code under test
// in between, and the pattern is prepared before the sequence starts.
func runVecClearProof(t *testing.T, planted, got []byte, fill, dump func(), fillable int) {
	t.Helper()
	if len(planted) != len(got) || fillable > len(got) {
		t.Fatalf("probe geometry: planted %d, got %d, fillable %d", len(planted), len(got), fillable)
	}
	for i := range planted {
		planted[i] = byte(i%0xEE) + 0x11 // 0x11..0xFE: never zero, so a zero in a dump is a clear's doing
	}
	// expected is what a dump right after a fill must show.
	expected := func(i int) byte {
		if i < fillable {
			return planted[i]
		}
		return 0
	}

	// 1. Probe sanity.
	fill()
	dump()
	for i := range got {
		if got[i] != expected(i) {
			t.Fatalf("probe sanity: byte %d read back %#x, want %#x — the probe cannot plant and observe a pattern, so nothing below can be trusted", i, got[i], expected(i))
		}
	}

	// 2. Controls.
	var unwindFootprint []bool // positions the unwind writes on its own; nil when unmeasured
	if vecClearControlAvailable {
		legacyWindowNoClear(fill)
		dump()
		if allZero(got) {
			t.Fatal("control failed: no vector-register residue observed after the window's exit sequence without the clear, so the clear cannot be shown to reach anything")
		}
		t.Logf("control (normal return): %d of %d planted bytes survive the window without the clear", countEqual(got[:fillable], planted[:fillable]), fillable)

		func() {
			defer func() { _ = recover() }()
			legacyWindowNoClear(func() { fill(); panic("vecclear-control") })
		}()
		dump()
		survived := countEqual(got[:fillable], planted[:fillable])
		if survived == 0 {
			t.Fatal("control failed (panic path): no planted byte survives the unwind without the clear, so a clear cannot be shown to be what removes them")
		}
		unwindFootprint = make([]bool, len(got))
		n := 0
		for i := range got {
			if got[i] != expected(i) {
				unwindFootprint[i] = true
				n++
			}
		}
		t.Logf("control (panic unwind): %d of %d planted bytes survive the window without the clear; the unwind itself writes %d bytes", survived, fillable, n)
	} else {
		t.Log("runtime/secret active: controls omitted, the legacy exit sequence they replicate does not exist on this build")
	}

	// 3. Subjects.
	Scrub(fill)
	dump()
	if !allZero(got) {
		t.Errorf("Scrub: vector registers hold residue after the window: %x", got)
	}

	if err := ScrubErr(func() error { fill(); return nil }); err != nil {
		t.Fatal(err)
	}
	dump()
	if !allZero(got) {
		t.Errorf("ScrubErr: vector registers hold residue after the window: %x", got)
	}

	func() {
		defer func() { _ = recover() }()
		Scrub(func() { fill(); panic("vecclear") })
	}()
	dump()
	if n := countEqual(got[:fillable], planted[:fillable]); n != 0 {
		t.Errorf("Scrub (panicking fn): %d planted bytes survive the unwind: %x", n, got)
	}
	for i := range got {
		if got[i] != 0 && (unwindFootprint == nil || !unwindFootprint[i]) {
			t.Errorf("Scrub (panicking fn): byte %d = %#x after the unwind, outside the footprint the unwind itself writes (%x)", i, got[i], got)
			break
		}
	}
	if !allZero(got) {
		t.Logf("after the panicking window the registers hold only what the unwind wrote after the clear: %x", got)
	}
}
