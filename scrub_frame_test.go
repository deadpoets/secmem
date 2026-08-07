//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && amd64 && !asan

// Excluded under -asan on purpose. This proof observes dead stack through a raw
// uintptr and asserts the wipe assembly zeroed it; AddressSanitizer instruments
// every Go frame with redzones, which relocates the observed local out of the
// fixed-offset band wipeScratchFrameFull's assembly clears. The read address and
// the wiped region then no longer alias, so every marker survives regardless of
// call depth — an artifact of the sanitizer's frame layout, not a wipe failure.
// Confirmed empirically on real amd64 hardware (kernel 7.0.0-1009-azure, Go
// 1.26.5): the whole suite passes under -asan except this one test, it fails
// identically at recursion depth 1 through 4, and disabling asan's fake-stack
// changes nothing — the geometry premise simply does not hold under asan. asan
// is a test-only sanitizer, never a shipped artifact, and the frame scrub is
// still exercised on every non-asan build, plain and under -race.

package secmem

import (
	"testing"
	"unsafe"
)

// Regression guard for the legacy Scrub stack scrub on amd64, where
// wipeScratchFrameFull is real assembly. It pins the reserve-then-wipe fix:
// Scrub must reach the residue a SHALLOW call tree leaves, with NO manual
// stack pre-growth — the exact case a single deferred wipe silently missed,
// because allocating the 32 KiB wipe frame relocated the stack out from under
// it. Without the entry-side reserve this test fails (markers survive).
//
// Inspecting dead stack requires raw pointer reads: Go zero-initializes every
// local, so there is no safe-Go way to observe uninitialized/residual stack.
// The address is held as a uintptr on purpose — an unsafe.Pointer return would
// make escape analysis heap-allocate the marker array, defeating the test.

const scrubMarker = 0xA5
const scrubPad = 2048 // marker bytes planted per recursion level

// plantMarkers writes scrubPad marker bytes into a local array at each of depth
// recursion levels and returns the address of the deepest one. After it
// returns, that memory is dead stack below SP — where a secret-touching call
// tree leaves register spills and locals.
//
//go:noinline
func plantMarkers(depth int) uintptr {
	var pad [scrubPad]byte
	for i := range pad {
		pad[i] = scrubMarker
	}
	if depth > 1 {
		a := plantMarkers(depth - 1)
		if pad[0] != scrubMarker { // keep pad live across the recursive call
			return 0
		}
		return a
	}
	return uintptr(unsafe.Pointer(&pad[0]))
}

// countMarkers reads scrubPad bytes of (dead) stack at addr and counts markers.
// nocheckptr: reading an address held across calls is exactly what checkptr
// forbids; it is intentional here and safe (stack segments are pooled, not
// unmapped).
//
//go:nocheckptr
//go:noinline
func countMarkers(addr uintptr) int {
	c := 0
	for i := 0; i < scrubPad; i++ {
		if *(*byte)(unsafe.Pointer(addr + uintptr(i))) == scrubMarker { //nolint:govet // unsafeptr: intentional dead-stack inspection
			c++
		}
	}
	return c
}

// TestScrub_ScrubsShallowCallTree verifies Scrub scrubs the stack residue
// its own shallow call tree leaves — without any manual pre-growth.
func TestScrub_ScrubsShallowCallTree(t *testing.T) {
	// Control: confirm markers are observable on dead stack when nothing scrubs
	// them. If a future toolchain zeros eagerly, the subject would be vacuous.
	if countMarkers(plantMarkers(4)) == 0 {
		t.Skip("stack markers not observable on this build; scrub assertion would be vacuous")
	}

	// Subject: Scrub must zero the residue of its own call tree.
	var addr uintptr
	Scrub(func() { addr = plantMarkers(4) })

	if got := countMarkers(addr); got != 0 {
		t.Errorf("Scrub left %d/%d secret marker bytes on the stack — "+
			"reserve-then-wipe regressed (a shallow-stack wipe relocated and missed)", got, scrubPad)
	}
}
