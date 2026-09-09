//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && (amd64 || arm64) && !asan

// Excluded under -asan for the same reason as scrub_frame_test.go: the
// sanitizer's redzones move the observed local out of the fixed-offset band
// the wipe assembly clears, so the read and the wipe no longer alias.

package secmem

import (
	"errors"
	"runtime/debug"
	"testing"
	"unsafe"
)

// Regression guard for the legacy Scrub on the PANIC path.
//
// Scrub used to run its stack wipe from a deferred call. A deferred call that
// runs because fn panicked does not run where a deferred call that runs on
// return does: runtime.gopanic calls it from ITS frame, which sits BELOW the
// still-live panicking frames — fn's call tree is not unwound until recover
// returns. The 32 KiB wipe therefore landed under the residue instead of on
// it, and every marker byte in the live frames survived, identical to a
// no-Scrub control. Scrub now recovers fn's panic in a helper, so the frames
// are dead by the time the wipe runs, and re-raises it afterwards — the shape
// runtime/secret.Do uses.
//
// plantThenPanic writes scrubPad marker bytes into a local at each of depth
// recursion levels and panics from the deepest one, with every level still
// live. It reports the deepest local's address through out rather than a
// return value, because it never returns.
//
//go:noinline
func plantThenPanic(depth int, out *uintptr) {
	var p [scrubPad]byte
	for i := range p {
		p[i] = scrubMarker
	}
	if depth > 1 {
		plantThenPanic(depth-1, out)
		if p[0] != scrubMarker { // keep p live across the recursive call
			panic("unreachable")
		}
		return
	}
	*out = uintptr(unsafe.Pointer(&p[0]))
	panic("boom")
}

// growStack forces this goroutine's stack to be at least depth*4 KiB deep
// before the markers are planted. The markers are read back through a raw
// address after the fact, and a morestack in between — triggered by the panic
// machinery's own frames, or by Scrub's wipe frame — would copy the stack and
// leave that address pointing at the abandoned segment. Growing first puts
// every frame this test creates on one segment that is never relocated
// (shrinking is a GC action, and the caller turns the GC off).
//
//go:noinline
func growStack(depth int) byte {
	var pad [4096]byte
	pad[depth&4095] = byte(depth)
	if depth > 0 {
		return growStack(depth-1) + pad[depth&4095]
	}
	return pad[0]
}

// TestScrub_ScrubsLiveFramesOnPanic verifies Scrub scrubs the frames that were
// still live when fn panicked, and re-raises the panic.
func TestScrub_ScrubsLiveFramesOnPanic(t *testing.T) {
	// No stack shrink between planting and reading — see
	// TestScrub_ScrubsShallowCallTree for why a shrink would make the
	// assertion vacuous or fault.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	growStack(64) // ~256 KiB: no relocation from here on

	// Control: a recovered panic with no Scrub leaves the markers in place.
	// If a future toolchain zeroes unwound frames, the subject is vacuous.
	var addr uintptr
	func() {
		defer func() { _ = recover() }()
		plantThenPanic(4, &addr)
	}()
	if countMarkers(addr) == 0 {
		t.Skip("stack markers not observable across a recovered panic on this build; scrub assertion would be vacuous")
	}

	// Subject: the same panic, inside Scrub.
	addr = 0
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		Scrub(func() { plantThenPanic(4, &addr) })
	}()
	if recovered != "boom" {
		t.Fatalf("panic value through Scrub = %v, want \"boom\"", recovered)
	}
	if addr == 0 {
		t.Fatal("marker address not recorded")
	}
	if got := countMarkers(addr); got != 0 {
		t.Errorf("Scrub left %d/%d secret marker bytes in frames that were live at the panic — "+
			"the wipe ran from the unwinding defer, below the residue, instead of after recovery", got, scrubPad)
	}
}

// TestScrubErr_ScrubsLiveFramesOnPanic is the same proof for ScrubErr, whose
// panic path is a separate copy of the sequence.
func TestScrubErr_ScrubsLiveFramesOnPanic(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	growStack(64)

	var addr uintptr
	func() {
		defer func() { _ = recover() }()
		plantThenPanic(4, &addr)
	}()
	if countMarkers(addr) == 0 {
		t.Skip("stack markers not observable across a recovered panic on this build; scrub assertion would be vacuous")
	}

	addr = 0
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_ = ScrubErr(func() error { plantThenPanic(4, &addr); return nil })
	}()
	if recovered != "boom" {
		t.Fatalf("panic value through ScrubErr = %v, want \"boom\"", recovered)
	}
	if got := countMarkers(addr); got != 0 {
		t.Errorf("ScrubErr left %d/%d secret marker bytes in frames that were live at the panic", got, scrubPad)
	}
}

// TestScrubErr_ReturnsFnError pins the non-panic contract alongside: the
// helper that captures a panic must not swallow fn's ordinary error.
func TestScrubErr_ReturnsFnError(t *testing.T) {
	want := errors.New("fn failed")
	if got := ScrubErr(func() error { return want }); !errors.Is(got, want) {
		t.Errorf("ScrubErr returned %v, want %v", got, want)
	}
	if got := ScrubErr(func() error { return nil }); got != nil {
		t.Errorf("ScrubErr returned %v, want nil", got)
	}
}
