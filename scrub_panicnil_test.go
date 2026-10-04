package secmem

import "testing"

// TestScrub_PanicNilIsNotSwallowed runs with GODEBUG=panicnil=1, where
// panic(nil) recovers as nil instead of *runtime.PanicNilError. The legacy
// window told "fn panicked" from "fn returned" by that value alone, so such a
// panic was absorbed: Scrub returned normally and ScrubErr returned a nil
// error for a function that never finished. A window must re-raise whatever
// fn raised.
func TestScrub_PanicNilIsNotSwallowed(t *testing.T) {
	t.Setenv("GODEBUG", "panicnil=1")

	// Under panicnil=1 a recovered panic(nil) is indistinguishable from no
	// panic by its value, so the test watches control flow instead: the line
	// after the window must not be reached.
	panicsThrough := func(window func()) (reachedAfter bool) {
		defer func() { _ = recover() }()
		window()
		return true
	}

	if panicsThrough(func() { Scrub(func() { panic(nil) }) }) { //nolint:govet // panic(nil) is the subject
		t.Error("Scrub returned normally from a fn that called panic(nil)")
	}
	var err error
	if panicsThrough(func() { err = ScrubErr(func() error { panic(nil) }) }) { //nolint:govet // panic(nil) is the subject
		t.Errorf("ScrubErr returned %v from a fn that called panic(nil); the caller would take a partial result for a success", err)
	}

	// The ordinary paths are unchanged.
	if !panicsThrough(func() { Scrub(func() {}) }) {
		t.Error("Scrub panicked for a fn that returned")
	}
	if panicsThrough(func() { Scrub(func() { panic("boom") }) }) {
		t.Error("Scrub swallowed an ordinary panic")
	}
}
