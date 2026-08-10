//go:build !race

// Allocation counts are only meaningful without the race detector's
// instrumentation, so these gates are excluded under -race. The non-race CI
// job (test-386-linux) executes them; escape behavior is arch-independent.

package secmem

import "testing"

// TestNoHeapEscape_HotPaths turns the "a secret accessed through the borrow,
// copy, and compare paths never escapes to the Go heap" claim from a
// benchmark a human has to read into an invariant CI enforces. If a future
// change makes one of these paths allocate — the usual way a secret leaks
// onto the GC heap — testing.AllocsPerRun catches it and this test fails.
//
// Closures are created ONCE outside the measured function so we measure the
// method's own allocations, not the (one-time) closure value.
func TestNoHeapEscape_HotPaths(t *testing.T) {
	buf, err := NewBuffer([]byte("hunter2-hunter2-hunter2-hunter2-"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer buf.Destroy()

	n := buf.Len()
	dst := make([]byte, n)
	src := make([]byte, n)
	cmp := make([]byte, n)

	borrow := func([]byte) {}
	borrowErr := func([]byte) error { return nil }

	cases := []struct {
		name string
		want float64
		fn   func()
	}{
		{"WithBytes", 0, func() { _ = buf.WithBytes(borrow) }},
		{"WithBytesErr", 0, func() { _ = buf.WithBytesErr(borrowErr) }},
		{"ByteAt", 0, func() { _, _ = buf.ByteAt(0) }},
		{"SetByteAt", 0, func() { _ = buf.SetByteAt(0, 1) }},
		{"CopyOut", 0, func() { _, _ = buf.CopyOut(dst, 0) }},
		{"CopyIn", 0, func() { _, _ = buf.CopyIn(src, 0) }},
		{"ConstantTimeEqual", 0, func() { _, _ = buf.ConstantTimeEqual(cmp) }},
		{"Len", 0, func() { _ = buf.Len() }},
		{"IsDestroyed", 0, func() { _ = buf.IsDestroyed() }},
		{"IsSealed", 0, func() { _ = buf.IsSealed() }},
	}
	for _, c := range cases {
		got := testing.AllocsPerRun(200, c.fn)
		if got > c.want {
			t.Errorf("%s: %.1f allocs/op, want <= %.0f — a secret may be escaping to the heap",
				c.name, got, c.want)
		}
	}
}

// TestNoHeapEscape_Scrub gates the Scrub window itself.
//
// This exists because it was missed. Adding the asynchronous-preemption
// suppression put two allocations per call into Scrub and ScrubErr on Linux —
// the restore closure, and the saved signal mask it captured — and NOTHING in
// this module noticed. It was caught downstream, by secmem-crypto's gate on
// OpenInto (which runs inside ScrubErr), on CI, on a platform the author's
// machine cannot execute: the suppression is Linux-only, so Windows and macOS
// compile a no-op stub and stay at zero either way. A regression in this
// module should not need a different module's test, on a different OS, to
// surface it.
//
// Scrub is the wrapper for cipher and KDF hot paths, so per-call allocations
// here are paid on every operation a caller hardens — and allocating inside a
// window whose purpose is secret hygiene is the wrong shape regardless of cost.
//
// The closures are hoisted out of the measured function so this counts Scrub's
// own allocations rather than the one-time closure values.
func TestNoHeapEscape_Scrub(t *testing.T) {
	noop := func() {}
	noopErr := func() error { return nil }

	cases := []struct {
		name string
		fn   func()
	}{
		{"Scrub", func() { Scrub(noop) }},
		{"ScrubErr", func() { _ = ScrubErr(noopErr) }},
		{"Scrub(nil)", func() { Scrub(nil) }},
		{"ScrubErr(nil)", func() { _ = ScrubErr(nil) }},
	}
	for _, c := range cases {
		if got := testing.AllocsPerRun(200, c.fn); got > 0 {
			t.Errorf("%s: %.1f allocs/op, want 0 — the scrub window must not allocate "+
				"(it wraps every hardened crypto operation)", c.name, got)
		}
	}
}
