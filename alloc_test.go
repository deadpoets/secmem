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
