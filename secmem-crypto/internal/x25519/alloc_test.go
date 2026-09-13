//go:build !race

package x25519

import "testing"

// The ladder must allocate nothing: an allocation here would be the heap
// copy of the scalar or of the output that this package exists to avoid.
func TestNoHeapEscape_ScalarMult(t *testing.T) {
	var scalar, point, dst [32]byte
	scalar[0], point[0] = 0x42, 9
	if n := testing.AllocsPerRun(100, func() { ScalarMult(&dst, &scalar, &point) }); n != 0 {
		t.Fatalf("ScalarMult: %.1f allocs/op, want 0", n)
	}
}
