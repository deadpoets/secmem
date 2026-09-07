package secmem

import "testing"

// TestLockOrder pins the contract lock-ordering callers rely on: distinct live
// buffers get distinct nonzero ordinals, an ordinal is stable for the buffer's
// lifetime, and a nil buffer reports 0.
func TestLockOrder(t *testing.T) {
	a, err := NewEmptyBuffer(16)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	defer a.Destroy()
	b, err := NewEmptyBuffer(16)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	defer b.Destroy()

	ao, bo := a.LockOrder(), b.LockOrder()
	if ao == 0 || bo == 0 {
		t.Fatalf("registered buffers must have nonzero ordinals: %d %d", ao, bo)
	}
	if ao == bo {
		t.Fatalf("distinct live buffers share ordinal %d", ao)
	}
	if again := a.LockOrder(); again != ao {
		t.Fatalf("ordinal not stable for the buffer's lifetime: %d then %d", ao, again)
	}
	var nilBuf *SecureBuffer
	if got := nilBuf.LockOrder(); got != 0 {
		t.Fatalf("nil buffer ordinal = %d, want 0", got)
	}
}
