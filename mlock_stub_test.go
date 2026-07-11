//go:build !linux && !darwin && !windows

// Tests for the LOUD stub: constructors on platforms with no lockable
// off-heap memory fail closed with ErrNoSecureMemory, and the explicit
// WithInsecureFallback opt-in yields a working heap-backed buffer that
// reports itself as Insecure.

package secmem

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestStub_FailsClosed verifies every constructor returns ErrNoSecureMemory
// without the explicit opt-in — the silent heap fallback is gone.
func TestStub_FailsClosed(t *testing.T) {
	t.Parallel()

	if _, err := NewBuffer([]byte("x")); !errors.Is(err, ErrNoSecureMemory) {
		t.Errorf("NewBuffer = %v, want ErrNoSecureMemory", err)
	}
	if _, err := NewEmptyBuffer(16); !errors.Is(err, ErrNoSecureMemory) {
		t.Errorf("NewEmptyBuffer = %v, want ErrNoSecureMemory", err)
	}
	if _, err := NewSyscallSafeBuffer([]byte("x")); !errors.Is(err, ErrNoSecureMemory) {
		t.Errorf("NewSyscallSafeBuffer = %v, want ErrNoSecureMemory", err)
	}
	if _, _, err := NewBufferFromReader(bytes.NewReader([]byte("x")), 1); !errors.Is(err, ErrNoSecureMemory) {
		t.Errorf("NewBufferFromReader = %v, want ErrNoSecureMemory", err)
	}
	if _, err := NewArena(16, 2); !errors.Is(err, ErrNoSecureMemory) {
		t.Errorf("NewArena = %v, want ErrNoSecureMemory", err)
	}
}

// TestStub_OptInWorks verifies the explicit fallback: the buffer functions,
// and its Capabilities tell the truth about the heap backing.
func TestStub_OptInWorks(t *testing.T) {
	t.Parallel()

	want := []byte("insecure-but-explicit")
	buf, err := NewBuffer(append([]byte(nil), want...), WithInsecureFallback())
	if err != nil {
		t.Fatalf("NewBuffer with WithInsecureFallback: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	c := buf.Capabilities()
	if !c.Insecure {
		t.Error("heap-backed buffer did not report Insecure = true")
	}
	if c.OffHeap || c.Mlocked {
		t.Errorf("heap-backed buffer claimed protections it does not have: %+v", c)
	}
	w := c.Warnings()
	if len(w) == 0 || !strings.Contains(w[0], "INSECURE") {
		t.Errorf("Warnings() must lead with the insecure heap exposure, got %q", w)
	}

	if err := buf.WithBytes(func(b []byte) {
		if !bytes.Equal(b, want) {
			t.Errorf("contents = %q, want %q", b, want)
		}
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
}
