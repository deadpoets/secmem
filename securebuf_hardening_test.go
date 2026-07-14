package secmem

import (
	"bytes"
	"errors"
	"testing"
)

// TestSignalWipe_NoUseAfterMunmap covers the emergency-wipe path (H1). The wipe
// must clear a live buffer's secret but leave the region MAPPED, so a goroutine
// still touching the buffer during the shutdown window reads zeros rather than
// faulting on freed memory. This drives the per-region in-place wipe for one
// buffer in isolation; before the fix the region was unmapped and the access
// below SIGSEGV'd the process.
func TestSignalWipe_NoUseAfterMunmap(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	secret := bytes.Repeat([]byte{0x5A}, 48)
	buf, err := NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	// Reproduce the signal path for just this buffer: take it out of the
	// registry (as wipeAll does) and wipe WITHOUT unmapping.
	region, ok := emergencyJanitor.take(buf.janitorKey)
	if !ok {
		t.Fatal("buffer not registered with the emergency janitor")
	}
	if err := wipeAndFree(region, false, false); err != nil {
		t.Fatalf("signal-path wipe: %v", err)
	}

	// The region is wiped but still mapped: access must NOT fault (a fault would
	// crash this test), and the secret must be gone.
	sawNonZero := false
	if err := buf.WithBytes(func(b []byte) {
		for _, x := range b {
			if x != 0 {
				sawNonZero = true
			}
		}
	}); err != nil {
		t.Fatalf("access after signal wipe returned %v (must read the wiped-but-mapped region)", err)
	}
	if sawNonZero {
		t.Fatal("secret was not fully wiped by the signal path")
	}
}

// TestTruncate_OnSealedBufferReturnsErrSealed covers H2: Truncate must reject a
// sealed (PROT_NONE) buffer with ErrSealed instead of wiping the freed tail
// into protected memory, which faulted. Then the buffer stays usable after
// Unseal.
func TestTruncate_OnSealedBufferReturnsErrSealed(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	buf, err := NewBuffer([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := buf.Truncate(16); !errors.Is(err, ErrSealed) {
		t.Fatalf("Truncate on sealed buffer = %v, want ErrSealed", err)
	}
	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if err := buf.Truncate(16); err != nil {
		t.Fatalf("Truncate after Unseal: %v", err)
	}
	if buf.Len() != 16 {
		t.Fatalf("Len after Truncate = %d, want 16", buf.Len())
	}
}

type panicWriter struct{}

func (panicWriter) Write([]byte) (int, error) { panic("hostile writer") }

// TestWriteTo_PanickingWriterUnwindsCleanly covers L3: a panicking io.Writer
// must not skip the temp-copy wipe. We can't observe the internal temp, but the
// deferred wipe now runs during the unwind; the test asserts the panic
// propagates (the fixed path is exercised) rather than being swallowed.
func TestWriteTo_PanickingWriterUnwindsCleanly(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	buf, err := NewBuffer([]byte("secret-material"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()
	defer func() {
		if recover() == nil {
			t.Fatal("expected the writer panic to propagate through WriteTo")
		}
	}()
	_, _ = buf.WriteTo(panicWriter{})
	t.Fatal("WriteTo should have panicked")
}
