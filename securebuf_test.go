package secmem

import (
	"errors"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// TestSecureBuffer_New verifies basic construction, size reporting, and that
// the buffer is writable. Mirrors NewBuffer in the v2.2 reference.
func TestSecureBuffer_New(t *testing.T) {
	t.Parallel()

	const size = 64
	buf, err := NewBuffer(make([]byte, size))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if buf.Len() != size {
		t.Errorf("Len() = %d, want %d", buf.Len(), size)
	}
	if buf.MappedLen() < size {
		t.Errorf("MappedLen() = %d, want >= %d", buf.MappedLen(), size)
	}
	if buf.MappedLen()%4096 != 0 {
		t.Errorf("MappedLen() = %d, not page-aligned", buf.MappedLen())
	}
}

// TestSecureBuffer_NewEmpty verifies the zero-filled empty constructor.
func TestSecureBuffer_NewEmpty(t *testing.T) {
	t.Parallel()

	const size = 128
	buf, err := NewEmptyBuffer(size)
	if err != nil {
		t.Fatalf("NewEmpty: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if buf.Len() != size {
		t.Errorf("Len() = %d, want %d", buf.Len(), size)
	}
}

// TestSecureBuffer_NewSyscallSafe verifies the MAP_ANON-only path.
func TestSecureBuffer_NewSyscallSafe(t *testing.T) {
	t.Parallel()

	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	buf, err := NewSyscallSafeBuffer(raw)
	if err != nil {
		t.Fatalf("NewSyscallSafe: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if buf.Len() != len(raw) {
		t.Errorf("Len() = %d, want %d", buf.Len(), len(raw))
	}
}

// TestSecureBuffer_Destroy_Idempotent verifies that calling Destroy twice is safe.
func TestSecureBuffer_Destroy_Idempotent(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(64)
	if err != nil {
		t.Fatalf("NewEmpty: %v", err)
	}

	if err := buf.Destroy(); err != nil {
		t.Fatalf("first Destroy: %v", err)
	}
	// Second call must be safe and return nil.
	if err := buf.Destroy(); err != nil {
		t.Errorf("second Destroy returned error: %v, want nil", err)
	}
}

// TestSecureBuffer_IsDestroyed verifies the IsDestroyed predicate.
func TestSecureBuffer_IsDestroyed(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(64)
	if err != nil {
		t.Fatalf("NewEmpty: %v", err)
	}

	if buf.IsDestroyed() {
		t.Error("IsDestroyed() = true before Destroy, want false")
	}

	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	if !buf.IsDestroyed() {
		t.Error("IsDestroyed() = false after Destroy, want true")
	}
}

// TestSecureBuffer_ErrDestroyed verifies that methods return ErrDestroyed
// after the buffer is destroyed.
func TestSecureBuffer_ErrDestroyed(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(64)
	if err != nil {
		t.Fatalf("NewEmpty: %v", err)
	}

	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	// ReadOnly / ReadWrite must return ErrDestroyed after Destroy.
	if gotErr := buf.ReadOnly(); !errors.Is(gotErr, ErrDestroyed) {
		t.Errorf("ReadOnly() after Destroy = %v, want ErrDestroyed", gotErr)
	}
	if gotErr := buf.ReadWrite(); !errors.Is(gotErr, ErrDestroyed) {
		t.Errorf("ReadWrite() after Destroy = %v, want ErrDestroyed", gotErr)
	}
}

// TestSecureBuffer_ReadOnlyReadWrite verifies mprotect toggling.
func TestSecureBuffer_ReadOnlyReadWrite(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(64)
	if err != nil {
		t.Fatalf("NewEmpty: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.ReadOnly(); err != nil {
		t.Fatalf("ReadOnly: %v", err)
	}
	if err := buf.ReadWrite(); err != nil {
		t.Fatalf("ReadWrite: %v", err)
	}
}

// TestSecureBuffer_Truncate verifies that Truncate re-slices data and reports
// the new length, while MappedLen remains unchanged (raw is immutable).
func TestSecureBuffer_Truncate(t *testing.T) {
	t.Parallel()

	const size = 64
	buf, err := NewEmptyBuffer(size)
	if err != nil {
		t.Fatalf("NewEmpty: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	mapped := buf.MappedLen() // should be page-rounded, immutable

	if err := buf.Truncate(32); err != nil {
		t.Fatalf("Truncate(32): %v", err)
	}
	if buf.Len() != 32 {
		t.Errorf("Len() after Truncate(32) = %d, want 32", buf.Len())
	}
	if buf.MappedLen() != mapped {
		t.Errorf("MappedLen() changed after Truncate: got %d, want %d", buf.MappedLen(), mapped)
	}
}

// TestSecureBuffer_Truncate_InvalidAfterDestroy verifies Truncate returns
// ErrDestroyed when the buffer has been destroyed.
func TestSecureBuffer_Truncate_InvalidAfterDestroy(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(64)
	if err != nil {
		t.Fatalf("NewEmpty: %v", err)
	}
	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	if gotErr := buf.Truncate(32); !errors.Is(gotErr, ErrDestroyed) {
		t.Errorf("Truncate after Destroy = %v, want ErrDestroyed", gotErr)
	}
}

// TestSecureBuffer_NilSafe verifies that nil receiver calls don't panic.
func TestSecureBuffer_NilSafe(t *testing.T) {
	t.Parallel()

	var buf *SecureBuffer

	if buf.Len() != 0 {
		t.Errorf("nil.Len() = %d, want 0", buf.Len())
	}
	if buf.MappedLen() != 0 {
		t.Errorf("nil.MappedLen() = %d, want 0", buf.MappedLen())
	}
	if err := buf.Destroy(); err != nil {
		t.Errorf("nil.Destroy() = %v, want nil", err)
	}
	if !buf.IsDestroyed() {
		t.Error("nil.IsDestroyed() = false, want true")
	}
}

// TestErrDestroyed_Sentinel verifies ErrDestroyed is a distinct error and
// satisfies errors.Is expectations.
func TestErrDestroyed_Sentinel(t *testing.T) {
	t.Parallel()

	if ErrDestroyed == nil {
		t.Fatal("ErrDestroyed is nil")
	}
	wrapped := errors.New("outer: " + ErrDestroyed.Error())
	if errors.Is(wrapped, ErrDestroyed) {
		t.Error("non-wrapping error should not match ErrDestroyed via errors.Is")
	}
}

// TestNew_PageAlignment verifies MappedLen is always a multiple of the OS page size.
func TestNew_PageAlignment(t *testing.T) {
	t.Parallel()

	for _, size := range []int{1, 7, 32, 4095, 4096, 4097, 65536} {
		t.Run("size_"+itoa(size), func(t *testing.T) {
			t.Parallel()
			buf, err := NewEmptyBuffer(size)
			if err != nil {
				t.Fatalf("NewEmpty(%d): %v", size, err)
			}
			defer func() { _ = buf.Destroy() }()

			mapped := buf.MappedLen()
			if mapped%4096 != 0 {
				t.Errorf("MappedLen()=%d is not page-aligned for size=%d", mapped, size)
			}
			if mapped < size {
				t.Errorf("MappedLen()=%d < requested size=%d", mapped, size)
			}
		})
	}
}

// TestSecureWipe_FullRegionIncludingTail verifies that when size < page the raw
// region (including the tail bytes past data[:Len()]) is valid to Destroy.
func TestSecureWipe_FullRegionIncludingTail(t *testing.T) {
	t.Parallel()

	// Use a size that is definitely smaller than a page so there will be a tail.
	const size = 32
	buf, err := NewEmptyBuffer(size)
	if err != nil {
		t.Fatalf("NewEmpty: %v", err)
	}

	mapped := buf.MappedLen()
	if mapped <= size {
		t.Skipf("MappedLen()=%d not larger than size=%d; tail test skipped", mapped, size)
	}

	// Destroy must wipe the full raw region (size + tail) without faulting.
	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if !buf.IsDestroyed() {
		t.Error("IsDestroyed() = false after Destroy")
	}
}

// TestTruncate_DoesNotModifyRaw verifies that Truncate changes Len() but leaves
// MappedLen() (reflecting raw) completely unchanged.
func TestTruncate_DoesNotModifyRaw(t *testing.T) {
	t.Parallel()

	const size = 128
	buf, err := NewEmptyBuffer(size)
	if err != nil {
		t.Fatalf("NewEmpty: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	before := buf.MappedLen()

	if err := buf.Truncate(64); err != nil {
		t.Fatalf("Truncate(64): %v", err)
	}
	if buf.Len() != 64 {
		t.Errorf("Len() after Truncate = %d, want 64", buf.Len())
	}
	if buf.MappedLen() != before {
		t.Errorf("MappedLen() changed after Truncate: %d → %d", before, buf.MappedLen())
	}

	// Second truncate to a smaller value.
	if err := buf.Truncate(16); err != nil {
		t.Fatalf("Truncate(16): %v", err)
	}
	if buf.Len() != 16 {
		t.Errorf("Len() after second Truncate = %d, want 16", buf.Len())
	}
	if buf.MappedLen() != before {
		t.Errorf("MappedLen() changed after second Truncate: %d → %d", before, buf.MappedLen())
	}
}

// TestHasCLFLUSHOPT verifies the CPU feature flag helper returns without crashing.
// The actual return value is hardware-dependent; we just verify the function is safe.
func TestHasCLFLUSHOPT(t *testing.T) {
	t.Parallel()
	_ = HasCLFLUSHOPT() // must not panic
}

// TestDestroy_StopsCleanup verifies that an explicit Destroy prevents the
// AddCleanup safety-net from firing on GC. The absence of a crash after
// forcing GC on a destroyed buffer is the assertion — if Stop() did not work,
// the cleanup would call secureWipeSlice/freeSecretMem on an already-freed
// region, causing a crash or data race caught by the race detector.
func TestDestroy_StopsCleanup(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(64)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}

	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	buf = nil //nolint:wastedassign // intentionally nil to allow GC

	// Force GC three times. If cleanup.Stop() did not work, the raw‐memory
	// callback would run on the already-freed mmap region — crash or race.
	for range 3 {
		runtime.GC()
	}
}

// TestAddCleanup_NoDoubleFreeOnGC verifies that a buffer finalized by the GC
// (without explicit Destroy) does not panic or cause a double-free. This acts
// as a safety-net regression test for the AddCleanup callback.
func TestAddCleanup_NoDoubleFreeOnGC(t *testing.T) {
	before := janitorRegionCount()

	buf, err := NewEmptyBuffer(64)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	_ = buf.Len() // use the buffer to ensure it is allocated

	buf = nil //nolint:wastedassign // intentionally nil to allow GC

	// Force GC to trigger the AddCleanup callback.
	// If the callback wipes and frees memory incorrectly, the race detector
	// or OS will catch it.
	for range 3 {
		runtime.GC()
	}

	// Wait for cleanup goroutine scheduling and verify region ownership has
	// returned to baseline. If janitor held a strong *SecureBuffer ref, this
	// would remain +1 indefinitely.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if janitorRegionCount() == before {
			return
		}
		runtime.GC()
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("janitor regions did not return to baseline: got=%d want=%d", janitorRegionCount(), before)
}

// TestJanitorRelease_DestroyRace verifies that concurrent release attempts from
// Destroy and non-Destroy paths do not double-free or panic.
func TestJanitorRelease_DestroyRace(t *testing.T) {
	for range 64 {
		buf, err := NewEmptyBuffer(64)
		if err != nil {
			t.Fatalf("NewEmptyBuffer: %v", err)
		}

		done := make(chan error, 1)
		go func() {
			done <- buf.Destroy()
		}()

		// Competing release path (simulates cleanup/signal race).
		if relErr := emergencyJanitor.release(buf.janitorKey, false); relErr != nil {
			t.Fatalf("janitor release: %v", relErr)
		}
		if dErr := <-done; dErr != nil {
			t.Fatalf("Destroy: %v", dErr)
		}
		if !buf.IsDestroyed() {
			t.Fatal("buffer should be destroyed after concurrent release paths")
		}
	}
}

// BenchmarkSecureWipe_4K measures the wipe throughput for a 4 KiB region.
func BenchmarkSecureWipe_4K(b *testing.B) {
	buf, err := NewEmptyBuffer(4096)
	if err != nil {
		b.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	b.SetBytes(4096)
	b.ResetTimer()
	for range b.N {
		secureWipeSlice(buf.data)
	}
}

// BenchmarkSecureWipe_64K measures the wipe throughput for a 64 KiB region.
func BenchmarkSecureWipe_64K(b *testing.B) {
	buf, err := NewEmptyBuffer(65536)
	if err != nil {
		b.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	b.SetBytes(65536)
	b.ResetTimer()
	for range b.N {
		secureWipeSlice(buf.data)
	}
}

// BenchmarkNewDestroy measures the allocation + wipe + free cycle.
func BenchmarkNewDestroy(b *testing.B) {
	const size = 32
	b.ResetTimer()
	for range b.N {
		buf, err := NewEmptyBuffer(size)
		if err != nil {
			b.Fatalf("NewEmptyBuffer: %v", err)
		}
		if err := buf.Destroy(); err != nil {
			b.Fatalf("Destroy: %v", err)
		}
	}
}

// BenchmarkWithBytesErr measures the overhead of the bufferRWLock rLock/rUnlock
// cycle per WithBytesErr call. The callback is a no-op so the result isolates
// lock acquisition cost (sync.Cond-based vs the old sync.RWMutex baseline).
func BenchmarkWithBytesErr(b *testing.B) {
	buf, err := NewEmptyBuffer(32)
	if err != nil {
		b.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	noop := func(_ []byte) error { return nil }
	b.ResetTimer()
	for range b.N {
		if err := buf.WithBytesErr(noop); err != nil {
			b.Fatalf("WithBytesErr: %v", err)
		}
	}
}

// BenchmarkWithBytesErr_Parallel measures bufferRWLock contention under
// concurrent reader load (no writer). GOMAXPROCS goroutines run WithBytesErr
// simultaneously — this is the hot path for multi-goroutine secret access.
func BenchmarkWithBytesErr_Parallel(b *testing.B) {
	buf, err := NewEmptyBuffer(32)
	if err != nil {
		b.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	noop := func(_ []byte) error { return nil }
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := buf.WithBytesErr(noop); err != nil {
				b.Fatalf("WithBytesErr: %v", err)
			}
		}
	})
}

// itoa is a minimal int-to-string helper for sub-test names.
func itoa(n int) string {
	return strconv.Itoa(n)
}

func janitorRegionCount() int {
	emergencyJanitor.mu.Lock()
	defer emergencyJanitor.mu.Unlock()
	return len(emergencyJanitor.regions)
}
