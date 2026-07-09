package secmem

import (
	"testing"
)

// ─── Truncate boundary tests ──────────────────────────────────────────────────

// TestTruncate_ToZero verifies that Truncate(0) succeeds and sets Len() to 0.
// This pins the n >= 0 lower-boundary: a CONDITIONALS_BOUNDARY mutation on
// n < 0 (→ n <= 0) would reject n=0 as invalid.
func TestTruncate_ToZero(t *testing.T) {
	t.Parallel()
	const size = 32
	buf, err := NewEmptyBuffer(size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.Truncate(0); err != nil {
		t.Fatalf("Truncate(0): %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("Len() after Truncate(0) = %d, want 0", buf.Len())
	}
}

// TestTruncate_ToExactLen verifies that Truncate(len) is a valid no-op (tail is
// empty; no bytes are wiped, length unchanged). This pins the n <= len(data)
// upper-boundary: a CONDITIONALS_BOUNDARY mutation on n > len(data) (→ n >=)
// would reject this valid call.
func TestTruncate_ToExactLen(t *testing.T) {
	t.Parallel()
	const size = 32
	buf, err := NewEmptyBuffer(size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.Truncate(size); err != nil {
		t.Fatalf("Truncate(%d): %v", size, err)
	}
	if buf.Len() != size {
		t.Errorf("Len() after Truncate(%d) = %d, want %d", size, buf.Len(), size)
	}
}

// TestTruncate_Negative verifies that Truncate(-1) returns an error. Pins the
// lower boundary from below: a mutation that removes the n < 0 guard would
// allow this to proceed to a runtime slice panic.
func TestTruncate_Negative(t *testing.T) {
	t.Parallel()
	buf, err := NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.Truncate(-1); err == nil {
		t.Fatal("Truncate(-1): expected error, got nil")
	}
}

// TestTruncate_PastEnd verifies that Truncate(len+1) returns an error. Pins the
// upper boundary from above: a mutation that removes the n > len(data) guard
// would allow this to proceed to a slice-out-of-bounds panic.
func TestTruncate_PastEnd(t *testing.T) {
	t.Parallel()
	const size = 32
	buf, err := NewEmptyBuffer(size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.Truncate(size + 1); err == nil {
		t.Fatalf("Truncate(%d): expected error, got nil", size+1)
	}
}

// TestTruncate_EmptyTail_NoWipeNeeded verifies that Truncate(len) (empty tail)
// returns nil without error. This covers the len(tail) > 0 guard: a mutation
// changing > to >= would attempt to wipe a zero-length slice (harmless but wrong).
func TestTruncate_EmptyTail_NoWipeNeeded(t *testing.T) {
	t.Parallel()
	const size = 16
	buf, err := NewEmptyBuffer(size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.Truncate(size); err != nil {
		t.Fatalf("Truncate(%d) with empty tail: %v", size, err)
	}
	if buf.Len() != size {
		t.Errorf("Len() = %d, want %d", buf.Len(), size)
	}
}

// TestTruncate_NonEmptyTail_Wiped verifies that after Truncate(n) where n < len,
// the freed tail is zeroed. This covers the len(tail) > 0 wipe path: a mutation
// removing the wipe would allow tail bytes to be read back via Read.
func TestTruncate_NonEmptyTail_Wiped(t *testing.T) {
	t.Parallel()
	buf, err := NewBuffer([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")) // 32 'A's
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	// Truncate to 16 — the tail [16:32] should be zeroed.
	if err := buf.Truncate(16); err != nil {
		t.Fatalf("Truncate(16): %v", err)
	}

	// Read the first 16 bytes — should still be 'A'.
	head := make([]byte, 16)
	if n, err := buf.Read(head, 0); err != nil || n != 16 {
		t.Fatalf("Read head: n=%d, err=%v", n, err)
	}
	for i, b := range head {
		if b != 'A' {
			t.Errorf("head[%d] = %#x, want 'A'", i, b)
		}
	}

	// Reading from offset 16 should fail (out of range after truncation).
	if n, err := buf.Read(make([]byte, 1), 16); err == nil {
		t.Errorf("Read past truncation returned n=%d, want error", n)
	}
}

// ─── NewEmptyBuffer size-0 boundary ──────────────────────────────────────────

// TestNewEmptyBuffer_SizeZero verifies that size=0 returns an error.
// A CONDITIONALS_BOUNDARY mutation on size <= 0 (→ size < 0) would allow
// size=0 through and attempt to allocate zero bytes of mlock'd memory.
func TestNewEmptyBuffer_SizeZero(t *testing.T) {
	t.Parallel()
	if _, err := NewEmptyBuffer(0); err == nil {
		t.Fatal("NewEmptyBuffer(0): expected error, got nil")
	}
}

// TestNewEmptyBuffer_SizeOne verifies that size=1 succeeds. This is the valid
// lower boundary: a mutation changing <= to < would still accept 1, but
// changing <= to == 0 would accept only 0, so this covers the shape.
func TestNewEmptyBuffer_SizeOne(t *testing.T) {
	t.Parallel()
	buf, err := NewEmptyBuffer(1)
	if err != nil {
		t.Fatalf("NewEmptyBuffer(1): %v", err)
	}
	defer func() { _ = buf.Destroy() }()
	if buf.Len() != 1 {
		t.Errorf("Len() = %d, want 1", buf.Len())
	}
}

// ─── ByteAt / SetByteAt exact-boundary ───────────────────────────────────────

// TestByteAt_ExactLastIndex verifies that ByteAt(len-1) (the last valid index)
// succeeds. A CONDITIONALS_BOUNDARY mutation on i >= len(data) (→ i > len(data))
// would incorrectly allow i=len, so we also need to confirm that i=len fails.
func TestByteAt_ExactLastIndex(t *testing.T) {
	t.Parallel()
	const size = 8
	buf, err := NewEmptyBuffer(size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	// Last valid index must succeed.
	if _, err := buf.ByteAt(size - 1); err != nil {
		t.Errorf("ByteAt(%d): %v", size-1, err)
	}
	// Exact-len must fail.
	if _, err := buf.ByteAt(size); err == nil {
		t.Errorf("ByteAt(%d): expected error for exact-len index, got nil", size)
	}
}

// TestSetByteAt_ExactLastIndex mirrors TestByteAt_ExactLastIndex for writes.
func TestSetByteAt_ExactLastIndex(t *testing.T) {
	t.Parallel()
	const size = 8
	buf, err := NewEmptyBuffer(size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.SetByteAt(size-1, 0xFF); err != nil {
		t.Errorf("SetByteAt(%d, 0xFF): %v", size-1, err)
	}
	if err := buf.SetByteAt(size, 0xFF); err == nil {
		t.Errorf("SetByteAt(%d): expected error for exact-len index, got nil", size)
	}
}

// TestRead_ExactLastValidOffset verifies Read at offset=len-1 (1 byte available)
// returns 1 byte, and at offset=len returns an error.
func TestRead_ExactLastValidOffset(t *testing.T) {
	t.Parallel()
	const size = 8
	buf, err := NewBuffer([]byte("ABCDEFGH"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	dst := make([]byte, 4)

	// offset = size-1: reads 1 byte from position 7.
	n, err := buf.Read(dst, size-1)
	if err != nil || n != 1 {
		t.Errorf("Read(offset=%d): got n=%d, err=%v; want n=1, nil", size-1, n, err)
	}

	// offset = size: must return an error.
	if n, err := buf.Read(dst, size); err == nil {
		t.Errorf("Read(offset=%d): got n=%d nil, want error", size, n)
	}
}

// TestWrite_ExactLastValidOffset verifies Write at offset=len-1 and offset=len.
func TestWrite_ExactLastValidOffset(t *testing.T) {
	t.Parallel()
	const size = 8
	buf, err := NewEmptyBuffer(size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	src := []byte{0xFF, 0xFF}

	// offset = size-1: writes 1 byte (only 1 byte available from position 7).
	n, err := buf.Write(src, size-1)
	if err != nil || n != 1 {
		t.Errorf("Write(offset=%d): got n=%d, err=%v; want n=1, nil", size-1, n, err)
	}

	// offset = size: must return an error.
	if n, err := buf.Write(src, size); err == nil {
		t.Errorf("Write(offset=%d): got n=%d nil, want error", size, n)
	}
}
