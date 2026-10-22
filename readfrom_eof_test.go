package secmem

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// TestReadFrom_EmptyReaderIsNotAnError pins the io.ReaderFrom contract: EOF
// ends the read and is not reported. A source with one byte was a successful
// partial fill while a source with none returned io.EOF.
func TestReadFrom_EmptyReaderIsNotAnError(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	buf, err := NewEmptyBuffer(16)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if n, err := buf.ReadFrom(bytes.NewReader(nil)); n != 0 || err != nil {
		t.Errorf("ReadFrom(empty) = (%d, %v), want (0, nil)", n, err)
	}
	// The contract is io.ReaderFrom's, which the type claims to implement.
	var _ io.ReaderFrom = buf

	// The constructor keeps refusing an empty source, deliberately: with
	// io.EOF and no buffer.
	fromEmpty, err := NewBufferFromReader(bytes.NewReader(nil), 16)
	if !errors.Is(err, io.EOF) || fromEmpty != nil {
		t.Errorf("NewBufferFromReader(empty) = (%v, %v), want (nil, io.EOF)", fromEmpty != nil, err)
	}
	// A short source gives a short buffer: Len is what was read, and the
	// slice a borrow hands out is exactly that, not zero-padded to size.
	short, err := NewBufferFromReader(bytes.NewReader([]byte{1}), 16)
	if err != nil {
		t.Fatalf("NewBufferFromReader(one byte): %v", err)
	}
	defer func() { _ = short.Destroy() }()
	if short.Len() != 1 {
		t.Errorf("NewBufferFromReader(one byte).Len() = %d, want 1", short.Len())
	}
	if err := short.WithBytes(func(b []byte) {
		if len(b) != 1 || cap(b) != 1 || b[0] != 1 {
			t.Errorf("borrowed slice = %v (cap %d), want [1] (cap 1)", b, cap(b))
		}
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
}
