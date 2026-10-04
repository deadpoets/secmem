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
	fromEmpty, n, err := NewBufferFromReader(bytes.NewReader(nil), 16)
	if !errors.Is(err, io.EOF) || n != 0 || fromEmpty != nil {
		t.Errorf("NewBufferFromReader(empty) = (%v, %d, %v), want (nil, 0, io.EOF)", fromEmpty != nil, n, err)
	}
	short, n, err := NewBufferFromReader(bytes.NewReader([]byte{1}), 16)
	if err != nil || n != 1 {
		t.Fatalf("NewBufferFromReader(one byte) = (_, %d, %v), want 1, nil", n, err)
	}
	_ = short.Destroy()
}
