package secmem

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// TestWithBytes_Basic verifies the basic access callback pattern.
func TestWithBytes_Basic(t *testing.T) {
	t.Parallel()

	secret := []byte("secmem-access-test")
	want := make([]byte, len(secret))
	copy(want, secret) // save before NewBuffer wipes the input
	buf, err := NewBuffer(secret)
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	called := false
	if err := buf.WithBytes(func(b []byte) {
		called = true
		if !bytes.Equal(b, want) {
			t.Errorf("WithBytes: got %x, want %x", b, want)
		}
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	if !called {
		t.Error("WithBytes: callback was not called")
	}
}

// TestWithBytes_AfterDestroy verifies that WithBytes returns ErrDestroyed.
func TestWithBytes_AfterDestroy(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	if gotErr := buf.WithBytes(func(_ []byte) {}); !errors.Is(gotErr, ErrDestroyed) {
		t.Errorf("WithBytes after Destroy = %v, want ErrDestroyed", gotErr)
	}
}

// TestWithBytesErr_PropagatesError verifies that callback errors are returned.
func TestWithBytesErr_PropagatesError(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(16)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	sentinel := errors.New("callback-error")
	gotErr := buf.WithBytesErr(func(_ []byte) error { return sentinel })
	if !errors.Is(gotErr, sentinel) {
		t.Errorf("WithBytesErr: got %v, want sentinel", gotErr)
	}
}

// TestReadWrite_RoundTrip verifies Read and Write.
func TestReadWrite_RoundTrip(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(8)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	src := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if n, err := buf.Write(src, 0); err != nil || n != len(src) {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}

	dst := make([]byte, 8)
	if n, err := buf.Read(dst, 0); err != nil || n != len(src) {
		t.Fatalf("Read: n=%d err=%v", n, err)
	}
	if !bytes.Equal(dst, src) {
		t.Errorf("Read: got %x, want %x", dst, src)
	}
}

// TestByteAt_Error verifies ByteAt returns error instead of panicking on bad index.
func TestByteAt_Error(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(4)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if _, err := buf.ByteAt(10); err == nil {
		t.Error("ByteAt(out-of-range): expected error, got nil")
	}
}

// TestSetByteAt_Error verifies SetByteAt returns error on bad index.
func TestSetByteAt_Error(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(4)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.SetByteAt(10, 0xFF); err == nil {
		t.Error("SetByteAt(out-of-range): expected error, got nil")
	}
}

// TestConstantEqual verifies constant-time comparison.
func TestConstantEqual(t *testing.T) {
	t.Parallel()

	data := []byte("secret-value-32-bytes-long-test!")
	want := make([]byte, len(data))
	copy(want, data) // save before NewBuffer wipes the input
	buf, err := NewBuffer(data)
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	equal, err := buf.ConstantEqual(want)
	if err != nil {
		t.Fatalf("ConstantEqual: %v", err)
	}
	if !equal {
		t.Error("ConstantEqual: expected true for matching bytes")
	}

	other := []byte("different-value-32-bytes-long---!")
	notEqual, err := buf.ConstantEqual(other)
	if err != nil {
		t.Fatalf("ConstantEqual (different): %v", err)
	}
	if notEqual {
		t.Error("ConstantEqual: expected false for different bytes")
	}
}

// TestWriteTo verifies io.WriterTo implementation.
func TestWriteTo(t *testing.T) {
	t.Parallel()

	want := []byte("write-to-test")
	wantSaved := make([]byte, len(want))
	copy(wantSaved, want) // save before NewBuffer wipes the input
	buf, err := NewBuffer(want)
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	var dst bytes.Buffer
	n, err := buf.WriteTo(&dst)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if int(n) != len(wantSaved) {
		t.Errorf("WriteTo: wrote %d bytes, want %d", n, len(wantSaved))
	}
	if !bytes.Equal(dst.Bytes(), wantSaved) {
		t.Errorf("WriteTo: got %x, want %x", dst.Bytes(), wantSaved)
	}
}

// TestReadFrom verifies io.ReaderFrom implementation.
func TestReadFrom(t *testing.T) {
	t.Parallel()

	want := []byte("read-from-data")
	buf, err := NewEmptyBuffer(len(want))
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	r := bytes.NewReader(want)
	if _, err := buf.ReadFrom(r); err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadFrom: %v", err)
	}

	var out bytes.Buffer
	if _, err := buf.WriteTo(&out); err != nil {
		t.Fatalf("WriteTo after ReadFrom: %v", err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("ReadFrom round-trip: got %x, want %x", out.Bytes(), want)
	}
}

func TestNewBufferFromReader(t *testing.T) {
	t.Parallel()

	want := []byte("reader-secret")
	buf, n, err := NewBufferFromReader(bytes.NewReader(want), len(want))
	if err != nil {
		t.Fatalf("NewBufferFromReader: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if n != int64(len(want)) {
		t.Fatalf("NewBufferFromReader read %d bytes, want %d", n, len(want))
	}
	var match bool
	if err := buf.WithBytesErr(func(b []byte) error {
		match = bytes.Equal(b, want)
		return nil
	}); err != nil {
		t.Fatalf("WithBytesErr: %v", err)
	}
	if !match {
		t.Error("NewBufferFromReader stored unexpected bytes")
	}
}

func TestUseAsString(t *testing.T) {
	t.Parallel()

	raw := []byte("string-boundary-secret")
	want := append([]byte(nil), raw...)
	buf, err := NewBuffer(raw)
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	var gotLen int
	err = UseAsString(buf, "test-boundary", func(s string) error {
		if s != string(want) {
			t.Errorf("UseAsString got %q, want %q", s, want)
		}
		gotLen = len(s)
		return nil
	})
	if err != nil {
		t.Fatalf("UseAsString: %v", err)
	}
	if gotLen != len(want) {
		t.Errorf("UseAsString length = %d, want %d", gotLen, len(want))
	}
}

// TestRead_Write_BoundsCheck verifies that Read and Write return errors for
// out-of-range offsets rather than panicking.
func TestRead_Write_BoundsCheck(t *testing.T) {
	t.Parallel()

	const size = 16
	buf, err := NewEmptyBuffer(size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	t.Cleanup(func() { _ = buf.Destroy() })

	dst := make([]byte, 4)

	cases := []struct {
		name   string
		offset int
	}{
		{"negative", -1},
		{"equal_to_len", size},
		{"past_end", size + 10},
	}

	for _, tc := range cases {
		t.Run("Read/"+tc.name, func(t *testing.T) {
			t.Parallel()
			n, err := buf.Read(dst, tc.offset)
			if err == nil {
				t.Errorf("Read(offset=%d): expected error, got n=%d nil", tc.offset, n)
			}
		})
		t.Run("Write/"+tc.name, func(t *testing.T) {
			t.Parallel()
			src := make([]byte, 4)
			n, err := buf.Write(src, tc.offset)
			if err == nil {
				t.Errorf("Write(offset=%d): expected error, got n=%d nil", tc.offset, n)
			}
		})
	}

	// A zero-length dst/src at offset 0 should always succeed.
	if n, err := buf.Read(nil, 0); err != nil || n != 0 {
		t.Errorf("Read(nil, 0): got n=%d, err=%v; want 0, nil", n, err)
	}
}
