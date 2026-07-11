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

// TestCopyInOut_RoundTrip verifies Read and Write.
func TestCopyInOut_RoundTrip(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(8)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	src := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if n, err := buf.CopyIn(src, 0); err != nil || n != len(src) {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}

	dst := make([]byte, 8)
	if n, err := buf.CopyOut(dst, 0); err != nil || n != len(src) {
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

// TestConstantTimeEqual verifies constant-time comparison.
func TestConstantTimeEqual(t *testing.T) {
	t.Parallel()

	data := []byte("secret-value-32-bytes-long-test!")
	want := make([]byte, len(data))
	copy(want, data) // save before NewBuffer wipes the input
	buf, err := NewBuffer(data)
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	equal, err := buf.ConstantTimeEqual(want)
	if err != nil {
		t.Fatalf("ConstantTimeEqual: %v", err)
	}
	if !equal {
		t.Error("ConstantTimeEqual: expected true for matching bytes")
	}

	other := []byte("different-value-32-bytes-long---!")
	notEqual, err := buf.ConstantTimeEqual(other)
	if err != nil {
		t.Fatalf("ConstantTimeEqual (different): %v", err)
	}
	if notEqual {
		t.Error("ConstantTimeEqual: expected false for different bytes")
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

// TestExposeString_ReturnsCopy verifies ExposeString returns the exact buffer
// contents, including the len==1 case (which the runtime serves from a shared
// static table rather than a fresh allocation).
func TestExposeString_ReturnsCopy(t *testing.T) {
	t.Parallel()

	for _, want := range []string{"s", "expose-string-secret"} {
		t.Run(want, func(t *testing.T) {
			t.Parallel()
			buf, err := NewBuffer([]byte(want))
			if err != nil {
				t.Fatalf("NewBuffer: %v", err)
			}
			defer func() { _ = buf.Destroy() }()

			got, err := buf.ExposeString()
			if err != nil {
				t.Fatalf("ExposeString: %v", err)
			}
			if got != want {
				t.Errorf("ExposeString = %q, want %q", got, want)
			}
		})
	}
}

// TestExposeString_BufferStateErrors verifies ExposeString returns the
// buffer-state sentinel and an empty string on a nil, destroyed, or sealed
// buffer.
func TestExposeString_BufferStateErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		setup func(t *testing.T) *SecureBuffer
		want  error
	}{
		{"nil_buffer", func(t *testing.T) *SecureBuffer { return nil }, ErrDestroyed},
		{"destroyed", func(t *testing.T) *SecureBuffer {
			buf, err := NewEmptyBuffer(16)
			if err != nil {
				t.Fatalf("NewEmptyBuffer: %v", err)
			}
			if err := buf.Destroy(); err != nil {
				t.Fatalf("Destroy: %v", err)
			}
			return buf
		}, ErrDestroyed},
		{"sealed", func(t *testing.T) *SecureBuffer {
			buf, err := NewEmptyBuffer(16)
			if err != nil {
				t.Fatalf("NewEmptyBuffer: %v", err)
			}
			if err := buf.Seal(); err != nil {
				t.Fatalf("Seal: %v", err)
			}
			t.Cleanup(func() { _ = buf.Destroy() })
			return buf
		}, ErrSealed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			buf := tc.setup(t)
			got, err := buf.ExposeString()
			if !errors.Is(err, tc.want) {
				t.Errorf("ExposeString err = %v, want %v", err, tc.want)
			}
			if got != "" {
				t.Errorf("ExposeString returned %q on error, want empty string", got)
			}
		})
	}
}

// TestExposeString_CopySurvivesDestroy pins the load-bearing contract: the
// returned string is an independent copy that stays valid after the buffer is
// destroyed. A future switch to a wiped or zero-copy handoff would break this —
// and every real consumer that keeps the string.
func TestExposeString_CopySurvivesDestroy(t *testing.T) {
	t.Parallel()

	const want = "retained-past-destroy"
	buf, err := NewBuffer([]byte(want))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}

	got, err := buf.ExposeString()
	if err != nil {
		t.Fatalf("ExposeString: %v", err)
	}
	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if got != want {
		t.Errorf("string = %q after Destroy, want %q", got, want)
	}
}

// TestNilCallback_ReturnsError verifies the borrowing accessors return an error
// instead of panicking when handed a nil callback (no-panic rule).
func TestNilCallback_ReturnsError(t *testing.T) {
	t.Parallel()

	buf, err := NewBuffer([]byte("nil-callback-secret"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	arena, err := NewArena(16, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = arena.Destroy() }()
	slot, err := arena.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	goodCtor := func() (*SecureBuffer, error) { return NewEmptyBuffer(16) }
	goodFn := func(*SecureBuffer) error { return nil }

	cases := []struct {
		name string
		call func() error
	}{
		{"SecureBuffer.WithBytes", func() error { return buf.WithBytes(nil) }},
		{"SecureBuffer.WithBytesErr", func() error { return buf.WithBytesErr(nil) }},
		{"ArenaSlot.WithBytes", func() error { return slot.WithBytes(nil) }},
		{"ArenaSlot.WithBytesErr", func() error { return slot.WithBytesErr(nil) }},
		{"Scope", func() error { return Scope(16, nil) }},
		{"ScopeWith_nil_ctor", func() error { return ScopeWith(nil, goodFn) }},
		{"ScopeWith_nil_fn", func() error { return ScopeWith(goodCtor, nil) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.call(); err == nil {
				t.Errorf("%s(nil): expected error, got nil", tc.name)
			}
		})
	}
}

// TestCopyOut_CopyIn_BoundsCheck verifies that Read and Write return errors for
// out-of-range offsets rather than panicking.
func TestCopyOut_CopyIn_BoundsCheck(t *testing.T) {
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
			n, err := buf.CopyOut(dst, tc.offset)
			if err == nil {
				t.Errorf("Read(offset=%d): expected error, got n=%d nil", tc.offset, n)
			}
		})
		t.Run("Write/"+tc.name, func(t *testing.T) {
			t.Parallel()
			src := make([]byte, 4)
			n, err := buf.CopyIn(src, tc.offset)
			if err == nil {
				t.Errorf("Write(offset=%d): expected error, got n=%d nil", tc.offset, n)
			}
		})
	}

	// A zero-length dst/src at offset 0 should always succeed.
	if n, err := buf.CopyOut(nil, 0); err != nil || n != 0 {
		t.Errorf("Read(nil, 0): got n=%d, err=%v; want 0, nil", n, err)
	}
}
