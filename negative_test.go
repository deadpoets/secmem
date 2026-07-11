package secmem

import (
	"bytes"
	"io"
	"math"
	"strings"
	"testing"
)

// The negative suite proves the library's failure-mode promises, which are as
// load-bearing as its features: constructors return errors and NEVER panic
// on a bad allocation, every method is safe on a nil receiver and after
// Destroy/Seal, and no adversarial input can make a redacting method leak.
// A security library that panics on a bad allocation or leaks on a bad
// input is worse than none.

// mustNotPanic runs fn and turns a panic into a test failure with a label,
// so one bad case does not abort the whole table.
func mustNotPanic(t *testing.T, label string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked: %v", label, r)
		}
	}()
	fn()
}

// TestConstructors_NeverPanicOnBadInput drives every constructor with empty,
// zero, negative, and overflow-sized inputs. Each must return an error, not
// panic and not a usable buffer.
func TestConstructors_NeverPanicOnBadInput(t *testing.T) {
	t.Parallel()
	huge := math.MaxInt // page-rounding + guard math must reject this, not overflow

	mustNotPanic(t, "NewBuffer(nil)", func() {
		if b, err := NewBuffer(nil); err == nil {
			_ = b.Destroy()
			t.Error("NewBuffer(nil) returned no error")
		}
	})
	mustNotPanic(t, "NewBuffer(empty)", func() {
		if _, err := NewBuffer([]byte{}); err == nil {
			t.Error("NewBuffer(empty) returned no error")
		}
	})
	mustNotPanic(t, "NewEmptyBuffer(0)", func() {
		if _, err := NewEmptyBuffer(0); err == nil {
			t.Error("NewEmptyBuffer(0) returned no error")
		}
	})
	mustNotPanic(t, "NewEmptyBuffer(negative)", func() {
		if _, err := NewEmptyBuffer(-1); err == nil {
			t.Error("NewEmptyBuffer(-1) returned no error")
		}
	})
	mustNotPanic(t, "NewEmptyBuffer(huge)", func() {
		if b, err := NewEmptyBuffer(huge); err == nil {
			_ = b.Destroy()
			t.Error("NewEmptyBuffer(MaxInt) returned no error — overflow guard missing")
		}
	})
	mustNotPanic(t, "NewSyscallSafeBuffer(nil)", func() {
		if _, err := NewSyscallSafeBuffer(nil); err == nil {
			t.Error("NewSyscallSafeBuffer(nil) returned no error")
		}
	})
	mustNotPanic(t, "NewArena(0,0)", func() {
		if _, err := NewArena(0, 0); err == nil {
			t.Error("NewArena(0,0) returned no error")
		}
	})
	mustNotPanic(t, "NewArena(huge,huge)", func() {
		if a, err := NewArena(huge, huge); err == nil {
			_ = a.Destroy()
			t.Error("NewArena(MaxInt,MaxInt) returned no error — overflow guard missing")
		}
	})
	mustNotPanic(t, "NewSecret(nil)", func() {
		if _, err := NewSecret(nil); err == nil {
			t.Error("NewSecret(nil) returned no error")
		}
	})
	mustNotPanic(t, "NewBufferFromReader(negative)", func() {
		if b, _, err := NewBufferFromReader(bytes.NewReader([]byte("x")), -1); err == nil {
			_ = b.Destroy()
			t.Error("NewBufferFromReader(negative) returned no error")
		}
	})
	mustNotPanic(t, "Scope(bad)", func() {
		if err := Scope(-1, func(*SecureBuffer) error { return nil }); err == nil {
			t.Error("Scope(-1) returned no error")
		}
	})
	mustNotPanic(t, "Scope(nil fn)", func() {
		if err := Scope(16, nil); err == nil {
			t.Error("Scope(nil fn) returned no error")
		}
	})
}

// TestBuffer_NeverPanicsAfterDestroy calls every method on a destroyed buffer
// and requires no panic (errors or safe zero values are fine).
func TestBuffer_NeverPanicsAfterDestroy(t *testing.T) {
	t.Parallel()
	buf, err := NewBuffer([]byte("to-be-destroyed"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	mustNotPanic(t, "destroyed buffer method sweep", func() {
		_ = buf.IsDestroyed()
		_ = buf.Len()
		_ = buf.MappedLen()
		_ = buf.IsSealed()
		_ = buf.ReadOnly()
		_ = buf.ReadWrite()
		_ = buf.Seal()
		_ = buf.Unseal()
		_ = buf.Truncate(0)
		_ = buf.WithBytes(func([]byte) {})
		_ = buf.WithBytesErr(func([]byte) error { return nil })
		_, _ = buf.ExposeString()
		_, _ = buf.CopyOut(make([]byte, 4), 0)
		_, _ = buf.CopyIn([]byte("x"), 0)
		_, _ = buf.ByteAt(0)
		_ = buf.SetByteAt(0, 1)
		_, _ = buf.ConstantTimeEqual([]byte("x"))
		_, _ = buf.WriteTo(io.Discard)
		_, _ = buf.ReadFrom(bytes.NewReader([]byte("x")))
		_ = buf.Capabilities()
		_ = buf.Destroy() // idempotent
	})
}

// TestBuffer_NilReceiverNeverPanics calls every method on a nil *SecureBuffer.
func TestBuffer_NilReceiverNeverPanics(t *testing.T) {
	t.Parallel()
	var buf *SecureBuffer
	mustNotPanic(t, "nil buffer method sweep", func() {
		_ = buf.IsDestroyed()
		_ = buf.Len()
		_ = buf.MappedLen()
		_ = buf.IsSealed()
		_ = buf.ReadOnly()
		_ = buf.ReadWrite()
		_ = buf.Seal()
		_ = buf.Unseal()
		_ = buf.Truncate(0)
		_ = buf.WithBytes(func([]byte) {})
		_, _ = buf.CopyOut(make([]byte, 4), 0)
		_, _ = buf.ByteAt(0)
		_, _ = buf.ConstantTimeEqual([]byte("x"))
		_, _ = buf.WriteTo(io.Discard)
		_ = buf.Capabilities()
		_ = buf.Destroy()
	})
}

// TestArenaAndSlot_NilAndDestroyed sweeps arena and slot methods on nil
// receivers and after Destroy.
func TestArenaAndSlot_NilAndDestroyed(t *testing.T) {
	t.Parallel()
	var arena *SecureArena
	var slot *ArenaSlot
	mustNotPanic(t, "nil arena/slot sweep", func() {
		_ = arena.IsDestroyed()
		_, _ = arena.Acquire()
		_ = arena.LiveCount()
		_ = arena.Cap()
		_ = arena.SlotSize()
		_ = arena.ReadOnly()
		_ = arena.Destroy()
		_ = arena.Capabilities()
		_ = slot.WithBytes(func([]byte) {})
		_ = slot.Release()
		_ = slot.Index()
		_ = slot.IsLive()
	})

	a, err := NewArena(32, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	s, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := a.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	mustNotPanic(t, "destroyed arena/slot sweep", func() {
		_, _ = a.Acquire()
		_ = a.LiveCount()
		_ = a.ReadOnly()
		_ = s.WithBytes(func([]byte) {})
		_ = s.Release()
		_ = s.IsLive()
		_ = a.Destroy() // idempotent
	})
}

// TestSecret_RedactionNeverLeaks_Table drives the redaction surface with
// adversarial contents, including the sentinel itself and control bytes.
func TestSecret_RedactionNeverLeaks_Table(t *testing.T) {
	t.Parallel()
	inputs := [][]byte{
		[]byte("[REDACTED]"),
		[]byte("password=hunter2"),
		bytes.Repeat([]byte{0}, 64),
		bytes.Repeat([]byte{0xFF}, 64),
		[]byte("\x1b[31m\r\n"),
		[]byte(strings.Repeat("A", 4096)),
	}
	for _, in := range inputs {
		s, err := NewSecret(append([]byte(nil), in...))
		if err != nil {
			t.Fatalf("NewSecret: %v", err)
		}
		for name, out := range map[string]string{
			"String":   s.String(),
			"GoString": s.GoString(),
		} {
			if out != redacted {
				t.Errorf("%s = %q, want the sentinel", name, out)
			}
		}
		jb, _ := s.MarshalJSON()
		tb, _ := s.MarshalText()
		if string(jb) != `"`+redacted+`"` {
			t.Errorf("MarshalJSON = %q", jb)
		}
		if string(tb) != redacted {
			t.Errorf("MarshalText = %q", tb)
		}
		if v := s.LogValue().String(); v != redacted {
			t.Errorf("LogValue = %q", v)
		}
		_ = s.Destroy()
	}
}

// FuzzNewBuffer_RoundTrip proves that for ANY non-empty input, NewBuffer
// copies it faithfully, wipes the source, and never panics — and Destroy is
// always clean (no false canary violation).
func FuzzNewBuffer_RoundTrip(f *testing.F) {
	f.Add([]byte("seed"))
	f.Add([]byte{0})
	f.Add(bytes.Repeat([]byte{0xAB}, 5000))
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) == 0 {
			return // empty is a documented error, covered elsewhere
		}
		src := append([]byte(nil), in...)
		buf, err := NewBuffer(src)
		if err != nil {
			return // e.g. RLIMIT_MEMLOCK — an error is an acceptable outcome
		}
		// Source must be wiped.
		for _, b := range src {
			if b != 0 {
				t.Fatal("NewBuffer did not wipe its input")
			}
		}
		// Contents must match the original.
		if err := buf.WithBytes(func(b []byte) {
			if !bytes.Equal(b, in) {
				t.Fatal("round-trip mismatch")
			}
		}); err != nil {
			t.Fatalf("WithBytes: %v", err)
		}
		if err := buf.Destroy(); err != nil {
			t.Fatalf("Destroy reported: %v", err)
		}
	})
}

// FuzzSecret_NeverLeaks proves no input makes a redacting method emit anything
// but the sentinel, and never the input bytes (unless the input already IS the
// sentinel text).
func FuzzSecret_NeverLeaks(f *testing.F) {
	f.Add([]byte("api_key=SECRETVALUE"))
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) == 0 {
			return
		}
		s, err := NewSecret(append([]byte(nil), in...))
		if err != nil {
			return
		}
		defer func() { _ = s.Destroy() }()

		for _, out := range []string{s.String(), s.GoString(), s.LogValue().String()} {
			if out != redacted {
				t.Fatalf("redaction emitted non-sentinel: %q", out)
			}
		}
		jb, _ := s.MarshalJSON()
		if !bytes.Equal(jb, []byte(`"`+redacted+`"`)) {
			t.Fatalf("MarshalJSON = %q", jb)
		}
	})
}
