package secmem

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestSeal_StateTracking verifies IsSealed reports the correct state after
// Seal and Unseal transitions.
func TestSeal_StateTracking(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if buf.IsSealed() {
		t.Error("IsSealed() should be false on a newly created buffer")
	}

	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !buf.IsSealed() {
		t.Error("IsSealed() should be true after Seal()")
	}

	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if buf.IsSealed() {
		t.Error("IsSealed() should be false after Unseal()")
	}
}

// TestSeal_Idempotent verifies that calling Seal multiple times is safe.
func TestSeal_Idempotent(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.Seal(); err != nil {
		t.Fatalf("first Seal: %v", err)
	}
	if err := buf.Seal(); err != nil {
		t.Fatalf("second Seal (idempotent): %v", err)
	}
	if !buf.IsSealed() {
		t.Error("IsSealed() should be true after double Seal()")
	}
}

// TestUnseal_Idempotent verifies that calling Unseal on an unsealed buffer
// is a safe no-op.
func TestUnseal_Idempotent(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	// Unseal on an already-unsealed buffer must not error.
	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal on unsealed buffer: %v", err)
	}
	if buf.IsSealed() {
		t.Error("IsSealed() should still be false after no-op Unseal()")
	}
}

// TestSeal_AccessMethodsReturnErrSealed verifies that all access methods return
// ErrSealed after Seal() is called.
func TestSeal_AccessMethodsReturnErrSealed(t *testing.T) {
	// Not parallel: subtests share one sealed buf with a deferred Destroy, so they
	// must run serially before the parent returns (a parallel subtest would touch
	// buf after Destroy). Keeping the parent serial keeps t.Parallel use consistent.

	buf, err := NewBuffer(bytes.Repeat([]byte{0xAB}, 32))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	t.Run("WithBytes", func(t *testing.T) {
		gotErr := buf.WithBytes(func(_ []byte) { t.Error("callback must not be called") })
		if !errors.Is(gotErr, ErrSealed) {
			t.Errorf("WithBytes = %v, want ErrSealed", gotErr)
		}
	})

	t.Run("WithBytesErr", func(t *testing.T) {
		gotErr := buf.WithBytesErr(func(_ []byte) error {
			t.Error("callback must not be called")
			return nil
		})
		if !errors.Is(gotErr, ErrSealed) {
			t.Errorf("WithBytesErr = %v, want ErrSealed", gotErr)
		}
	})

	t.Run("CopyOut", func(t *testing.T) {
		dst := make([]byte, 8)
		_, gotErr := buf.CopyOut(dst, 0)
		if !errors.Is(gotErr, ErrSealed) {
			t.Errorf("CopyOut = %v, want ErrSealed", gotErr)
		}
	})

	t.Run("CopyIn", func(t *testing.T) {
		_, gotErr := buf.CopyIn([]byte{0x00}, 0)
		if !errors.Is(gotErr, ErrSealed) {
			t.Errorf("CopyIn = %v, want ErrSealed", gotErr)
		}
	})

	t.Run("ByteAt", func(t *testing.T) {
		_, gotErr := buf.ByteAt(0)
		if !errors.Is(gotErr, ErrSealed) {
			t.Errorf("ByteAt = %v, want ErrSealed", gotErr)
		}
	})

	t.Run("SetByteAt", func(t *testing.T) {
		gotErr := buf.SetByteAt(0, 0x00)
		if !errors.Is(gotErr, ErrSealed) {
			t.Errorf("SetByteAt = %v, want ErrSealed", gotErr)
		}
	})

	t.Run("ConstantTimeEqual", func(t *testing.T) {
		_, gotErr := buf.ConstantTimeEqual(make([]byte, 32))
		if !errors.Is(gotErr, ErrSealed) {
			t.Errorf("ConstantTimeEqual = %v, want ErrSealed", gotErr)
		}
	})

	t.Run("WriteTo", func(t *testing.T) {
		var w strings.Builder
		_, gotErr := buf.WriteTo(&w)
		if !errors.Is(gotErr, ErrSealed) {
			t.Errorf("WriteTo = %v, want ErrSealed", gotErr)
		}
	})

	t.Run("ReadFrom", func(t *testing.T) {
		r := bytes.NewReader(bytes.Repeat([]byte{0xCC}, 32))
		_, gotErr := buf.ReadFrom(r)
		if !errors.Is(gotErr, ErrSealed) {
			t.Errorf("ReadFrom = %v, want ErrSealed", gotErr)
		}
	})
}

// TestUnseal_RestoresAccess verifies that Unseal after Seal allows normal access.
func TestUnseal_RestoresAccess(t *testing.T) {
	t.Parallel()

	secret := bytes.Repeat([]byte{0xDE}, 16)
	want := make([]byte, len(secret))
	copy(want, secret)

	buf, err := NewBuffer(secret)
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal: %v", err)
	}

	// Assert inside the callback — never copy borrowed secret bytes out of it.
	if err := buf.WithBytesErr(func(b []byte) error {
		if !bytes.Equal(b, want) {
			t.Errorf("data after Seal+Unseal mismatch (want %x)", want)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytesErr after Unseal: %v", err)
	}
}

// TestSeal_ThenDestroy verifies that Destroy works correctly on a sealed buffer.
func TestSeal_ThenDestroy(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}

	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if err := buf.Destroy(); err != nil {
		t.Errorf("Destroy on sealed buffer: %v", err)
	}
	if !buf.IsDestroyed() {
		t.Error("IsDestroyed() should be true after Destroy()")
	}
}

// TestSeal_OnDestroyedBuffer verifies that Seal returns ErrDestroyed after Destroy.
func TestSeal_OnDestroyedBuffer(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	if gotErr := buf.Seal(); !errors.Is(gotErr, ErrDestroyed) {
		t.Errorf("Seal on destroyed buffer = %v, want ErrDestroyed", gotErr)
	}
}

// TestUnseal_OnDestroyedBuffer verifies that Unseal returns ErrDestroyed after Destroy.
func TestUnseal_OnDestroyedBuffer(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	if gotErr := buf.Unseal(); !errors.Is(gotErr, ErrDestroyed) {
		t.Errorf("Unseal on destroyed buffer = %v, want ErrDestroyed", gotErr)
	}
}

// TestSeal_NilReceiver verifies that Seal on a nil receiver returns an error.
func TestSeal_NilReceiver(t *testing.T) {
	t.Parallel()

	var buf *SecureBuffer
	if err := buf.Seal(); err == nil {
		t.Error("Seal on nil receiver: expected error, got nil")
	}
}

// TestUnseal_NilReceiver verifies that Unseal on a nil receiver returns an error.
func TestUnseal_NilReceiver(t *testing.T) {
	t.Parallel()

	var buf *SecureBuffer
	if err := buf.Unseal(); err == nil {
		t.Error("Unseal on nil receiver: expected error, got nil")
	}
}

// TestIsSealed_NilReceiver verifies that IsSealed on a nil receiver returns false.
func TestIsSealed_NilReceiver(t *testing.T) {
	t.Parallel()

	var buf *SecureBuffer
	if buf.IsSealed() {
		t.Error("IsSealed on nil receiver should return false")
	}
}

// TestReadOnly_OnSealedBuffer verifies ReadOnly returns ErrSealed when sealed.
func TestReadOnly_OnSealedBuffer(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if gotErr := buf.ReadOnly(); !errors.Is(gotErr, ErrSealed) {
		t.Errorf("ReadOnly on sealed buffer = %v, want ErrSealed", gotErr)
	}
}

// TestReadWrite_OnSealedBuffer verifies ReadWrite returns ErrSealed when sealed.
func TestReadWrite_OnSealedBuffer(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if gotErr := buf.ReadWrite(); !errors.Is(gotErr, ErrSealed) {
		t.Errorf("ReadWrite on sealed buffer = %v, want ErrSealed", gotErr)
	}
}
