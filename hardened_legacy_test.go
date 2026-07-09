//go:build !goexperiment.runtimesecret || !(linux && (amd64 || arm64))

// Tests for the legacy hardening layer.
// DO NOT REMOVE — these validate the Windows/Darwin memory-safety path.
// See hardened_legacy.go header for rationale.

package secmem

import (
	"errors"
	"strings"
	"testing"
)

// TestWipeBytes_ZerosSlice verifies WipeBytes zeros every byte in a non-empty slice.
func TestWipeBytes_ZerosSlice(t *testing.T) {
	t.Parallel()
	b := []byte("secret-password-1234")
	WipeBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte[%d] = %d, want 0", i, v)
		}
	}
}

// TestWipeBytes_EmptySlice verifies WipeBytes does not panic on nil or empty input.
func TestWipeBytes_EmptySlice(t *testing.T) {
	t.Parallel()
	WipeBytes(nil)
	WipeBytes([]byte{})
}

// TestWipeArray_ZerosArray verifies WipeArray (alias for WipeBytes) zeros the slice.
func TestWipeArray_ZerosArray(t *testing.T) {
	t.Parallel()
	b := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	WipeArray(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte[%d] = 0x%02X, want 0", i, v)
		}
	}
}

// TestSecureContext_Basic verifies that Do and DoErr both invoke the callback.
func TestSecureContext_Basic(t *testing.T) {
	t.Parallel()

	t.Run("Do_calls_fn", func(t *testing.T) {
		t.Parallel()
		called := false
		sc := NewSecureContext()
		defer sc.Close()
		sc.Do(func() { called = true })
		if !called {
			t.Error("Do: callback was not called")
		}
	})

	t.Run("DoErr_calls_fn", func(t *testing.T) {
		t.Parallel()
		called := false
		sc := NewSecureContext()
		defer sc.Close()
		err := sc.DoErr(func() error {
			called = true
			return nil
		})
		if err != nil {
			t.Errorf("DoErr: unexpected error: %v", err)
		}
		if !called {
			t.Error("DoErr: callback was not called")
		}
	})
}

// TestSecureContext_Panic verifies panic-recovery behavior.
// Do re-raises as *PanicError; DoErr returns *PanicError.
func TestSecureContext_Panic(t *testing.T) {
	t.Parallel()

	t.Run("Do_repanics_as_PanicError", func(t *testing.T) {
		t.Parallel()
		sc := NewSecureContext()
		var panicVal any
		func() {
			defer sc.Close()
			defer func() { panicVal = recover() }()
			// Do should re-panic with *PanicError — recovered by the outer defer above.
			sc.Do(func() { panic("test-panic-value") })
		}()

		pe, ok := panicVal.(*PanicError)
		if !ok {
			t.Fatalf("expected re-panic as *PanicError, got %T: %v", panicVal, panicVal)
		}
		if pe.Value != "test-panic-value" {
			t.Errorf("PanicError.Value = %v, want %q", pe.Value, "test-panic-value")
		}
	})

	t.Run("DoErr_returns_PanicError", func(t *testing.T) {
		t.Parallel()
		sc := NewSecureContext()
		defer sc.Close()

		err := sc.DoErr(func() error { panic("doerr-panic-value") })

		pe, ok := errors.AsType[*PanicError](err)
		if !ok {
			t.Fatalf("expected *PanicError error, got %T: %v", err, err)
		}
		if pe.Value != "doerr-panic-value" {
			t.Errorf("PanicError.Value = %v, want %q", pe.Value, "doerr-panic-value")
		}
		if len(pe.Stack) == 0 {
			t.Error("PanicError.Stack should not be empty")
		}
	})

	t.Run("Do_no_panic_is_silent", func(t *testing.T) {
		t.Parallel()
		sc := NewSecureContext()
		defer sc.Close()
		// Must not panic.
		sc.Do(func() {})
	})
}

// TestPanicError_Formatting verifies PanicError.Error() contains the panic value.
func TestPanicError_Formatting(t *testing.T) {
	t.Parallel()
	pe := &PanicError{Value: "catastrophic-oops", Stack: []byte("goroutine 1 [running]")}
	got := pe.Error()
	if !strings.Contains(got, "catastrophic-oops") {
		t.Errorf("Error() = %q, want to contain the panic value", got)
	}
}

// TestWithBytesHardened verifies the borrowed bytes are accessible inside the closure.
func TestWithBytesHardened(t *testing.T) {
	t.Parallel()
	buf, err := NewBuffer([]byte("hardened-key"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() {
		if dErr := buf.Destroy(); dErr != nil {
			t.Errorf("Destroy: %v", dErr)
		}
	}()

	var seen []byte
	err = WithBytesHardened(buf, func(b []byte) {
		seen = make([]byte, len(b))
		copy(seen, b)
	})
	if err != nil {
		t.Fatalf("WithBytesHardened: %v", err)
	}
	if string(seen) != "hardened-key" {
		t.Errorf("got %q, want %q", seen, "hardened-key")
	}
}

// TestWithBytesHardenedErr verifies error propagation and destroyed-buffer behavior.
func TestWithBytesHardenedErr(t *testing.T) {
	t.Parallel()

	t.Run("success_path", func(t *testing.T) {
		t.Parallel()
		buf, err := NewBuffer([]byte("hardened-key-err"))
		if err != nil {
			t.Fatalf("NewBuffer: %v", err)
		}
		defer func() {
			if dErr := buf.Destroy(); dErr != nil {
				t.Errorf("Destroy: %v", dErr)
			}
		}()

		var seen []byte
		err = WithBytesHardenedErr(buf, func(b []byte) error {
			seen = make([]byte, len(b))
			copy(seen, b)
			return nil
		})
		if err != nil {
			t.Fatalf("WithBytesHardenedErr: %v", err)
		}
		if string(seen) != "hardened-key-err" {
			t.Errorf("got %q, want %q", seen, "hardened-key-err")
		}
	})

	t.Run("destroyed_buffer_returns_ErrDestroyed", func(t *testing.T) {
		t.Parallel()
		buf, err := NewBuffer([]byte("gone"))
		if err != nil {
			t.Fatalf("NewBuffer: %v", err)
		}
		if dErr := buf.Destroy(); dErr != nil {
			t.Fatalf("Destroy: %v", dErr)
		}
		err = WithBytesHardenedErr(buf, func(_ []byte) error { return nil })
		if err == nil {
			t.Fatal("expected error for destroyed buffer, got nil")
		}
	})

	t.Run("fn_error_propagates", func(t *testing.T) {
		t.Parallel()
		buf, err := NewBuffer([]byte("key"))
		if err != nil {
			t.Fatalf("NewBuffer: %v", err)
		}
		defer func() {
			if dErr := buf.Destroy(); dErr != nil {
				t.Errorf("Destroy: %v", dErr)
			}
		}()

		sentinel := ErrDestroyed // reuse as a convenient non-nil sentinel error
		err = WithBytesHardenedErr(buf, func(_ []byte) error { return sentinel })
		if !errors.Is(err, sentinel) {
			t.Errorf("got %v, want sentinel error", err)
		}
	})
}
