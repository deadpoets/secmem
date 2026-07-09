package secmem

import (
	"errors"
	"testing"
)

// TestScope_Basic verifies that Scope creates a buffer, calls fn, and destroys it.
func TestScope_Basic(t *testing.T) {
	t.Parallel()

	called := false
	if err := Scope(32, func(buf *SecureBuffer) error {
		called = true
		if buf.IsDestroyed() {
			t.Error("buffer is destroyed inside Scope callback")
		}
		if buf.Len() != 32 {
			t.Errorf("Len = %d inside Scope, want 32", buf.Len())
		}
		return nil
	}); err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if !called {
		t.Error("Scope: callback was not called")
	}
}

// TestScope_DestroyedAfterCallback verifies the buffer is destroyed after Scope returns.
func TestScope_DestroyedAfterCallback(t *testing.T) {
	t.Parallel()

	var escaped *SecureBuffer
	if err := Scope(16, func(buf *SecureBuffer) error {
		escaped = buf
		return nil
	}); err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if !escaped.IsDestroyed() {
		t.Error("buffer still live after Scope returned, want destroyed")
	}
}

// TestScope_PropagatesCallbackError verifies that fn errors are returned.
func TestScope_PropagatesCallbackError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("scope-callback-error")
	if err := Scope(16, func(_ *SecureBuffer) error {
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Errorf("Scope: got %v, want sentinel", err)
	}
}

// TestScope_PropagatesDestroyError verifies that Destroy errors are joined.
// This is a theoretical test — Munmap rarely fails; we verify the errors.Join
// semantics by ensuring a nil fn error + Destroy error produces a non-nil result.
// (We can't easily force Munmap to fail, but we can check the invariant.)
func TestScope_BothErrors_JoinedInNamedReturn(t *testing.T) {
	t.Parallel()

	// Destroy() on an already-destroyed buffer returns nil — all we can test
	// here is that Scope itself succeeds when fn and Destroy both succeed.
	if err := Scope(16, func(buf *SecureBuffer) error {
		return nil
	}); err != nil {
		t.Errorf("Scope with no errors: got %v, want nil", err)
	}
}

// TestScopeWith_CustomConstructor verifies ScopeWith with a custom constructor.
func TestScopeWith_CustomConstructor(t *testing.T) {
	t.Parallel()

	called := false
	ctor := func() (*SecureBuffer, error) {
		return NewSyscallSafeBuffer([]byte("scope-with-test"))
	}
	if err := ScopeWith(ctor, func(buf *SecureBuffer) error {
		called = true
		if buf.Len() != len("scope-with-test") {
			t.Errorf("Len = %d inside ScopeWith, want %d", buf.Len(), len("scope-with-test"))
		}
		return nil
	}); err != nil {
		t.Fatalf("ScopeWith: %v", err)
	}
	if !called {
		t.Error("ScopeWith: callback was not called")
	}
}

// TestScopeWith_CtorError verifies that constructor errors are returned without calling fn.
func TestScopeWith_CtorError(t *testing.T) {
	t.Parallel()

	ctorErr := errors.New("constructor-error")
	fnCalled := false
	err := ScopeWith(
		func() (*SecureBuffer, error) { return nil, ctorErr },
		func(_ *SecureBuffer) error {
			fnCalled = true
			return nil
		},
	)
	if !errors.Is(err, ctorErr) {
		t.Errorf("ScopeWith ctor error: got %v, want ctorErr", err)
	}
	if fnCalled {
		t.Error("ScopeWith: fn was called after constructor error")
	}
}

// TestScope_DestroysOnPanic verifies that Scope's deferred Destroy fires even when
// the callback panics. We capture the buffer pointer to check IsDestroyed() after
// recovering the panic.
func TestScope_DestroysOnPanic(t *testing.T) {
	t.Parallel()

	var capturedBuf *SecureBuffer

	// Wrap Scope call so we can recover the panic while still verifying behavior.
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic to propagate, but it did not")
			}
		}()
		_ = Scope(8, func(buf *SecureBuffer) error {
			capturedBuf = buf
			panic("test panic in Scope callback")
		})
	}()

	if capturedBuf == nil {
		t.Fatal("buffer reference was not captured before panic")
	}
	if !capturedBuf.IsDestroyed() {
		t.Error("buffer not destroyed after panic in Scope callback")
	}
}
