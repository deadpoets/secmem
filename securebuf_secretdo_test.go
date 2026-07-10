//go:build goexperiment.runtimesecret

// Integration test for the runtime/secret.Do + SecureBuffer.WithBytesErr pattern.
// Build-tagged so the main test suite compiles without GOEXPERIMENT=runtimesecret.

package secmem

import (
	"bytes"
	"runtime/secret"
	"testing"
)

// TestSecretDo_WithBytesErr_Integration verifies that calling secret.Do wrapping
// a WithBytesErr callback:
//   - Does not panic (no stack-manipulation interaction with bufferRWLock)
//   - Provides access to the correct bytes inside the callback
//   - Reports secret.Enabled() = true (confirming runtime erasure is active)
//
// This is the only test that imports runtime/secret. It is build-tagged to
// ensure the main test suite compiles without GOEXPERIMENT=runtimesecret.
func TestSecretDo_WithBytesErr_Integration(t *testing.T) {
	t.Parallel()

	input := []byte("secret-do-integration-key")
	want := make([]byte, len(input))
	copy(want, input)

	buf, err := NewBuffer(input) // wipes input after copying
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	var (
		callbackRan     bool
		secretEnabled   bool
		dataMatchedWant bool
	)

	secret.Do(func() {
		secretEnabled = secret.Enabled()

		accessErr := buf.WithBytesErr(func(got []byte) error {
			callbackRan = true
			dataMatchedWant = bytes.Equal(got, want)
			return nil
		})
		if accessErr != nil {
			t.Errorf("WithBytesErr inside secret.Do: %v", accessErr)
		}
	})

	if !callbackRan {
		t.Error("WithBytesErr callback did not run inside secret.Do")
	}
	if !secretEnabled {
		t.Error("secret.Enabled() = false inside secret.Do; GOEXPERIMENT=runtimesecret may not be active")
	}
	if !dataMatchedWant {
		t.Error("data mismatch inside secret.Do callback")
	}
}
