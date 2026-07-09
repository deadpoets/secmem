package secmem

import (
	"bytes"
	"errors"
	"testing"
)

func TestSecretDo_RunsFn(t *testing.T) {
	t.Parallel()
	ran := false
	SecretDo(func() { ran = true })
	if !ran {
		t.Fatal("SecretDo did not invoke fn")
	}
}

func TestSecretDoErr_PropagatesError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("boom")
	err := SecretDoErr(func() error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("SecretDoErr error = %v, want %v", err, sentinel)
	}
}

func TestSecretDoErr_NilOnSuccess(t *testing.T) {
	t.Parallel()
	if err := SecretDoErr(func() error { return nil }); err != nil {
		t.Fatalf("SecretDoErr = %v, want nil", err)
	}
}

// TestSecretDo_ResultSurvives is the guard against the runtime/secret erasure
// zeroing a result we still need. A value produced inside SecretDo and kept
// referenced (assigned to an outer variable) MUST remain intact after SecretDo
// returns. Run under GOEXPERIMENT=runtimesecret to exercise the real erasure:
//
//	GOEXPERIMENT=runtimesecret CGO_ENABLED=0 go test -run ResultSurvives ./...
func TestSecretDo_ResultSurvives(t *testing.T) {
	t.Parallel()

	want := make([]byte, 64)
	for i := range want {
		want[i] = byte(i*7 + 1)
	}

	// Produced inside SecretDo, retained via the outer variable `got`.
	var got []byte
	SecretDo(func() {
		got = make([]byte, 64)
		for i := range got {
			got[i] = byte(i*7 + 1)
		}
	})
	if !bytes.Equal(got, want) {
		t.Fatalf("result not preserved across SecretDo: got %x", got)
	}

	// Same via the error-returning form and a copy-out into a caller buffer
	// (the documented best practice for results that must survive).
	out := make([]byte, 64)
	err := SecretDoErr(func() error {
		tmp := make([]byte, 64)
		for i := range tmp {
			tmp[i] = byte(i*7 + 1)
		}
		copy(out, tmp)
		return nil
	})
	if err != nil {
		t.Fatalf("SecretDoErr: %v", err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("copied-out result not preserved: got %x", out)
	}
}

func TestSecretDo_PanicPropagates(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic to propagate through SecretDo")
		}
	}()
	SecretDo(func() { panic("kaboom") })
}

// TestAssertRuntimeSecret_ConsistentWithActive verifies the posture policy:
// AssertRuntimeSecret returns nil iff the erasure layer is active OR the
// platform does not support it. On a supported-but-inactive build it returns
// ErrRuntimeSecretInactive.
func TestAssertRuntimeSecret_ConsistentWithActive(t *testing.T) {
	t.Parallel()
	err := AssertRuntimeSecret()
	if RuntimeSecretActive() {
		// Active implies supported, so the assertion must pass.
		if err != nil {
			t.Fatalf("runtime secret active but AssertRuntimeSecret = %v", err)
		}
		return
	}
	// Inactive: error must be nil (unsupported platform) or the sentinel
	// (supported platform misbuild). It must never be some other error.
	if err != nil && !errors.Is(err, ErrRuntimeSecretInactive) {
		t.Fatalf("unexpected AssertRuntimeSecret error: %v", err)
	}
}
