package secmem

import (
	"bytes"
	"errors"
	"testing"
)

func TestScrub_RunsFn(t *testing.T) {
	t.Parallel()
	ran := false
	Scrub(func() { ran = true })
	if !ran {
		t.Fatal("Scrub did not invoke fn")
	}
}

func TestScrubErr_PropagatesError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("boom")
	err := ScrubErr(func() error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("ScrubErr error = %v, want %v", err, sentinel)
	}
}

func TestScrubErr_NilOnSuccess(t *testing.T) {
	t.Parallel()
	if err := ScrubErr(func() error { return nil }); err != nil {
		t.Fatalf("ScrubErr = %v, want nil", err)
	}
}

// TestScrub_ResultSurvives is the guard against the runtime/secret erasure
// zeroing a result we still need. A value produced inside Scrub and kept
// referenced (assigned to an outer variable) MUST remain intact after Scrub
// returns. Run under GOEXPERIMENT=runtimesecret to exercise the real erasure:
//
//	GOEXPERIMENT=runtimesecret CGO_ENABLED=0 go test -run ResultSurvives ./...
func TestScrub_ResultSurvives(t *testing.T) {
	t.Parallel()

	want := make([]byte, 64)
	for i := range want {
		want[i] = byte(i*7 + 1)
	}

	// Produced inside Scrub, retained via the outer variable `got`.
	var got []byte
	Scrub(func() {
		got = make([]byte, 64)
		for i := range got {
			got[i] = byte(i*7 + 1)
		}
	})
	if !bytes.Equal(got, want) {
		t.Fatalf("result not preserved across Scrub: got %x", got)
	}

	// Same via the error-returning form and a copy-out into a caller buffer
	// (the documented best practice for results that must survive).
	out := make([]byte, 64)
	err := ScrubErr(func() error {
		tmp := make([]byte, 64)
		for i := range tmp {
			tmp[i] = byte(i*7 + 1)
		}
		copy(out, tmp)
		return nil
	})
	if err != nil {
		t.Fatalf("ScrubErr: %v", err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("copied-out result not preserved: got %x", out)
	}
}

func TestScrub_PanicPropagates(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic to propagate through Scrub")
		}
	}()
	Scrub(func() { panic("kaboom") })
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

// TestScrub_NilIsNoop verifies Scrub(nil)/ScrubErr(nil) do not panic
// and that ScrubErr(nil) returns nil.
func TestScrub_NilIsNoop(t *testing.T) {
	t.Parallel()
	Scrub(nil) // must not panic
	if err := ScrubErr(nil); err != nil {
		t.Errorf("ScrubErr(nil) = %v, want nil", err)
	}
}
