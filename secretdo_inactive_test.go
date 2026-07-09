//go:build !goexperiment.runtimesecret || !(linux && (amd64 || arm64))

package secmem

import (
	"errors"
	"testing"
)

// TestRuntimeSecretActive_FalseWithoutExperiment pins the legacy/unsupported
// posture: without the experiment (or on a platform it does not support) the
// erasure layer is inactive, so RuntimeSecretActive is false. AssertRuntimeSecret
// then returns the misbuild sentinel on a supported platform built without the
// experiment, or nil on an unsupported platform — never some other error.
func TestRuntimeSecretActive_FalseWithoutExperiment(t *testing.T) {
	t.Parallel()
	if RuntimeSecretActive() {
		t.Fatal("built without the runtimesecret experiment (or unsupported platform), but RuntimeSecretActive()=true")
	}
	if err := AssertRuntimeSecret(); err != nil && !errors.Is(err, ErrRuntimeSecretInactive) {
		t.Fatalf("AssertRuntimeSecret returned an unexpected error: %v", err)
	}
}
