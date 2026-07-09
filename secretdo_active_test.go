//go:build goexperiment.runtimesecret && linux && (amd64 || arm64)

package secmem

import "testing"

// TestRuntimeSecretActive_TrueUnderExperiment pins the load-bearing invariant:
// when built WITH GOEXPERIMENT=runtimesecret on a supported platform, the erasure
// layer is active and AssertRuntimeSecret must pass at startup (outside any Do).
//
// This is the regression guard for the fail-closed brick: a prior implementation
// used runtime/secret.Enabled() — which reports whether Do is on the CURRENT
// stack — so it returned false at startup and refused to start every correctly
// built production binary. RuntimeSecretActive must reflect "experiment compiled
// in", which the build tag on this file already guarantees.
func TestRuntimeSecretActive_TrueUnderExperiment(t *testing.T) {
	t.Parallel()
	if !RuntimeSecretActive() {
		t.Fatal("built with GOEXPERIMENT=runtimesecret on a supported platform, but RuntimeSecretActive()=false")
	}
	if err := AssertRuntimeSecret(); err != nil {
		t.Fatalf("AssertRuntimeSecret must pass on a correctly-built binary, got: %v", err)
	}
}
