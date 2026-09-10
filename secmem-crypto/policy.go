package secmemcrypto

import (
	"errors"
	"fmt"
)

// ErrHeapTransients marks a constructor refusing to build a key type whose
// every operation copies the secret through the Go heap — [RSASigner] and
// [ECDSASigner] — on a build where nothing erases those copies.
//
// No constructor returns it in this release: heapTransientsAllowed is
// permissive. It exists so that the decision recorded in the README under
// "What each signer actually buys you" — keep the two types as they are,
// gate them to GOEXPERIMENT=runtimesecret builds, or remove them — can be
// taken by changing one line rather than designing an API under pressure.
// Callers that want to be ready for it can test for it with errors.Is now.
var ErrHeapTransients = errors.New("secmemcrypto: operation would leave key material on the unprotected heap on this build")

// heapTransientsAllowed decides whether the constructors of RSASigner and
// ECDSASigner proceed on this build. Returning true unconditionally is the
// current policy. The alternative on the table is
//
//	var heapTransientsAllowed = secmem.RuntimeSecretActive
//
// which refuses both types on Windows, macOS, and any Linux build without
// the experiment, where the per-operation copies their type docs list are
// reclaimed by the collector but never zeroed. A package var, not a
// constant, so a test can exercise the refusal without a foreign build.
var heapTransientsAllowed = func() bool { return true }

// checkHeapTransients is the gate the constructors call; op names the
// constructor for the error.
func checkHeapTransients(op string) error {
	if heapTransientsAllowed() {
		return nil
	}
	return fmt.Errorf("%s: %w (build with GOEXPERIMENT=runtimesecret on linux/amd64 or linux/arm64, or keep the key in an HSM/KMS)", op, ErrHeapTransients)
}
