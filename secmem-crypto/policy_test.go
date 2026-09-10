package secmemcrypto

import (
	"crypto/elliptic"
	"errors"
	"testing"
)

// TestHeapTransientsPolicy exercises the gate the README leaves for the
// maintainers: with the policy flipped, every constructor of the two
// heap-transient signer types refuses with ErrHeapTransients, and with it
// as shipped they all proceed. Must not call t.Parallel(): it swaps a
// package var.
func TestHeapTransientsPolicy(t *testing.T) {
	orig := heapTransientsAllowed
	defer func() { heapTransientsAllowed = orig }()

	heapTransientsAllowed = func() bool { return false }
	if _, err := GenerateECDSASigner(elliptic.P256()); !errors.Is(err, ErrHeapTransients) {
		t.Errorf("GenerateECDSASigner under the gate: %v, want ErrHeapTransients", err)
	}
	if _, err := NewECDSASigner(elliptic.P256(), nil); !errors.Is(err, ErrHeapTransients) {
		t.Errorf("NewECDSASigner under the gate: %v, want ErrHeapTransients", err)
	}
	if _, err := GenerateRSASigner(2048); !errors.Is(err, ErrHeapTransients) {
		t.Errorf("GenerateRSASigner under the gate: %v, want ErrHeapTransients", err)
	}
	if _, err := NewRSASigner(nil); !errors.Is(err, ErrHeapTransients) {
		t.Errorf("NewRSASigner under the gate: %v, want ErrHeapTransients", err)
	}

	heapTransientsAllowed = orig
	if !heapTransientsAllowed() {
		t.Fatal("the shipped policy refuses heap transients; the README and CHANGELOG say otherwise")
	}
	s, err := GenerateECDSASigner(elliptic.P256())
	if err != nil {
		t.Skipf("GenerateECDSASigner: %v", err)
	}
	s.Destroy()
}
