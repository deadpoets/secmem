package secmemcrypto

import (
	"testing"

	"filippo.io/edwards25519"
)

func TestWipeEd25519Scalar_ZeroesValue(t *testing.T) {
	t.Parallel()
	nonZero := make([]byte, 64)
	for i := range nonZero {
		nonZero[i] = byte(i + 1)
	}
	s, err := edwards25519.NewScalar().SetUniformBytes(nonZero)
	if err != nil {
		t.Fatalf("SetUniformBytes: %v", err)
	}
	zeroScalar := edwards25519.NewScalar()
	if s.Equal(zeroScalar) == 1 {
		t.Fatal("scalar is already zero before WipeEd25519Scalar")
	}

	WipeEd25519Scalar(s)
	if s.Equal(zeroScalar) != 1 {
		t.Error("WipeEd25519Scalar did not zero the scalar")
	}
}

func TestWipeEd25519Scalar_NilSafe(t *testing.T) {
	t.Parallel()
	WipeEd25519Scalar(nil) // must not panic
}
