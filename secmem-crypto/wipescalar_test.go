package secmemcrypto

import (
	"testing"

	"filippo.io/edwards25519"
)

func TestWipeScalar_ZeroesValue(t *testing.T) {
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
		t.Fatal("scalar is already zero before WipeScalar")
	}

	WipeScalar(s)
	if s.Equal(zeroScalar) != 1 {
		t.Error("WipeScalar did not zero the scalar")
	}
}

func TestWipeScalar_NilSafe(t *testing.T) {
	t.Parallel()
	WipeScalar(nil) // must not panic
}
