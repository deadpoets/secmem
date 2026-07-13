package secmemcrypto

import (
	"bytes"
	"crypto/mlkem"
	"errors"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/deadpoets/secmem"
)

// TestX25519Key_SealedBuffer verifies every X25519Key borrow path surfaces a clean
// errors.Is(ErrSealed) while the backing buffer is sealed, and recovers
// after Unseal — the block-1 sealed-regression standard, applied to X25519Key.
func TestX25519Key_SealedBuffer(t *testing.T) {
	t.Parallel()
	buf, err := secmem.NewBuffer(bytes.Repeat([]byte{0x42}, curve25519.ScalarSize))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	k, err := NewX25519Key(buf) // k owns buf; buf ref retained only to seal it
	if err != nil {
		t.Fatalf("NewX25519Key: %v", err)
	}
	defer k.Destroy()

	pub, err := k.PublicKey() // capture a valid peer point while live
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := k.PublicKey(); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("sealed PublicKey: error = %v, want ErrSealed", err)
	}
	if _, err := k.SharedSecret(pub); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("sealed SharedSecret: error = %v, want ErrSealed", err)
	}
	if err := k.WithScalar(func([]byte) error { return nil }); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("sealed WithScalar: error = %v, want ErrSealed", err)
	}
	if k.ConstantTimeEqual(k) {
		t.Error("ConstantTimeEqual on a sealed key returned true, want false")
	}

	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if _, err := k.PublicKey(); err != nil {
		t.Errorf("PublicKey after Unseal failed: %v", err)
	}
	if !k.ConstantTimeEqual(k) {
		t.Error("ConstantTimeEqual on a live key (self) returned false, want true")
	}
}

// TestMLKEM768_SealedBuffer does the same for MLKEM768Key, including
// NewMLKEM768Key on a sealed buffer (which reads the seed to validate it).
func TestMLKEM768_SealedBuffer(t *testing.T) {
	t.Parallel()
	buf, err := secmem.NewEmptyBuffer(mlkem.SeedSize) // all-zero is a valid seed
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	k, err := NewMLKEM768Key(buf)
	if err != nil {
		t.Fatalf("NewMLKEM768Key: %v", err)
	}
	defer k.Destroy()

	ekBytes, err := k.EncapsulationKeyBytes()
	if err != nil {
		t.Fatalf("EncapsulationKeyBytes: %v", err)
	}
	ct, ss, err := Encapsulate(ekBytes) // a valid ciphertext to try decapsulating
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	ss.Destroy()

	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := k.EncapsulationKeyBytes(); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("sealed EncapsulationKeyBytes: error = %v, want ErrSealed", err)
	}
	if _, err := k.Decapsulate(ct); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("sealed Decapsulate: error = %v, want ErrSealed", err)
	}
	if err := k.WithSeed(func([]byte) error { return nil }); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("sealed WithSeed: error = %v, want ErrSealed", err)
	}

	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if _, err := k.EncapsulationKeyBytes(); err != nil {
		t.Errorf("EncapsulationKeyBytes after Unseal failed: %v", err)
	}
}

func TestNewMLKEM768Key_SealedBuffer(t *testing.T) {
	t.Parallel()
	buf, err := secmem.NewEmptyBuffer(mlkem.SeedSize)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer buf.Destroy()
	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// NewMLKEM768Key reads the seed to validate expansion, so a sealed buffer
	// must fail with ErrSealed and not transfer ownership.
	if _, err := NewMLKEM768Key(buf); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("NewMLKEM768Key(sealed): error = %v, want ErrSealed", err)
	}
	if buf.IsDestroyed() {
		t.Error("ownership transferred on failure")
	}
}

func TestOpenInto_SealedOutputBuffer(t *testing.T) {
	t.Parallel()
	gcm := newGCM(t)
	nonce := make([]byte, gcm.NonceSize())
	ct := gcm.Seal(nil, nonce, []byte("sealed target"), nil)

	out, err := secmem.NewEmptyBuffer(len("sealed target"))
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()
	if err := out.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := OpenInto(out, gcm, nonce, ct, nil); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("OpenInto(sealed out): error = %v, want ErrSealed", err)
	}
}

func TestSealFrom_SealedPlaintextBuffer(t *testing.T) {
	t.Parallel()
	gcm := newGCM(t)
	nonce := make([]byte, gcm.NonceSize())

	pt, err := secmem.NewBuffer([]byte("sealed secret"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer pt.Destroy()
	if err := pt.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := SealFrom(nil, gcm, nonce, pt, nil); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("SealFrom(sealed plaintext): error = %v, want ErrSealed", err)
	}
}
