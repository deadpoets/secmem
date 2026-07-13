package secmemcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/deadpoets/secmem"
)

// TestECDSASigner_SealedBuffer verifies every ECDSASigner borrow path
// surfaces a clean errors.Is(ErrSealed) while the backing buffer is sealed,
// and recovers after Unseal — the block-1 sealed-regression standard.
func TestECDSASigner_SealedBuffer(t *testing.T) {
	t.Parallel()
	buf := scalarBufFromHex(t, elliptic.P256(),
		"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
	s, err := NewECDSASigner(elliptic.P256(), buf) // s owns buf; ref retained only to seal it
	if err != nil {
		t.Fatalf("NewECDSASigner: %v", err)
	}
	defer s.Destroy()

	pub := s.Public()
	digest := sha256.Sum256([]byte("sealed"))

	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("sealed Sign: error = %v, want ErrSealed", err)
	}
	if err := s.WithScalar(func([]byte) error { return nil }); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("sealed WithScalar: error = %v, want ErrSealed", err)
	}
	// The cached public key is not secret and stays available.
	if s.Public() == nil || !s.Equal(pub) {
		t.Error("cached public key should survive sealing")
	}

	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	sig, err := s.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign after Unseal: %v", err)
	}
	if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Error("signature after Unseal does not verify")
	}
}

func TestNewECDSASigner_SealedBuffer(t *testing.T) {
	t.Parallel()
	buf := scalarBufFromHex(t, elliptic.P256(),
		"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
	defer buf.Destroy()
	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// NewECDSASigner reads the scalar to validate it and derive the public
	// key, so a sealed buffer must fail with ErrSealed, without taking
	// ownership.
	if _, err := NewECDSASigner(elliptic.P256(), buf); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("NewECDSASigner(sealed): error = %v, want ErrSealed", err)
	}
	if buf.IsDestroyed() {
		t.Error("ownership transferred on failure")
	}
}

// TestRSASigner_SealedBuffer does the same for RSASigner.
func TestRSASigner_SealedBuffer(t *testing.T) {
	t.Parallel()
	buf := cloneRSADER(t)
	s, err := NewRSASigner(buf)
	if err != nil {
		t.Fatalf("NewRSASigner: %v", err)
	}
	defer s.Destroy()

	pub := s.Public()
	digest := sha256.Sum256([]byte("sealed"))

	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("sealed Sign: error = %v, want ErrSealed", err)
	}
	if err := s.WithDER(func([]byte) error { return nil }); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("sealed WithDER: error = %v, want ErrSealed", err)
	}
	if s.Public() == nil || !s.Equal(pub) {
		t.Error("cached public key should survive sealing")
	}

	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Errorf("Sign after Unseal failed: %v", err)
	}
}

func TestNewRSASigner_SealedBuffer(t *testing.T) {
	t.Parallel()
	buf := cloneRSADER(t)
	defer buf.Destroy()
	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := NewRSASigner(buf); !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("NewRSASigner(sealed): error = %v, want ErrSealed", err)
	}
	if buf.IsDestroyed() {
		t.Error("ownership transferred on failure")
	}
}
