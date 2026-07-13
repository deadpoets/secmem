package secmemcrypto

import (
	"bytes"
	"crypto/mlkem"
	"errors"
	"testing"

	"github.com/deadpoets/secmem"
)

// TestMLKEM768_RoundTrip is the functional correctness test: a peer
// encapsulates against the public key, and Decapsulate must recover the
// identical shared key. (ML-KEM's NIST KATs are ACVP-format and enormous;
// the encapsulate/decapsulate agreement is the property that matters and is
// what the wrapper is responsible for.)
func TestMLKEM768_RoundTrip(t *testing.T) {
	t.Parallel()
	k, err := GenerateMLKEM768Key()
	if err != nil {
		t.Fatalf("GenerateMLKEM768Key: %v", err)
	}
	defer k.Destroy()

	ekBytes, err := k.EncapsulationKeyBytes()
	if err != nil {
		t.Fatalf("EncapsulationKeyBytes: %v", err)
	}
	if len(ekBytes) != mlkem.EncapsulationKeySize768 {
		t.Fatalf("encapsulation key size = %d, want %d", len(ekBytes), mlkem.EncapsulationKeySize768)
	}

	// Sender side: EncapsulateInto keeps the sender's shared secret hardened.
	ct, senderShared, err := EncapsulateInto(ekBytes)
	if err != nil {
		t.Fatalf("EncapsulateInto: %v", err)
	}
	defer senderShared.Destroy()

	// Receiver side: Decapsulate must recover the identical shared secret.
	got, err := k.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	defer got.Destroy()

	if err := got.WithBytesErr(func(recv []byte) error {
		eq, err := senderShared.ConstantTimeEqual(recv)
		if err != nil {
			return err
		}
		if !eq {
			t.Error("sender and receiver ML-KEM shared secrets disagree")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytesErr: %v", err)
	}
}

func TestEncapsulateInto_BadKey(t *testing.T) {
	t.Parallel()
	if _, _, err := EncapsulateInto(make([]byte, 10)); err == nil {
		t.Error("expected error for a malformed encapsulation key")
	}
}

// TestMLKEM768_DeterministicFromSeed pins that the same seed yields the same
// encapsulation key — the property WithSeed-based persistence relies on.
func TestMLKEM768_DeterministicFromSeed(t *testing.T) {
	t.Parallel()
	k, err := GenerateMLKEM768Key()
	if err != nil {
		t.Fatalf("GenerateMLKEM768Key: %v", err)
	}
	defer k.Destroy()

	ek1, err := k.EncapsulationKeyBytes()
	if err != nil {
		t.Fatalf("EncapsulationKeyBytes: %v", err)
	}

	persisted := make([]byte, mlkem.SeedSize)
	if err := k.WithSeed(func(s []byte) error { copy(persisted, s); return nil }); err != nil {
		t.Fatalf("WithSeed: %v", err)
	}
	buf, err := secmem.NewBuffer(persisted)
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	restored, err := NewMLKEM768Key(buf)
	if err != nil {
		t.Fatalf("NewMLKEM768Key: %v", err)
	}
	defer restored.Destroy()

	ek2, err := restored.EncapsulationKeyBytes()
	if err != nil {
		t.Fatalf("EncapsulationKeyBytes (restored): %v", err)
	}
	if !bytes.Equal(ek1, ek2) {
		t.Error("same seed produced different encapsulation keys")
	}

	// The key restored from the persisted seed must decapsulate ciphertexts
	// made against the original's public key.
	ek, _ := mlkem.NewEncapsulationKey768(ek1)
	peerShared, ct := ek.Encapsulate()
	got, err := restored.Decapsulate(ct)
	if err != nil {
		t.Fatalf("restored Decapsulate: %v", err)
	}
	defer got.Destroy()
	_ = got.WithBytesErr(func(sk []byte) error {
		if !bytes.Equal(sk, peerShared) {
			t.Error("restored key did not recover the shared secret")
		}
		return nil
	})
}

func TestMLKEM768_DistinctKeys(t *testing.T) {
	t.Parallel()
	a, err := GenerateMLKEM768Key()
	if err != nil {
		t.Fatalf("GenerateMLKEM768Key: %v", err)
	}
	defer a.Destroy()
	b, err := GenerateMLKEM768Key()
	if err != nil {
		t.Fatalf("GenerateMLKEM768Key: %v", err)
	}
	defer b.Destroy()

	ekA, _ := a.EncapsulationKeyBytes()
	ekB, _ := b.EncapsulationKeyBytes()
	if bytes.Equal(ekA, ekB) {
		t.Error("two independently generated ML-KEM keys share an encapsulation key")
	}
}

func TestMLKEM768_Decapsulate_InvalidCiphertext(t *testing.T) {
	t.Parallel()
	k, err := GenerateMLKEM768Key()
	if err != nil {
		t.Fatalf("GenerateMLKEM768Key: %v", err)
	}
	defer k.Destroy()

	// Wrong-length ciphertext must error, not panic. (ML-KEM decapsulation
	// is designed not to fail on a well-formed-but-wrong ciphertext — it
	// returns an implicit-rejection key — so only a malformed one errors.)
	if _, err := k.Decapsulate(make([]byte, 10)); err == nil {
		t.Error("expected error for wrong-length ciphertext")
	}
}

func TestNewMLKEM768Key_BadInputs(t *testing.T) {
	t.Parallel()
	if _, err := NewMLKEM768Key(nil); err == nil {
		t.Error("expected error for nil buffer")
	}

	short, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer short.Destroy()
	_, err = NewMLKEM768Key(short)
	if !errors.Is(err, ErrBadSeedSize) {
		t.Errorf("wrong-size seed: error = %v, want wrap of ErrBadSeedSize", err)
	}
	if short.IsDestroyed() {
		t.Error("ownership transferred on failure")
	}

	destroyed, _ := secmem.NewEmptyBuffer(mlkem.SeedSize)
	_ = destroyed.Destroy()
	if _, err := NewMLKEM768Key(destroyed); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("destroyed buffer: error = %v, want wrap of ErrDestroyed", err)
	}
}

func TestMLKEM768_NilAndDestroyed(t *testing.T) {
	t.Parallel()
	var k *MLKEM768Key
	if _, err := k.EncapsulationKeyBytes(); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("nil.EncapsulationKeyBytes error = %v", err)
	}
	if _, err := k.Decapsulate(make([]byte, mlkem.CiphertextSize768)); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("nil.Decapsulate error = %v", err)
	}
	if err := k.WithSeed(func([]byte) error { return nil }); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("nil.WithSeed error = %v", err)
	}
	if err := k.Destroy(); err != nil {
		t.Errorf("nil.Destroy() = %v", err)
	}

	live, err := GenerateMLKEM768Key()
	if err != nil {
		t.Fatalf("GenerateMLKEM768Key: %v", err)
	}
	_ = live.Destroy()
	if _, err := live.EncapsulationKeyBytes(); err == nil {
		t.Error("EncapsulationKeyBytes after Destroy should error")
	}
	if err := live.Destroy(); err != nil {
		t.Errorf("double Destroy not idempotent: %v", err)
	}
}
