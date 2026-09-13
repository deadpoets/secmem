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
	k, err := GenerateMLKEM768Key(AllowHeapTransients())
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

	// Sender side: Encapsulate keeps the sender's shared secret hardened.
	ct, senderShared, err := Encapsulate(ekBytes)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
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

func TestEncapsulate_BadKey(t *testing.T) {
	t.Parallel()
	if _, _, err := Encapsulate(make([]byte, 10)); err == nil {
		t.Error("expected error for a malformed encapsulation key")
	}
}

// TestMLKEM768_DeterministicFromSeed pins that the same seed yields the same
// encapsulation key — the property WithSeed-based persistence relies on.
func TestMLKEM768_DeterministicFromSeed(t *testing.T) {
	t.Parallel()
	k, err := GenerateMLKEM768Key(AllowHeapTransients())
	if err != nil {
		t.Fatalf("GenerateMLKEM768Key: %v", err)
	}
	defer k.Destroy()

	ek1, err := k.EncapsulationKeyBytes()
	if err != nil {
		t.Fatalf("EncapsulationKeyBytes: %v", err)
	}

	persisted := make([]byte, mlkem.SeedSize)
	if err := k.WithSeed(func(s []byte) error {
		copy(persisted, s) //nolint:secmem-lint // test persists the seed to verify reload
		return nil
	}); err != nil {
		t.Fatalf("WithSeed: %v", err)
	}
	buf, err := secmem.NewBuffer(persisted)
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	restored, err := NewMLKEM768Key(buf, AllowHeapTransients())
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
	a, err := GenerateMLKEM768Key(AllowHeapTransients())
	if err != nil {
		t.Fatalf("GenerateMLKEM768Key: %v", err)
	}
	defer a.Destroy()
	b, err := GenerateMLKEM768Key(AllowHeapTransients())
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
	k, err := GenerateMLKEM768Key(AllowHeapTransients())
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
	if _, err := NewMLKEM768Key(nil, AllowHeapTransients()); err == nil {
		t.Error("expected error for nil buffer")
	}

	short, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer short.Destroy()
	_, err = NewMLKEM768Key(short, AllowHeapTransients())
	if !errors.Is(err, ErrBadSeedLength) {
		t.Errorf("wrong-size seed: error = %v, want wrap of ErrBadSeedLength", err)
	}
	if short.IsDestroyed() {
		t.Error("ownership transferred on failure")
	}

	destroyed, _ := secmem.NewEmptyBuffer(mlkem.SeedSize)
	_ = destroyed.Destroy()
	if _, err := NewMLKEM768Key(destroyed, AllowHeapTransients()); !errors.Is(err, secmem.ErrDestroyed) {
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

	live, err := GenerateMLKEM768Key(AllowHeapTransients())
	if err != nil {
		t.Fatalf("GenerateMLKEM768Key: %v", err)
	}
	before, err := live.EncapsulationKeyBytes()
	if err != nil {
		t.Fatalf("EncapsulationKeyBytes: %v", err)
	}
	_ = live.Destroy()
	// The encapsulation key is public and captured at construction, so it
	// survives Destroy like Ed25519Signer.Public — and does not re-expand.
	after, err := live.EncapsulationKeyBytes()
	if err != nil || !bytes.Equal(before, after) {
		t.Errorf("EncapsulationKeyBytes after Destroy = %v, want the cached key", err)
	}
	after[0] ^= 1
	if again, _ := live.EncapsulationKeyBytes(); !bytes.Equal(again, before) {
		t.Error("EncapsulationKeyBytes returned an alias of its cache")
	}
	if _, err := live.Decapsulate(make([]byte, mlkem.CiphertextSize768)); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("Decapsulate after Destroy error = %v", err)
	}
	if err := live.Destroy(); err != nil {
		t.Errorf("double Destroy not idempotent: %v", err)
	}
}

// TestEncapsulateInto_WipesToCapacity: crypto/mlkem returns the shared key as
// the first half of a slice whose second half recovers it, so the wipe must
// reach the slice's capacity — and must stop at its length when that range
// would reach into the ciphertext about to be returned. The residue test
// measures the first half end to end; this pins both halves of the rule.
func TestEncapsulateInto_WipesToCapacity(t *testing.T) {
	t.Parallel()
	check := func(name string, shared, ct []byte, wantShared, wantWiped, wantCT []byte) {
		t.Helper()
		_, ss, err := encapsulateInto(func() ([]byte, []byte, error) { return shared, ct, nil })
		if errors.Is(err, secmem.ErrNoSecureMemory) {
			t.Skipf("%s: %v", name, err)
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		defer ss.Destroy()
		if err := ss.WithBytesErr(func(b []byte) error {
			if !bytes.Equal(b, wantShared) {
				t.Errorf("%s: the buffer does not hold the shared key kem returned", name)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(wantWiped, make([]byte, len(wantWiped))) {
			t.Errorf("%s: %d bytes that should have been wiped hold %x", name, len(wantWiped), wantWiped)
		}
		if !bytes.Equal(ct, wantCT) {
			t.Errorf("%s: the ciphertext was modified: %x", name, ct)
		}
	}

	key := bytes.Repeat([]byte{0xA5}, 32)

	// The go1.26 shape: shared key and randomness in one 64-byte array, the
	// ciphertext elsewhere. All 64 bytes are wiped.
	g := append(bytes.Clone(key), bytes.Repeat([]byte{0x5A}, 32)...)
	ct := bytes.Repeat([]byte{0x3C}, 16)
	check("separate ciphertext", g[:32], ct, key, g, bytes.Clone(ct))

	// A ciphertext inside the shared key's capacity is returned intact; only
	// the shared key itself is wiped.
	a := append(bytes.Clone(key), bytes.Repeat([]byte{0x3C}, 64)...)
	check("overlapping ciphertext", a[:32], a[32:], key, a[:32], bytes.Repeat([]byte{0x3C}, 64))

	// A kem error surfaces, and nothing is returned.
	boom := errors.New("boom")
	if c, ss, err := encapsulateInto(func() ([]byte, []byte, error) { return nil, nil, boom }); !errors.Is(err, boom) || c != nil || ss != nil {
		t.Errorf("kem error: got (%v, %v, %v), want (nil, nil, boom)", c, ss, err)
	}
}
