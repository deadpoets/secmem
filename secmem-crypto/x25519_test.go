package secmemcrypto

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/deadpoets/secmem"
)

// x25519KeyFromHex builds a X25519Key whose scalar is the given hex bytes.
func x25519KeyFromHex(t *testing.T, hexScalar string) *X25519Key {
	t.Helper()
	buf, err := secmem.NewBuffer(mustDecodeHex(t, hexScalar))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	k, err := NewX25519Key(buf)
	if err != nil {
		t.Fatalf("NewX25519Key: %v", err)
	}
	return k
}

// TestX25519Key_RFC7748PublicKey checks PublicKey against RFC 7748 §6.1's
// Alice/Bob key pairs — a spec vector, not a self-consistency check.
func TestX25519Key_RFC7748PublicKey(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, priv, pub string }{
		{"Alice", "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"},
		{"Bob", "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			k := x25519KeyFromHex(t, c.priv)
			defer k.Destroy()
			pub, err := k.PublicKey()
			if err != nil {
				t.Fatalf("PublicKey: %v", err)
			}
			want := mustDecodeHex(t, c.pub)
			if !bytes.Equal(pub[:], want) {
				t.Errorf("public key mismatch\n  got:  %x\n  want: %x", pub, want)
			}
		})
	}
}

// TestX25519Key_RFC7748SharedSecret checks the full DH agreement against RFC
// 7748 §6.1's expected shared secret K, both directions.
func TestX25519Key_RFC7748SharedSecret(t *testing.T) {
	t.Parallel()
	alice := x25519KeyFromHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	defer alice.Destroy()
	bob := x25519KeyFromHex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	defer bob.Destroy()
	wantK := mustDecodeHex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	alicePub, _ := alice.PublicKey()
	bobPub, _ := bob.PublicKey()

	for _, tc := range []struct {
		name string
		self *X25519Key
		peer [32]byte
	}{
		{"alice·bobPub", alice, bobPub},
		{"bob·alicePub", bob, alicePub},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Not t.Parallel(): alice/bob are owned by the parent and
			// released by its defer, which would fire before parallel
			// subtests run.
			shared, err := tc.self.SharedSecret(tc.peer)
			if err != nil {
				t.Fatalf("SharedSecret: %v", err)
			}
			defer shared.Destroy()
			if err := shared.WithBytesErr(func(k []byte) error {
				if !bytes.Equal(k, wantK) {
					t.Errorf("shared secret mismatch\n  got:  %x\n  want: %x", k, wantK)
				}
				return nil
			}); err != nil {
				t.Fatalf("WithBytesErr: %v", err)
			}
		})
	}
}

func TestX25519Key_GenerateAndAgree(t *testing.T) {
	t.Parallel()
	a, err := GenerateX25519Key()
	if err != nil {
		t.Fatalf("GenerateX25519Key: %v", err)
	}
	defer a.Destroy()
	b, err := GenerateX25519Key()
	if err != nil {
		t.Fatalf("GenerateX25519Key: %v", err)
	}
	defer b.Destroy()

	aPub, _ := a.PublicKey()
	bPub, _ := b.PublicKey()

	sa, err := a.SharedSecret(bPub)
	if err != nil {
		t.Fatalf("a.SharedSecret: %v", err)
	}
	defer sa.Destroy()
	sb, err := b.SharedSecret(aPub)
	if err != nil {
		t.Fatalf("b.SharedSecret: %v", err)
	}
	defer sb.Destroy()

	var kaBytes, kbBytes []byte
	_ = sa.WithBytesErr(func(p []byte) error { kaBytes = append([]byte(nil), p...); return nil }) //nolint:secmem-lint // test extracts the shared secret to compare the two derivations
	_ = sb.WithBytesErr(func(p []byte) error { kbBytes = append([]byte(nil), p...); return nil }) //nolint:secmem-lint // test extracts the shared secret to compare the two derivations
	if !bytes.Equal(kaBytes, kbBytes) {
		t.Error("independently derived shared secrets disagree")
	}
	if a.ConstantTimeEqual(b) {
		t.Error("two independently generated keys compared equal")
	}
}

func TestX25519Key_SharedSecret_LowOrderPointRejected(t *testing.T) {
	t.Parallel()
	k, err := GenerateX25519Key()
	if err != nil {
		t.Fatalf("GenerateX25519Key: %v", err)
	}
	defer k.Destroy()

	// All-zero point is low-order: X25519 yields an all-zero shared secret,
	// which must be rejected rather than used as key material.
	var zero [32]byte
	if _, err := k.SharedSecret(zero); err == nil {
		t.Error("expected error for a low-order peer public key")
	}
}

func TestNewX25519Key_BadInputs(t *testing.T) {
	t.Parallel()
	if _, err := NewX25519Key(nil); err == nil {
		t.Error("expected error for nil buffer")
	}

	short, err := secmem.NewEmptyBuffer(16)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer short.Destroy()
	_, err = NewX25519Key(short)
	if !errors.Is(err, ErrBadScalarLength) {
		t.Errorf("wrong-length scalar: error = %v, want wrap of ErrBadScalarLength", err)
	}
	if short.IsDestroyed() {
		t.Error("ownership transferred on failure")
	}

	destroyed, _ := secmem.NewEmptyBuffer(curve25519.ScalarSize)
	_ = destroyed.Destroy()
	if _, err := NewX25519Key(destroyed); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("destroyed buffer: error = %v, want wrap of ErrDestroyed", err)
	}
}

func TestX25519Key_WithScalar_Persist(t *testing.T) {
	t.Parallel()
	k, err := GenerateX25519Key()
	if err != nil {
		t.Fatalf("GenerateX25519Key: %v", err)
	}
	defer k.Destroy()

	persisted := make([]byte, curve25519.ScalarSize)
	if err := k.WithScalar(func(s []byte) error {
		copy(persisted, s) //nolint:secmem-lint // test persists the scalar to verify reload
		return nil
	}); err != nil {
		t.Fatalf("WithScalar: %v", err)
	}

	buf, err := secmem.NewBuffer(persisted)
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	restored, err := NewX25519Key(buf)
	if err != nil {
		t.Fatalf("NewX25519Key: %v", err)
	}
	defer restored.Destroy()
	if !restored.ConstantTimeEqual(k) {
		t.Error("key restored from WithScalar-persisted bytes is not equal")
	}
}

func TestX25519Key_NilAndDestroyed(t *testing.T) {
	t.Parallel()
	var k *X25519Key
	if _, err := k.PublicKey(); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("nil.PublicKey error = %v", err)
	}
	if _, err := k.SharedSecret([32]byte{}); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("nil.SharedSecret error = %v", err)
	}
	if err := k.WithScalar(func([]byte) error { return nil }); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("nil.WithScalar error = %v", err)
	}
	if k.ConstantTimeEqual(nil) {
		t.Error("nil.ConstantTimeEqual(nil) = true")
	}
	if err := k.Destroy(); err != nil {
		t.Errorf("nil.Destroy() = %v", err)
	}

	live, err := GenerateX25519Key()
	if err != nil {
		t.Fatalf("GenerateX25519Key: %v", err)
	}
	_ = live.Destroy()
	if _, err := live.PublicKey(); err == nil {
		t.Error("PublicKey after Destroy should error")
	}
	if err := live.Destroy(); err != nil {
		t.Errorf("double Destroy not idempotent: %v", err)
	}
}
