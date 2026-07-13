package secmemcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/deadpoets/secmem"
)

func newGCM(t testing.TB) cipher.AEAD {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	return gcm
}

func TestOpenInto_RoundTrip(t *testing.T) {
	t.Parallel()
	gcm := newGCM(t)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	plaintext := []byte("the secret that must land only in protected memory")
	aad := []byte("associated data")
	ct := gcm.Seal(nil, nonce, plaintext, aad)

	out, err := secmem.NewEmptyBuffer(len(plaintext))
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()

	if err := OpenInto(out, gcm, nonce, ct, aad); err != nil {
		t.Fatalf("OpenInto: %v", err)
	}
	if err := out.WithBytesErr(func(got []byte) error {
		if !bytes.Equal(got, plaintext) {
			t.Errorf("plaintext mismatch\n  got:  %q\n  want: %q", got, plaintext)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytesErr: %v", err)
	}
}

// TestOpenInto_TamperedCiphertextLeavesBufferZeroed is the security-critical
// property: an authentication failure must not leave plaintext (or partial
// plaintext) in the output buffer.
func TestOpenInto_TamperedCiphertextLeavesBufferZeroed(t *testing.T) {
	t.Parallel()
	gcm := newGCM(t)
	nonce := make([]byte, gcm.NonceSize())
	plaintext := bytes.Repeat([]byte{0xAB}, 64)
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	ct[0] ^= 0xFF // tamper

	out, err := secmem.NewEmptyBuffer(len(plaintext))
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()

	err = OpenInto(out, gcm, nonce, ct, nil)
	if err == nil {
		t.Fatal("expected authentication failure for tampered ciphertext")
	}
	if err := out.WithBytesErr(func(got []byte) error {
		if !bytes.Equal(got, make([]byte, len(plaintext))) {
			t.Errorf("buffer not zeroed after auth failure: %x", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytesErr: %v", err)
	}
}

// TestOpenInto_RejectsWrongSizedBuffer pins the guard that prevents a silent
// heap allocation of plaintext: the output buffer must be exactly the
// plaintext length.
func TestOpenInto_RejectsWrongSizedBuffer(t *testing.T) {
	t.Parallel()
	gcm := newGCM(t)
	nonce := make([]byte, gcm.NonceSize())
	plaintext := []byte("sixteen-byte pt!")
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	// Undersized would force plaintext onto the heap; oversized would leave
	// stale bytes past the plaintext. Both must be refused.
	for _, size := range []int{len(plaintext) - 1, len(plaintext) + 1} {
		out, err := secmem.NewEmptyBuffer(size)
		if err != nil {
			t.Fatalf("NewEmptyBuffer(%d): %v", size, err)
		}
		if err := OpenInto(out, gcm, nonce, ct, nil); err == nil {
			t.Errorf("size %d: expected error for mismatched buffer size", size)
		}
		out.Destroy()
	}
}

func TestOpenInto_BadInputs(t *testing.T) {
	t.Parallel()
	gcm := newGCM(t)
	out, err := secmem.NewEmptyBuffer(16)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()
	goodNonce := make([]byte, gcm.NonceSize())
	ct := gcm.Seal(nil, goodNonce, make([]byte, 16), nil)

	if err := OpenInto(nil, gcm, goodNonce, ct, nil); err == nil {
		t.Error("expected error for nil aead")
	}
	if err := OpenInto(out, nil, goodNonce, ct, nil); err == nil {
		t.Error("expected error for nil buffer")
	}
	if err := OpenInto(out, gcm, make([]byte, gcm.NonceSize()+1), ct, nil); err == nil {
		t.Error("expected error for wrong nonce size (must not panic)")
	}
	if err := OpenInto(out, gcm, goodNonce, make([]byte, gcm.Overhead()-1), nil); err == nil {
		t.Error("expected error for ciphertext shorter than overhead")
	}

	destroyed, _ := secmem.NewEmptyBuffer(16)
	_ = destroyed.Destroy()
	if err := OpenInto(destroyed, gcm, goodNonce, ct, nil); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("destroyed buffer: error = %v, want wrap of ErrDestroyed", err)
	}
}

func TestSealFrom_RoundTripWithOpenInto(t *testing.T) {
	t.Parallel()
	gcm := newGCM(t)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	secret := []byte("a secret held in protected memory, sealed without exposure")
	aad := []byte("aad")

	pt, err := secmem.NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer pt.Destroy()

	ct, err := SealFrom(nil, gcm, nonce, pt, aad)
	if err != nil {
		t.Fatalf("SealFrom: %v", err)
	}

	// Decrypt it back with the standard library to prove interoperability.
	got, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		t.Fatalf("stdlib Open of SealFrom output: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("round trip mismatch\n  got:  %q\n  want: %q", got, secret)
	}

	// And round-trip fully through OpenInto.
	out, err := secmem.NewEmptyBuffer(len(secret))
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()
	if err := OpenInto(out, gcm, nonce, ct, aad); err != nil {
		t.Fatalf("OpenInto: %v", err)
	}
	if err := out.WithBytesErr(func(b []byte) error {
		if !bytes.Equal(b, secret) {
			t.Error("OpenInto of SealFrom output did not recover the secret")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytesErr: %v", err)
	}
}

func TestSealFrom_BadInputs(t *testing.T) {
	t.Parallel()
	gcm := newGCM(t)
	pt, err := secmem.NewBuffer([]byte("secret"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer pt.Destroy()
	goodNonce := make([]byte, gcm.NonceSize())

	if _, err := SealFrom(nil, nil, goodNonce, pt, nil); err == nil {
		t.Error("expected error for nil aead")
	}
	if _, err := SealFrom(nil, gcm, goodNonce, nil, nil); err == nil {
		t.Error("expected error for nil plaintext buffer")
	}
	if _, err := SealFrom(nil, gcm, make([]byte, gcm.NonceSize()+1), pt, nil); err == nil {
		t.Error("expected error for wrong nonce size (must not panic)")
	}

	destroyed, _ := secmem.NewBuffer([]byte("x"))
	_ = destroyed.Destroy()
	if _, err := SealFrom(nil, gcm, goodNonce, destroyed, nil); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("destroyed plaintext: error = %v, want wrap of ErrDestroyed", err)
	}
}
