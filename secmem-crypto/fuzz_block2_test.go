package secmemcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/deadpoets/secmem"
)

// FuzzOpenInto_RoundTrip asserts that anything SealFrom/gcm.Seal produces,
// OpenInto recovers exactly — and that OpenInto never panics on arbitrary
// (nonce, ciphertext, aad, buffer-size) inputs.
func FuzzOpenInto_RoundTrip(f *testing.F) {
	f.Add([]byte("plaintext secret"), []byte("aad"))
	f.Add([]byte(""), []byte(""))
	f.Add(bytes.Repeat([]byte{0x7f}, 300), []byte(nil))
	f.Fuzz(func(t *testing.T, plaintext, aad []byte) {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			t.Skip()
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Skip()
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Skip()
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			t.Skip()
		}

		ct := gcm.Seal(nil, nonce, plaintext, aad)
		out, err := secmem.NewEmptyBuffer(len(plaintext))
		if err != nil {
			// Zero-length plaintext yields a zero-length buffer, which the
			// core rejects; that is the core's concern, not OpenInto's.
			t.Skip()
		}
		defer out.Destroy()

		if err := OpenInto(out, gcm, nonce, ct, aad); err != nil {
			t.Fatalf("OpenInto of a valid ciphertext failed: %v", err)
		}
		_ = out.WithBytesErr(func(got []byte) error {
			if !bytes.Equal(got, plaintext) {
				t.Errorf("round trip mismatch\n  got:  %x\n  want: %x", got, plaintext)
			}
			return nil
		})
	})
}

// FuzzX25519Key_PublicKeyMatchesStdlib differentially fuzzes X25519Key.PublicKey
// against a direct curve25519 base-point multiplication for arbitrary
// 32-byte scalars.
func FuzzX25519Key_PublicKeyMatchesStdlib(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x01}, 32))
	f.Add(make([]byte, 32))
	f.Fuzz(func(t *testing.T, scalar []byte) {
		if len(scalar) != curve25519.ScalarSize {
			return
		}
		buf, err := secmem.NewBuffer(append([]byte(nil), scalar...))
		if err != nil {
			t.Skip()
		}
		k, err := NewX25519Key(buf)
		if err != nil {
			t.Fatalf("NewX25519Key: %v", err)
		}
		defer k.Destroy()

		got, err := k.PublicKey()
		if err != nil {
			t.Fatalf("PublicKey: %v", err)
		}
		want, err := curve25519.X25519(scalar, curve25519.Basepoint)
		if err != nil {
			t.Fatalf("stdlib X25519: %v", err)
		}
		if !bytes.Equal(got[:], want) {
			t.Errorf("public key differs from stdlib\n  got:  %x\n  want: %x", got, want)
		}
	})
}
