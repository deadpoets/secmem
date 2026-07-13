package secmemcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/sha3"
	"encoding/hex"
	"testing"

	"github.com/deadpoets/secmem"
)

func katHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestMLKEM768_AccumulatedKAT is a conformance known-answer test for the
// wrapper's seed→encapsulation-key and decapsulation paths against the
// FIPS 203 standard, not merely self-consistency.
//
// It reproduces the standard library's ML-KEM accumulation methodology
// (crypto/mlkem's TestAccumulated): a SHAKE128 stream drives 100 deterministic
// keygen / encapsulate / decapsulate rounds, and every produced value — the
// encapsulation key, the ciphertext, the encapsulated shared key, and the
// implicit-rejection key — is folded into a second SHAKE128 whose digest is
// compared to a pinned, NIST-anchored value. The full set of individual
// vectors is ~150 MB; the accumulated digest is how the reference and the
// standard library both check them compactly.
//
// The keygen and both decapsulation halves run through THIS package's
// [MLKEM768Key] (seed custody in a SecureBuffer), so matching the pinned
// digest proves the wrapper produces byte-for-byte the answers the standard
// mandates — upgrading ML-KEM conformance from "inherited silently from
// crypto/mlkem" to "checked here." The digest is the value crypto/mlkem
// validates ML-KEM-768 against at n=100 (its testing.Short vector); the
// encapsulation half uses crypto/mlkem/mlkemtest's derandomized
// Encaps_internal (test-only) so the run is reproducible.
func TestMLKEM768_AccumulatedKAT(t *testing.T) {
	const n = 100
	const expected = "1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415"

	s := sha3.NewSHAKE128() // deterministic input stream (empty absorb)
	o := sha3.NewSHAKE128() // output accumulator

	seed := make([]byte, mlkem.SeedSize)         // 64
	msg := make([]byte, 32)                      // encapsulation randomness
	ct1 := make([]byte, mlkem.CiphertextSize768) // 1088; a pseudo-random ciphertext

	for i := 0; i < n; i++ {
		if _, err := s.Read(seed); err != nil {
			t.Fatalf("s.Read(seed): %v", err)
		}

		// Keygen through the wrapper. NewBuffer wipes the copy it is handed.
		buf, err := secmem.NewBuffer(append([]byte(nil), seed...))
		if err != nil {
			t.Fatalf("NewBuffer: %v", err)
		}
		key, err := NewMLKEM768Key(buf)
		if err != nil {
			t.Fatalf("NewMLKEM768Key: %v", err)
		}
		ekBytes, err := key.EncapsulationKeyBytes()
		if err != nil {
			t.Fatalf("EncapsulationKeyBytes: %v", err)
		}
		o.Write(ekBytes)

		// Derandomized encapsulation (test-only stdlib helper) against the ek.
		if _, err := s.Read(msg); err != nil {
			t.Fatalf("s.Read(msg): %v", err)
		}
		ek, err := mlkem.NewEncapsulationKey768(ekBytes)
		if err != nil {
			t.Fatalf("NewEncapsulationKey768: %v", err)
		}
		sharedK, ct, err := mlkemtest.Encapsulate768(ek, msg)
		if err != nil {
			t.Fatalf("Encapsulate768: %v", err)
		}
		o.Write(ct)
		o.Write(sharedK)

		// Decapsulation through the wrapper must recover the same shared key.
		recovered, err := key.Decapsulate(ct)
		if err != nil {
			t.Fatalf("Decapsulate: %v", err)
		}
		if err := recovered.WithBytesErr(func(b []byte) error {
			if !bytes.Equal(b, sharedK) {
				t.Errorf("iter %d: decapsulated key disagrees with encapsulated", i)
			}
			return nil
		}); err != nil {
			t.Fatalf("WithBytesErr: %v", err)
		}
		recovered.Destroy()

		// Implicit-rejection path: a pseudo-random ciphertext decapsulates to
		// a deterministic, seed-derived key, also folded into the accumulator.
		if _, err := s.Read(ct1); err != nil {
			t.Fatalf("s.Read(ct1): %v", err)
		}
		rej, err := key.Decapsulate(ct1)
		if err != nil {
			t.Fatalf("Decapsulate(ct1): %v", err)
		}
		if err := rej.WithBytesErr(func(b []byte) error {
			o.Write(b)
			return nil
		}); err != nil {
			t.Fatalf("WithBytesErr(rej): %v", err)
		}
		rej.Destroy()

		key.Destroy()
	}

	// Public crypto/sha3.SHAKE has no Sum; reading 32 bytes squeezes the same
	// output the standard library's internal ShakeHash.Sum(nil) produces.
	out := make([]byte, 32)
	if _, err := o.Read(out); err != nil {
		t.Fatalf("o.Read: %v", err)
	}
	if got := hex.EncodeToString(out); got != expected {
		t.Errorf("accumulated ML-KEM-768 digest = %s, want %s (n=%d)", got, expected, n)
	}
}

// TestAEAD_AES256GCM_KAT threads a published AES-256-GCM known-answer vector
// (a GCM-specification / NIST test-set case, as carried in the Go standard
// library's crypto/cipher tests) through SealFrom and OpenInto, proving the
// wrapper preserves the AEAD contract byte-for-byte: encrypting the vector
// plaintext from a SecureBuffer yields exactly the vector ciphertext, and
// decrypting the vector ciphertext recovers the plaintext into a SecureBuffer.
func TestAEAD_AES256GCM_KAT(t *testing.T) {
	key := katHex(t, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	nonce := katHex(t, "54cc7dc2c37ec006bcc6d1da")
	plaintext := katHex(t, "007c5e5b3e59df24a7c355584fc1518d")
	wantCT := katHex(t, "d50b9e252b70945d4240d351677eb10f937cdaef6f2822b6a3191654ba41b197")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}

	// SealFrom: plaintext in a SecureBuffer must produce the exact vector CT.
	pt, err := secmem.NewBuffer(append([]byte(nil), plaintext...))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer pt.Destroy()
	gotCT, err := SealFrom(nil, gcm, nonce, pt, nil)
	if err != nil {
		t.Fatalf("SealFrom: %v", err)
	}
	if !bytes.Equal(gotCT, wantCT) {
		t.Errorf("SealFrom ciphertext = %x, want %x", gotCT, wantCT)
	}

	// OpenInto: the vector CT must decrypt back to the plaintext in a buffer.
	out, err := secmem.NewEmptyBuffer(len(plaintext))
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()
	if err := OpenInto(out, gcm, nonce, wantCT, nil); err != nil {
		t.Fatalf("OpenInto: %v", err)
	}
	if err := out.WithBytesErr(func(b []byte) error {
		if !bytes.Equal(b, plaintext) {
			t.Errorf("OpenInto plaintext = %x, want %x", b, plaintext)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytesErr: %v", err)
	}
}
