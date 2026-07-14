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

// TestMLKEM768_AccumulatedKAT pins the wrapper's seed→encapsulation-key and
// decapsulation paths to the standard library's own FIPS 203 answers, rather
// than to mere encapsulate/decapsulate self-consistency.
//
// It reproduces crypto/mlkem's accumulation methodology (its TestAccumulated):
// a SHAKE128 stream drives 100 deterministic keygen / encapsulate /
// decapsulate rounds, and every produced value — the encapsulation key, the
// ciphertext, the encapsulated shared key, and the implicit-rejection key —
// is folded into a second SHAKE128. The pinned digest is crypto/mlkem's own
// regression value for that run (its testing.Short n=100 value), computed by
// the Go team over a pseudo-random stream — it is NOT a NIST-published ACVP
// vector. Matching it therefore proves byte-for-byte agreement with
// crypto/mlkem's ML-KEM-768 implementation, which is itself validated against
// NIST's vectors; that is conformance to the reference implementation, not an
// independent known-answer.
//
// The value that makes this worth having: the keygen and both decapsulation
// halves run through THIS package's [MLKEM768Key] (seed custody in a
// SecureBuffer), so a plumbing regression in the wrapper — wrong seed
// handling, truncation, byte order — would break the digest. It upgrades the
// wrapper's ML-KEM correctness from "inherited silently from crypto/mlkem" to
// "checked against it." Encapsulation is inherently the public-key holder's
// job and has no wrapper method; that half uses crypto/mlkem/mlkemtest's
// derandomized Encaps_internal (test-only) purely to make the run
// reproducible.
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
