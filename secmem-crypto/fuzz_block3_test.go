package secmemcrypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/deadpoets/secmem"
)

// FuzzECDSASignDifferential feeds the same scalar and message to
// ECDSASigner and to a plain stdlib key, both in deterministic (RFC 6979)
// mode, and requires byte-identical signatures — any divergence introduced
// by the transient-materialization path shows up here.
func FuzzECDSASignDifferential(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x01}, 32), []byte("seed message"))
	f.Add(bytes.Repeat([]byte{0x7F}, 32), []byte(""))
	f.Fuzz(func(t *testing.T, scalar, msg []byte) {
		if len(scalar) != 32 {
			return
		}
		std, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
		if err != nil {
			return // out-of-range candidate; nothing to compare
		}

		cp := make([]byte, len(scalar))
		copy(cp, scalar)
		buf, err := secmem.NewBuffer(cp)
		if err != nil {
			t.Fatalf("NewBuffer: %v", err)
		}
		ours, err := NewECDSASigner(elliptic.P256(), buf)
		if err != nil {
			t.Fatalf("stdlib accepted the scalar but NewECDSASigner rejected it: %v", err)
		}
		defer ours.Destroy()

		digest := sha256.Sum256(msg)
		sigOurs, err := ours.Sign(nil, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("our Sign: %v", err)
		}
		sigStd, err := std.Sign(nil, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("stdlib Sign: %v", err)
		}
		if !bytes.Equal(sigOurs, sigStd) {
			t.Errorf("signatures diverge:\n ours:   %x\n stdlib: %x", sigOurs, sigStd)
		}
		if !ecdsa.VerifyASN1(ours.Public().(*ecdsa.PublicKey), digest[:], sigOurs) {
			t.Error("stdlib VerifyASN1 rejects the signature")
		}
	})
}

// FuzzRSASignDifferential signs the SHA-256 of arbitrary messages with the
// shared fixture through RSASigner and through the equivalent stdlib key;
// PKCS#1 v1.5 is deterministic, so the outputs must be byte-identical.
func FuzzRSASignDifferential(f *testing.F) {
	f.Add([]byte("seed message"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, msg []byte) {
		ours := testRSASigner(t)
		std := stdlibRSAKey(t)

		digest := sha256.Sum256(msg)
		sigOurs, err := ours.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("our Sign: %v", err)
		}
		sigStd, err := std.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("stdlib Sign: %v", err)
		}
		if !bytes.Equal(sigOurs, sigStd) {
			t.Error("signatures diverge from stdlib")
		}
		if err := rsa.VerifyPKCS1v15(ours.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], sigOurs); err != nil {
			t.Errorf("stdlib rejects the signature: %v", err)
		}
	})
}
