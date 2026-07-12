package secmemcrypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/deadpoets/secmem"
)

// The direct-vs-stdlib pair is the regression tripwire proving the
// hand-rolled, wipe-disciplined signing path stays within sane overhead of
// crypto/ed25519. Allocation counts are themselves a security signal here —
// unexpected allocations in the sign path mean secret-adjacent material
// landing on the heap.

func BenchmarkSignEd25519Direct(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	seed := priv.Seed()
	msg := []byte("benchmark message for the direct RFC 8032 path")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := signEd25519Direct(seed, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignStdlib(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("benchmark message for stdlib ed25519.Sign")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = ed25519.Sign(priv, msg)
	}
}

func BenchmarkSignerSign(b *testing.B) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		b.Fatalf("GenerateEd25519Signer: %v", err)
	}
	defer signer.Destroy()
	msg := []byte("benchmark message through the SecureBuffer borrow")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := signer.Sign(nil, msg, crypto.Hash(0)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHKDFSHA256Into(b *testing.B) {
	out, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		b.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()
	secret := []byte("benchmark master key material")
	salt := []byte("benchmark salt")
	info := []byte("benchmark info")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := HKDFSHA256Into(secret, salt, info, out); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkArgon2IDKeyInto(b *testing.B) {
	out, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		b.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()
	// Small cost parameters: this benchmark tracks wrapper overhead and
	// allocations, not Argon2's intrinsic (deliberate) expense.
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := Argon2IDKeyInto([]byte("password"), []byte("somesalt"), 1, 64, 1, out); err != nil {
			b.Fatal(err)
		}
	}
}
