package secmemcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// The *Stdlib* benchmarks below are baselines: the delta against the
// corresponding ECDSASigner/RSASigner benchmark is the price of per-
// operation transient materialization (DER/scalar parse + public-key
// recomputation), which is disclosed in the type docs.

func BenchmarkECDSASignerSignP256(b *testing.B) {
	s, err := GenerateECDSASigner(elliptic.P256())
	if err != nil {
		b.Fatal(err)
	}
	defer s.Destroy()
	digest := sha256.Sum256([]byte("bench"))

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkECDSAStdlibSignP256(b *testing.B) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	digest := sha256.Sum256([]byte("bench"))

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := key.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRSASignerSign2048(b *testing.B) {
	s := testRSASigner(b)
	digest := sha256.Sum256([]byte("bench"))

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRSAStdlibSign2048(b *testing.B) {
	key := stdlibRSAKey(b)
	digest := sha256.Sum256([]byte("bench"))

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := key.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
			b.Fatal(err)
		}
	}
}
