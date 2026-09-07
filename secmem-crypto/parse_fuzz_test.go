package secmemcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// FuzzParsePrivateKey: no input may panic, hang, or leak a buffer, and any
// input that parses must yield a signer that is internally consistent — its
// signatures verify under its own Public(). The seeds are every container
// and key type the round-trip test uses, so the mutator starts from real
// structure.
func FuzzParsePrivateKey(f *testing.F) {
	for _, k := range parseTestKeys(f) {
		for _, enc := range encodings(f, k) {
			f.Add(enc.data)
		}
	}
	f.Add([]byte("-----BEGIN " + "PRIVATE KEY-----\nAAAA\n-----END " + "PRIVATE KEY-----\n")) // split: no literal armour in the source
	f.Add([]byte("openssh-key-v1\x00"))
	f.Add([]byte{0x30, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := ParsePrivateKey(data)
		if err != nil {
			if s != nil {
				t.Fatal("error with a non-nil signer")
			}
			return
		}
		defer s.Destroy()
		pub := s.Public()
		if pub == nil {
			t.Fatal("parsed signer has no public key")
		}
		msg := []byte("fuzz")
		switch p := pub.(type) {
		case ed25519.PublicKey:
			sig, err := s.Sign(nil, msg, nil)
			if err != nil || !ed25519.Verify(p, msg, sig) {
				t.Fatalf("ed25519 signer from parsed key is inconsistent: %v", err)
			}
		case *ecdsa.PublicKey:
			h := sha256.Sum256(msg)
			sig, err := s.Sign(rand.Reader, h[:], crypto.SHA256)
			if err != nil || !ecdsa.VerifyASN1(p, h[:], sig) {
				t.Fatalf("ecdsa signer from parsed key is inconsistent: %v", err)
			}
		case *rsa.PublicKey:
			h := sha256.Sum256(msg)
			sig, err := s.Sign(rand.Reader, h[:], crypto.SHA256)
			if err != nil || rsa.VerifyPKCS1v15(p, crypto.SHA256, h[:], sig) != nil {
				t.Fatalf("rsa signer from parsed key is inconsistent: %v", err)
			}
		default:
			t.Fatalf("unexpected public key type %T", pub)
		}
	})
}
