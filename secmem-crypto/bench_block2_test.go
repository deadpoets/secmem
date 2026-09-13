package secmemcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"io"
	"testing"

	"github.com/deadpoets/secmem"
)

func benchGCM(b *testing.B) (cipher.AEAD, []byte) {
	b.Helper()
	key := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, key)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	return gcm, nonce
}

func BenchmarkOpenInto(b *testing.B) {
	gcm, nonce := benchGCM(b)
	plaintext := make([]byte, 1024)
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out, err := secmem.NewEmptyBuffer(len(plaintext))
	if err != nil {
		b.Fatal(err)
	}
	defer out.Destroy()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := OpenInto(out, gcm, nonce, ct, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkX25519KeySharedSecret(b *testing.B) {
	a, err := GenerateX25519Key()
	if err != nil {
		b.Fatal(err)
	}
	defer a.Destroy()
	peer, err := GenerateX25519Key()
	if err != nil {
		b.Fatal(err)
	}
	defer peer.Destroy()
	peerPub, _ := peer.PublicKey()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		shared, err := a.SharedSecret(peerPub)
		if err != nil {
			b.Fatal(err)
		}
		shared.Destroy()
	}
}

func BenchmarkMLKEM768Decapsulate(b *testing.B) {
	k, err := GenerateMLKEM768Key()
	if err != nil {
		b.Fatal(err)
	}
	defer k.Destroy()
	ekBytes, err := k.EncapsulationKeyBytes()
	if err != nil {
		b.Fatal(err)
	}
	ek, err := mlkem.NewEncapsulationKey768(ekBytes)
	if err != nil {
		b.Fatal(err)
	}
	_, ct := ek.Encapsulate()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		shared, err := k.Decapsulate(ct)
		if err != nil {
			b.Fatal(err)
		}
		shared.Destroy()
	}
}
