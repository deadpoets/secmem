package secmemcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/deadpoets/secmem"
)

// BenchmarkAESGCM compares sealing 1 KiB three ways: an AEAD built once and
// kept (the key schedule on the heap for its whole life), one built per call
// from a key borrowed out of a buffer and dropped (a schedule left for the
// collector each time), and WithAESGCM per call (built, used, wiped).
func BenchmarkAESGCM(b *testing.B) {
	keyBytes := make([]byte, 32)
	key, err := secmem.NewBuffer(append([]byte(nil), keyBytes...))
	if err != nil {
		b.Skipf("NewBuffer: %v", err)
	}
	defer key.Destroy()
	nonce, pt := make([]byte, 12), make([]byte, 1024)
	dst := make([]byte, 0, 1024+16)

	b.Run("kept", func(b *testing.B) {
		blk, _ := aes.NewCipher(keyBytes)
		g, _ := cipher.NewGCM(blk)
		for b.Loop() {
			_ = g.Seal(dst[:0], nonce, pt, nil)
		}
	})
	b.Run("per-call", func(b *testing.B) {
		for b.Loop() {
			_ = key.WithBytesErr(func(k []byte) error {
				blk, _ := aes.NewCipher(k) //nolint:secmem-lint // the unwiped per-call construction is the baseline being measured
				g, _ := cipher.NewGCM(blk)
				_ = g.Seal(dst[:0], nonce, pt, nil)
				return nil
			})
		}
	})
	b.Run("WithAESGCM", func(b *testing.B) {
		for b.Loop() {
			_ = WithAESGCM(key, func(g cipher.AEAD) error {
				_ = g.Seal(dst[:0], nonce, pt, nil)
				return nil
			})
		}
	})
}
