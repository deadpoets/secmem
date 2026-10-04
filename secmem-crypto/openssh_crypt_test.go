package secmemcrypto

import (
	"errors"
	"testing"

	"github.com/deadpoets/secmem"
)

// TestOpensshCrypt_RefusesEncryptionModes pins the two refusals in
// opensshCrypt that the public API cannot reach: marshalOpenSSH writes
// aes256-ctr only, so the CBC and chacha20-poly1305 branches are decrypt-only
// by construction, and a future writer that picked one of them up must find
// ErrUnsupportedKey rather than a mode this package never meant to write.
func TestOpensshCrypt_RefusesEncryptionModes(t *testing.T) {
	t.Parallel()
	salt := []byte("0123456789abcdef")
	for _, tc := range []struct {
		name string
		mode opensshCipher
	}{
		{"chacha20-poly1305", cipherChaCha20Poly1305},
		{"aes128-cbc", cipherAES128CBC},
		{"aes192-cbc", cipherAES192CBC},
		{"aes256-cbc", cipherAES256CBC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src, dst := make([]byte, 32), make([]byte, 32)
			err := opensshCrypt(nil, dst, src, nil, []byte(testPassphrase), salt, 1, tc.mode, false)
			if errors.Is(err, secmem.ErrNoSecureMemory) {
				t.Skipf("no secure memory on this host: %v", err)
			}
			if !errors.Is(err, ErrUnsupportedKey) {
				t.Fatalf("encrypting with %s: got %v, want ErrUnsupportedKey", tc.name, err)
			}
		})
	}
}
