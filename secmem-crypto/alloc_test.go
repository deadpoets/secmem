//go:build !race

// Allocation counts are only meaningful without the race detector's
// instrumentation, so this gate is excluded under -race. The non-race CI job
// (test-386-linux) executes it.

package secmemcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"

	"github.com/deadpoets/secmem"
)

// TestNoHeapEscape_OpenInto enforces the load-bearing claim behind OpenInto:
// the decrypted plaintext lands directly in the SecureBuffer with no heap
// intermediate the GC would hold. It is the one AEAD path where a stray
// allocation would mean a plaintext secret escaping to the ordinary heap, so
// "0 allocs" is an invariant, not a nice-to-have — testing.AllocsPerRun makes
// CI enforce it.
func TestNoHeapEscape_OpenInto(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("read key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("read nonce: %v", err)
	}
	plaintext := make([]byte, 1024)
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	out, err := secmem.NewEmptyBuffer(len(plaintext))
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()

	// Confirm it actually decrypts before trusting the measurement.
	if err := OpenInto(out, gcm, nonce, ct, nil); err != nil {
		t.Fatalf("OpenInto: %v", err)
	}

	got := testing.AllocsPerRun(200, func() {
		_ = OpenInto(out, gcm, nonce, ct, nil)
	})
	if got > 0 {
		t.Errorf("OpenInto: %.1f allocs/op, want 0 — the decrypted plaintext must not touch the Go heap", got)
	}
}
