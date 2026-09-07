package secmemcrypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/deadpoets/secmem"
)

// allocatingAEAD is a deliberately nonconforming cipher.AEAD: Open ignores
// dst and returns the plaintext in a fresh heap allocation, the naive shape
// nothing in the cipher.AEAD contract prevents. It records the allocation so
// the test can check OpenInto wiped it.
type allocatingAEAD struct {
	cipher.AEAD
	returned []byte
}

func (a *allocatingAEAD) Open(_, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	pt, err := a.AEAD.Open(nil, nonce, ciphertext, additionalData)
	a.returned = pt
	return pt, err
}

// shortAEAD authenticates but writes nothing: it returns dst[:0] itself, so
// the slice aliases the buffer but carries no plaintext.
type shortAEAD struct{ cipher.AEAD }

func (a shortAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if _, err := a.AEAD.Open(nil, nonce, ciphertext, additionalData); err != nil {
		return nil, err
	}
	return dst[:0], nil
}

// TestOpenInto_RejectsAEADThatDoesNotWriteInPlace pins the fail-closed
// contract: an AEAD whose Open does not return the output buffer's own
// backing array must produce an error, a zeroed buffer, and a wiped stray
// copy — never a nil error over a buffer that was never written. Before the
// check, OpenInto discarded Open's return value and reported success here.
func TestOpenInto_RejectsAEADThatDoesNotWriteInPlace(t *testing.T) {
	t.Parallel()
	gcm := newGCM(t)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	plaintext := []byte("plaintext that must never be reported as delivered")
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	t.Run("allocates", func(t *testing.T) {
		t.Parallel()
		out, err := secmem.NewEmptyBuffer(len(plaintext))
		if err != nil {
			t.Skipf("NewEmptyBuffer: %v", err)
		}
		defer out.Destroy()

		bad := &allocatingAEAD{AEAD: gcm}
		err = OpenInto(out, bad, nonce, ct, nil)
		if err == nil {
			t.Fatal("OpenInto reported success for an AEAD that returned a fresh allocation instead of writing into the buffer")
		}
		if !strings.Contains(err.Error(), "did not decrypt in place") {
			t.Errorf("error does not name the violation: %v", err)
		}
		if err := out.WithBytesErr(func(got []byte) error {
			if !bytes.Equal(got, make([]byte, len(got))) {
				t.Errorf("buffer not zeroed after the violation: %x", got)
			}
			return nil
		}); err != nil {
			t.Fatalf("WithBytesErr: %v", err)
		}
		if len(bad.returned) != len(plaintext) {
			t.Fatalf("fake returned %d bytes, want %d", len(bad.returned), len(plaintext))
		}
		if !bytes.Equal(bad.returned, make([]byte, len(bad.returned))) {
			t.Errorf("stray heap plaintext not wiped: %q", bad.returned)
		}
	})

	t.Run("aliases but writes nothing", func(t *testing.T) {
		t.Parallel()
		out, err := secmem.NewEmptyBuffer(len(plaintext))
		if err != nil {
			t.Skipf("NewEmptyBuffer: %v", err)
		}
		defer out.Destroy()

		if err := OpenInto(out, shortAEAD{gcm}, nonce, ct, nil); err == nil {
			t.Fatal("OpenInto reported success for an AEAD that returned a zero-length slice for a non-empty plaintext")
		}
	})
}

// TestOpenInto_EmptyPlaintextConforming guards the ptLen == 0 edge of the
// in-place check: an authenticated empty message has no plaintext anywhere,
// and a conforming AEAD may return dst[:0], a nil slice, or any other empty
// slice for it. None of those is a violation. A zero-length buffer cannot
// be allocated directly (NewEmptyBuffer rejects size 0); Truncate(0) is the
// only way to reach one.
func TestOpenInto_EmptyPlaintextConforming(t *testing.T) {
	t.Parallel()
	gcm := newGCM(t)
	nonce := make([]byte, gcm.NonceSize())
	ct := gcm.Seal(nil, nonce, nil, []byte("aad only"))

	out, err := secmem.NewEmptyBuffer(1)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()
	if err := out.Truncate(0); err != nil {
		t.Fatalf("Truncate(0): %v", err)
	}

	if err := OpenInto(out, gcm, nonce, ct, []byte("aad only")); err != nil {
		t.Fatalf("OpenInto on an empty plaintext: %v", err)
	}
	// An allocating AEAD returns a non-nil empty slice here; still fine.
	if err := OpenInto(out, &allocatingAEAD{AEAD: gcm}, nonce, ct, []byte("aad only")); err != nil {
		t.Fatalf("OpenInto on an empty plaintext with a non-aliasing empty return: %v", err)
	}
}
