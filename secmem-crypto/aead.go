// aead.go decrypts into and encrypts from a [secmem.SecureBuffer], so the
// plaintext of an AEAD operation never lands on the ordinary Go heap as an
// intermediate the caller has to remember to wipe.
package secmemcrypto

import (
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/deadpoets/secmem"
)

// OpenInto authenticates and decrypts ciphertext with aead, writing the
// plaintext DIRECTLY into out. The common `aead.Open(nil, ...)` idiom
// returns plaintext on the heap first and only then copies it into
// protected memory, leaving a plaintext copy the garbage collector zeroes
// whenever it feels like it; OpenInto closes that window by decrypting in
// place inside the locked buffer.
//
// out must be sized to exactly the plaintext length —
// len(ciphertext) - aead.Overhead(). A different size is an error, never a
// silent heap allocation: an undersized buffer would otherwise force the
// AEAD to allocate the plaintext on the heap (the very thing this avoids),
// and an oversized one would leave stale bytes past the plaintext.
//
// On any decryption failure OpenInto zeroes the output buffer before
// returning: the stdlib GCM and x/crypto ChaCha20Poly1305 AEADs already
// clear dst on authentication failure, but the cipher.AEAD contract does
// not require it, so OpenInto also does it itself — a tampered or corrupt
// ciphertext never leaves plaintext, or partial plaintext, in out for any
// AEAD. The in-place, no-heap-allocation decrypt holds for any AEAD that
// writes its output into the provided dst[:0] (true of the stdlib and
// x/crypto AEADs). The decryption runs inside [secmem.ScrubErr] so
// block-cipher residue on the stack/registers is erased on
// GOEXPERIMENT=runtimesecret builds.
func OpenInto(out *secmem.SecureBuffer, aead cipher.AEAD, nonce, ciphertext, additionalData []byte) error {
	if aead == nil {
		return errors.New("secmemcrypto: open: nil aead")
	}
	if out == nil {
		return errors.New("secmemcrypto: open: nil output buffer")
	}
	if out.IsDestroyed() {
		return fmt.Errorf("secmemcrypto: open: %w", secmem.ErrDestroyed)
	}
	if len(nonce) != aead.NonceSize() {
		return fmt.Errorf("secmemcrypto: open: nonce length %d, want %d", len(nonce), aead.NonceSize())
	}
	if len(ciphertext) < aead.Overhead() {
		return fmt.Errorf("secmemcrypto: open: ciphertext (%d bytes) shorter than the AEAD overhead (%d bytes)", len(ciphertext), aead.Overhead())
	}
	ptLen := len(ciphertext) - aead.Overhead()
	if n := out.Len(); n != ptLen {
		return fmt.Errorf("secmemcrypto: open: output buffer is %d bytes, want exactly %d (the plaintext length) — a mismatched size would force plaintext onto the heap", n, ptLen)
	}

	err := secmem.ScrubErr(func() error {
		return out.WithBytesErr(func(dst []byte) error {
			// dst has len == cap == ptLen, so dst[:0] gives the AEAD a
			// zero-length slice with exactly ptLen capacity: it writes the
			// plaintext in place with no heap allocation (verified against
			// the stdlib gcm sliceForAppend fast path).
			_, oerr := aead.Open(dst[:0], nonce, ciphertext, additionalData)
			if oerr != nil {
				// Guarantee no unauthenticated plaintext survives, even for
				// an AEAD that overwrites-but-does-not-zero dst on failure.
				secmem.SecureWipe(dst)
			}
			return oerr
		})
	})
	if err != nil {
		return fmt.Errorf("secmemcrypto: open: %w", err)
	}
	return nil
}

// SealFrom encrypts and authenticates the plaintext held in the SecureBuffer
// with aead, appending the sealed ciphertext to dst and returning the
// extended slice — the mirror of [OpenInto] for a secret that lives in
// protected memory and must be encrypted without first being copied out to
// a plain []byte. The returned ciphertext is not secret and lives on the
// ordinary heap.
//
// The plaintext is read inside [secmem.ScrubErr]; pass dst as nil (or a
// slice with spare capacity) exactly as you would to cipher.AEAD.Seal.
func SealFrom(dst []byte, aead cipher.AEAD, nonce []byte, plaintext *secmem.SecureBuffer, additionalData []byte) ([]byte, error) {
	if aead == nil {
		return nil, errors.New("secmemcrypto: seal: nil aead")
	}
	if plaintext == nil {
		return nil, errors.New("secmemcrypto: seal: nil plaintext buffer")
	}
	if plaintext.IsDestroyed() {
		return nil, fmt.Errorf("secmemcrypto: seal: %w", secmem.ErrDestroyed)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("secmemcrypto: seal: nonce length %d, want %d", len(nonce), aead.NonceSize())
	}

	var out []byte
	err := secmem.ScrubErr(func() error {
		return plaintext.WithBytesErr(func(pt []byte) error {
			out = aead.Seal(dst, nonce, pt, additionalData)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: seal: %w", err)
	}
	return out, nil
}
