// mlkem.go provides MLKEM768Key, a post-quantum ML-KEM-768 (FIPS 203)
// decapsulation key whose seed lives in a SecureBuffer.
package secmemcrypto

import (
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/deadpoets/secmem"
)

// ErrBadSeedSize is returned when an ML-KEM seed is not exactly
// [crypto/mlkem.SeedSize] (64) bytes.
var ErrBadSeedSize = errors.New("secmemcrypto: bad ML-KEM seed size")

// MLKEM768Key is an ML-KEM-768 (FIPS 203, the NIST post-quantum key
// encapsulation mechanism) decapsulation key whose 64-byte seed lives in a
// [secmem.SecureBuffer] for its entire lifetime. The seed is the compact,
// regenerable secret; each operation expands it into the full decapsulation
// key on demand and discards that expansion.
//
// Post-quantum posture: this hardens the at-rest custody of a KEM secret.
// The urgent PQ threat — "harvest now, decrypt later" against recorded
// traffic — is addressed at the transport layer (Go's crypto/tls already
// defaults to the X25519MLKEM768 hybrid key exchange); this type is for
// applications that hold a long-lived ML-KEM decapsulation secret and want
// it off the garbage-collected heap at rest.
//
// Honesty caveat: crypto/mlkem expands the seed into the full decapsulation
// key (via NewDecapsulationKey768) for each operation — an in-NTT-form
// struct holding roughly 1.6 KB of secret key material — and provides no way
// to wipe that expansion. It is transiently on the Go heap during
// EncapsulationKeyBytes and Decapsulate, then left for the garbage collector.
// This is the same un-wipeable dependency-transient the Argon2 and HKDF
// paths disclose in kdf.go — NOT the fully hardened at-rest custody of the
// Ed25519 [Signer] seed, which lives in a SecureBuffer and is never left for
// the GC. MLKEM768Key hardens the 64-byte seed at rest and minimizes the
// window; it does not claim the expanded key never touches the heap.
type MLKEM768Key struct {
	seedBuf *secmem.SecureBuffer
}

// GenerateMLKEM768Key generates a fresh 64-byte ML-KEM-768 seed directly
// into a new SecureBuffer using crypto/rand. With the default
// [crypto/rand.Reader] the seed is never materialized on the Go heap; see
// [GenerateEd25519Signer] for the caveat about a replaced Reader.
//
// To persist the generated key, use [MLKEM768Key.WithSeed].
func GenerateMLKEM768Key() (*MLKEM768Key, error) {
	buf, err := secmem.NewEmptyBuffer(mlkem.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: allocate seed buffer: %w", err)
	}
	// Validate the seed expands before returning — a random 64 bytes always
	// forms a valid "d || z" seed, but this keeps the guarantee explicit. The
	// expansion touches secret material, so it runs inside ScrubErr like every
	// other expansion path in this file.
	if err := secmem.ScrubErr(func() error {
		return buf.WithBytesErr(func(seed []byte) error {
			if _, e := io.ReadFull(rand.Reader, seed); e != nil {
				return e
			}
			_, e := mlkem.NewDecapsulationKey768(seed)
			return e
		})
	}); err != nil {
		_ = buf.Destroy()
		return nil, fmt.Errorf("secmemcrypto: generate seed: %w", err)
	}
	return &MLKEM768Key{seedBuf: buf}, nil
}

// NewMLKEM768Key wraps an existing 64-byte ML-KEM-768 seed already held in a
// SecureBuffer. On success, the MLKEM768Key owns seedBuf — call
// [MLKEM768Key.Destroy] to release it. On failure, ownership is not
// transferred.
func NewMLKEM768Key(seedBuf *secmem.SecureBuffer) (*MLKEM768Key, error) {
	if seedBuf == nil {
		return nil, errors.New("secmemcrypto: nil SecureBuffer")
	}
	if seedBuf.IsDestroyed() {
		return nil, fmt.Errorf("secmemcrypto: new ML-KEM key: %w", secmem.ErrDestroyed)
	}
	if n := seedBuf.Len(); n != mlkem.SeedSize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrBadSeedSize, n, mlkem.SeedSize)
	}
	// Reject a malformed seed up front; the expansion touches secret
	// material, so it runs inside ScrubErr.
	if err := secmem.ScrubErr(func() error {
		return seedBuf.WithBytesErr(func(seed []byte) error {
			_, e := mlkem.NewDecapsulationKey768(seed)
			return e
		})
	}); err != nil {
		return nil, fmt.Errorf("secmemcrypto: new ML-KEM key: %w", err)
	}
	return &MLKEM768Key{seedBuf: seedBuf}, nil
}

// EncapsulationKeyBytes returns the 1184-byte public ML-KEM-768
// encapsulation key, which a peer uses to produce ciphertexts (see
// [EncapsulateInto]). It is not secret. It is recomputed from the seed on
// each call, so it returns an error on a destroyed or sealed key; capture
// it while the key is live if you need it later.
func (k *MLKEM768Key) EncapsulationKeyBytes() ([]byte, error) {
	if k == nil || k.seedBuf == nil {
		return nil, fmt.Errorf("secmemcrypto: encapsulation key: %w", secmem.ErrDestroyed)
	}
	var ek []byte
	// The expansion touches secret material even though the output is public,
	// so it runs inside ScrubErr — matching Decapsulate and key32.PublicKey.
	err := secmem.ScrubErr(func() error {
		return k.seedBuf.WithBytesErr(func(seed []byte) error {
			dk, e := mlkem.NewDecapsulationKey768(seed)
			if e != nil {
				return e
			}
			ek = dk.EncapsulationKey().Bytes() // public — not secret
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: encapsulation key: %w", err)
	}
	return ek, nil
}

// Decapsulate recovers the shared key from a ciphertext produced against
// this key's encapsulation key, returning it in a new SecureBuffer (the
// caller owns and must Destroy it). It errors if the ciphertext is invalid,
// or if this key is destroyed or sealed. The expansion and decapsulation
// run inside [secmem.ScrubErr].
func (k *MLKEM768Key) Decapsulate(ciphertext []byte) (*secmem.SecureBuffer, error) {
	if k == nil || k.seedBuf == nil || k.seedBuf.IsDestroyed() {
		return nil, fmt.Errorf("secmemcrypto: decapsulate: %w", secmem.ErrDestroyed)
	}
	if k.seedBuf.IsSealed() {
		return nil, fmt.Errorf("secmemcrypto: decapsulate: %w", secmem.ErrSealed)
	}
	out, err := secmem.NewEmptyBuffer(mlkem.SharedKeySize)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: allocate shared key buffer: %w", err)
	}
	err = secmem.ScrubErr(func() error {
		return k.seedBuf.WithBytesErr(func(seed []byte) error {
			dk, e := mlkem.NewDecapsulationKey768(seed)
			if e != nil {
				return e
			}
			shared, e := dk.Decapsulate(ciphertext)
			if e != nil {
				return e
			}
			e = out.WithBytesErr(func(dst []byte) error {
				copy(dst, shared)
				return nil
			})
			secmem.SecureWipe(shared)
			return e
		})
	})
	if err != nil {
		_ = out.Destroy()
		return nil, fmt.Errorf("secmemcrypto: decapsulate: %w", err)
	}
	return out, nil
}

// EncapsulateInto is the sender-side mirror of [MLKEM768Key.Decapsulate]:
// given a peer's 1184-byte encapsulation key (from their
// [MLKEM768Key.EncapsulationKeyBytes]), it produces a ciphertext to send to
// that peer and the freshly generated shared secret, returned in a new
// SecureBuffer (the caller owns and must Destroy it). The ciphertext is
// public; the shared secret is not.
//
// crypto/mlkem's Encapsulate returns the shared key as a plain heap []byte,
// so EncapsulateInto copies it into protected memory and wipes the heap copy
// inside [secmem.ScrubErr] — closing, on the sending side, the same heap
// window Decapsulate closes on the receiving side. It does not require
// (and has no access to) a decapsulation key, which is why it is a free
// function rather than a method.
func EncapsulateInto(encapsulationKey []byte) (ciphertext []byte, sharedSecret *secmem.SecureBuffer, err error) {
	ek, err := mlkem.NewEncapsulationKey768(encapsulationKey)
	if err != nil {
		return nil, nil, fmt.Errorf("secmemcrypto: encapsulate: %w", err)
	}
	out, err := secmem.NewEmptyBuffer(mlkem.SharedKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("secmemcrypto: allocate shared key buffer: %w", err)
	}
	var ct []byte
	err = secmem.ScrubErr(func() error {
		shared, c := ek.Encapsulate()
		ct = c
		e := out.WithBytesErr(func(dst []byte) error {
			copy(dst, shared)
			return nil
		})
		secmem.SecureWipe(shared)
		return e
	})
	if err != nil {
		_ = out.Destroy()
		return nil, nil, fmt.Errorf("secmemcrypto: encapsulate: %w", err)
	}
	return ct, out, nil
}

// WithSeed borrows the 64-byte seed for the duration of fn — the deliberate
// egress point for persisting a generated key. The slice is valid ONLY
// inside fn and must not be retained. Returns an error wrapping
// [secmem.ErrDestroyed] or [secmem.ErrSealed] when the seed is no longer
// accessible.
func (k *MLKEM768Key) WithSeed(fn func(seed []byte) error) error {
	if k == nil || k.seedBuf == nil {
		return fmt.Errorf("secmemcrypto: with seed: %w", secmem.ErrDestroyed)
	}
	return k.seedBuf.WithBytesErr(fn)
}

// Destroy wipes and releases the underlying seed buffer. Destroy is
// idempotent and nil-receiver safe.
func (k *MLKEM768Key) Destroy() error {
	if k == nil {
		return nil
	}
	return k.seedBuf.Destroy()
}
