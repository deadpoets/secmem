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

// MLKEM768Key is an ML-KEM-768 (FIPS 203, the NIST post-quantum key
// encapsulation mechanism) decapsulation key whose 64-byte seed is held in
// a [secmem.SecureBuffer] between operations. The seed is the compact,
// regenerable secret; Decapsulate expands it into the full decapsulation
// key on demand and wipes that expansion before returning.
//
// Post-quantum posture: this hardens the at-rest custody of a KEM secret.
// The urgent PQ threat — "harvest now, decrypt later" against recorded
// traffic — is addressed at the transport layer (Go's crypto/tls already
// defaults to the X25519MLKEM768 hybrid key exchange); this type is for
// applications that hold a long-lived ML-KEM decapsulation secret and want
// it off the garbage-collected heap at rest.
//
// # What transits the heap, and for how long
//
// crypto/mlkem has no in-place API: every expansion allocates a heap
// DecapsulationKey768 which, in go1.26, stores the seed halves d and z
// verbatim ([32]byte each) and the secret polynomial vector s (about
// 1.5 KB) next to the public parts. That object is wiped by reflection
// through its unexported fields (mlkemwipe.go) at the end of every
// expansion — construction, and each Decapsulate — with a tripwire test
// pinning the layout and a call that fails closed, returning an error,
// when the layout is not the one it expects. So the seed and s are on the
// heap only for the duration of the call, and are zero afterwards.
//
// What no wipe here reaches, on every build: the SHA3/SHAKE digest states
// crypto/mlkem allocates during expansion (absorbing d) and during
// decapsulation (absorbing z and the recovered message), the 32-byte
// recovered message m, and the intermediate polynomials e and σ from key
// generation. All are allocated inside [secmem.ScrubErr], so on a
// GOEXPERIMENT=runtimesecret build the runtime erases them once they are
// unreachable; on any other build they are reclaimed by the collector,
// not zeroed. The shared key returned by crypto/mlkem is copied into a
// SecureBuffer and its heap copy wiped. The encapsulation key is public
// and is computed once at construction, so EncapsulationKeyBytes performs
// no expansion at all.
type MLKEM768Key struct {
	seedBuf *secmem.SecureBuffer
	ek      []byte // public encapsulation key, captured at construction
}

// GenerateMLKEM768Key generates a fresh 64-byte ML-KEM-768 seed directly
// into a new SecureBuffer using crypto/rand. With the default
// [crypto/rand.Reader] the seed is never materialized on the Go heap by the
// generation itself; see [GenerateEd25519Signer] for the caveat about a
// replaced Reader, and the type comment for the expansion that follows.
//
// To persist the generated key, use [MLKEM768Key.WithSeed].
func GenerateMLKEM768Key() (*MLKEM768Key, error) {
	buf, err := secmem.NewEmptyBuffer(mlkem.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: allocate seed buffer: %w", err)
	}
	if err := buf.WithBytesErr(func(seed []byte) error {
		_, e := io.ReadFull(rand.Reader, seed)
		return e
	}); err != nil {
		_ = buf.Destroy()
		return nil, fmt.Errorf("secmemcrypto: generate seed: %w", err)
	}
	k, err := NewMLKEM768Key(buf)
	if err != nil {
		_ = buf.Destroy()
		return nil, err
	}
	return k, nil
}

// NewMLKEM768Key wraps an existing 64-byte ML-KEM-768 seed already held in a
// SecureBuffer. The seed is expanded once, to validate it and to capture
// the public encapsulation key, and the expansion is wiped (see the type
// comment). On success, the MLKEM768Key owns seedBuf — call
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
		return nil, fmt.Errorf("%w: got %d, want %d", ErrBadSeedLength, n, mlkem.SeedSize)
	}
	var ek []byte
	err := secmem.ScrubErr(func() error {
		return seedBuf.WithBytesErr(func(seed []byte) (err error) {
			dk, e := mlkem.NewDecapsulationKey768(seed)
			if e != nil {
				return e
			}
			defer func() { err = errors.Join(err, wipeMLKEMDecapsulationKey(dk)) }()
			ek = dk.EncapsulationKey().Bytes() // public — not secret
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: new ML-KEM key: %w", err)
	}
	return &MLKEM768Key{seedBuf: seedBuf, ek: ek}, nil
}

// EncapsulationKeyBytes returns a copy of the 1184-byte public ML-KEM-768
// encapsulation key, which a peer uses to produce ciphertexts (see
// [Encapsulate]). It is not secret. It was computed once at construction,
// so — like [Ed25519Signer.Public] — it keeps working after Destroy and
// while the seed is sealed, and touches no secret material. Returns an
// error only on a nil receiver.
func (k *MLKEM768Key) EncapsulationKeyBytes() ([]byte, error) {
	if k == nil || k.ek == nil {
		return nil, fmt.Errorf("secmemcrypto: encapsulation key: %w", secmem.ErrDestroyed)
	}
	out := make([]byte, len(k.ek))
	copy(out, k.ek)
	return out, nil
}

// Decapsulate recovers the shared key from a ciphertext produced against
// this key's encapsulation key, returning it in a new SecureBuffer (the
// caller owns and must Destroy it). It errors if the ciphertext is invalid,
// or if this key is destroyed or sealed. The expansion and decapsulation
// run inside [secmem.ScrubErr], and the expanded key is wiped before
// return; an error wrapping the wipe's failure means the expansion could
// not be located and is still live on the heap.
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
		return k.seedBuf.WithBytesErr(func(seed []byte) (err error) {
			dk, e := mlkem.NewDecapsulationKey768(seed)
			if e != nil {
				return e
			}
			defer func() { err = errors.Join(err, wipeMLKEMDecapsulationKey(dk)) }()
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

// Encapsulate is the sender-side mirror of [MLKEM768Key.Decapsulate]:
// given a peer's 1184-byte encapsulation key (from their
// [MLKEM768Key.EncapsulationKeyBytes]), it produces a ciphertext to send to
// that peer and the freshly generated shared secret, returned in a new
// SecureBuffer (the caller owns and must Destroy it). The ciphertext is
// public; the shared secret is not.
//
// crypto/mlkem's Encapsulate returns the shared key as a plain heap []byte,
// so this copies it into protected memory and wipes the heap copy inside
// [secmem.ScrubErr]. What it cannot reach is crypto/mlkem's own working
// state — the SHA3 digest that produces the shared key and the encryption
// randomness, and the 32-byte message m — which is erased by the runtime
// on a runtimesecret build and left for the collector elsewhere. It does
// not require (and has no access to) a decapsulation key, which is why it
// is a free function rather than a method.
func Encapsulate(encapsulationKey []byte) (ciphertext []byte, sharedSecret *secmem.SecureBuffer, err error) {
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
// idempotent and nil-receiver safe. EncapsulationKeyBytes keeps working
// afterwards, since the encapsulation key is not secret.
func (k *MLKEM768Key) Destroy() error {
	if k == nil {
		return nil
	}
	return k.seedBuf.Destroy()
}
