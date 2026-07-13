// x25519.go provides X25519Key, an X25519 Diffie-Hellman key whose private
// scalar lives in a SecureBuffer.
package secmemcrypto

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"

	"github.com/deadpoets/secmem"
)

// ErrBadScalarLength is returned when a raw private scalar does not have
// the exact length its algorithm requires: 32 bytes for X25519 ([X25519Key]),
// or the curve's fixed encoding size for ECDSA ([ECDSASigner] — 28/32/48/66
// bytes for P-224/P-256/P-384/P-521).
var ErrBadScalarLength = errors.New("secmemcrypto: bad scalar length")

// X25519Key is an X25519 (Curve25519) Diffie-Hellman private key whose 32-byte
// scalar lives in a [secmem.SecureBuffer] for its entire lifetime — read
// only inside a borrowing closure during PublicKey and SharedSecret, never
// copied to a plain heap-backed key.
//
// Honesty caveat: golang.org/x/crypto/curve25519 operates on plain []byte.
// Computing a public key or shared secret copies the scalar into
// curve25519's (and crypto/ecdh's) own internal arrays, and the shared
// secret is first produced as a heap []byte inside crypto/ecdh before X25519Key
// copies it into a hardened buffer and wipes the copy it can reach — the
// intermediate copies inside the dependency it cannot. Both PublicKey and
// SharedSecret run inside [secmem.ScrubErr], which erases that residue on
// GOEXPERIMENT=runtimesecret builds and otherwise leaves it for the garbage
// collector (reclaimed, not explicitly zeroed) — the same window kdf.go
// discloses for its derivations. X25519Key hardens the scalar at rest and
// minimizes the window; it does not claim the multiply runs entirely inside
// locked memory. The computed shared secret IS returned in a hardened buffer.
type X25519Key struct {
	scalarBuf *secmem.SecureBuffer
}

// GenerateX25519Key generates a fresh X25519 scalar directly into a new
// SecureBuffer using crypto/rand. With the default [crypto/rand.Reader]
// the scalar is never materialized on the Go heap; see
// [GenerateEd25519Signer] for the caveat about a replaced Reader.
//
// To persist the generated key, use [X25519Key.WithScalar].
func GenerateX25519Key() (*X25519Key, error) {
	buf, err := secmem.NewEmptyBuffer(curve25519.ScalarSize)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: allocate scalar buffer: %w", err)
	}
	if err := buf.WithBytesErr(func(scalar []byte) error {
		_, e := io.ReadFull(rand.Reader, scalar)
		return e
	}); err != nil {
		_ = buf.Destroy()
		return nil, fmt.Errorf("secmemcrypto: generate scalar: %w", err)
	}
	return &X25519Key{scalarBuf: buf}, nil
}

// NewX25519Key wraps an existing 32-byte X25519 scalar already held in a
// SecureBuffer. On success, the X25519Key owns scalarBuf — call [X25519Key.Destroy]
// to release it. On failure, ownership is not transferred.
//
// The scalar is stored as given; X25519 clamps it per RFC 7748 at each use,
// so an unclamped scalar is accepted and behaves identically to its clamped
// form for PublicKey/SharedSecret.
func NewX25519Key(scalarBuf *secmem.SecureBuffer) (*X25519Key, error) {
	if scalarBuf == nil {
		return nil, errors.New("secmemcrypto: nil SecureBuffer")
	}
	if scalarBuf.IsDestroyed() {
		return nil, fmt.Errorf("secmemcrypto: new x25519 key: %w", secmem.ErrDestroyed)
	}
	if n := scalarBuf.Len(); n != curve25519.ScalarSize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrBadScalarLength, n, curve25519.ScalarSize)
	}
	return &X25519Key{scalarBuf: scalarBuf}, nil
}

// PublicKey returns the X25519 public key (scalar × basepoint). The public
// key is not secret. It is recomputed from the scalar on each call, so —
// unlike a cached [Ed25519Signer.Public] — it returns an error on a destroyed or
// sealed key; capture it while the key is live if you need it later.
func (k *X25519Key) PublicKey() ([32]byte, error) {
	if k == nil || k.scalarBuf == nil {
		return [32]byte{}, fmt.Errorf("secmemcrypto: public key: %w", secmem.ErrDestroyed)
	}
	var pub [32]byte
	err := secmem.ScrubErr(func() error {
		return k.scalarBuf.WithBytesErr(func(scalar []byte) error {
			out, e := curve25519.X25519(scalar, curve25519.Basepoint)
			if e != nil {
				return e
			}
			copy(pub[:], out) // out is the public key — not secret
			return nil
		})
	})
	if err != nil {
		return [32]byte{}, fmt.Errorf("secmemcrypto: public key: %w", err)
	}
	return pub, nil
}

// SharedSecret computes the X25519 shared secret with peerPub and returns it
// in a new SecureBuffer (the caller owns and must Destroy it). It errors if
// peerPub is a low-order point — X25519 would yield an all-zero shared
// secret, which must never be used as key material — or if this key is
// destroyed or sealed.
func (k *X25519Key) SharedSecret(peerPub [32]byte) (*secmem.SecureBuffer, error) {
	if k == nil || k.scalarBuf == nil || k.scalarBuf.IsDestroyed() {
		return nil, fmt.Errorf("secmemcrypto: shared secret: %w", secmem.ErrDestroyed)
	}
	if k.scalarBuf.IsSealed() {
		return nil, fmt.Errorf("secmemcrypto: shared secret: %w", secmem.ErrSealed)
	}
	out, err := secmem.NewEmptyBuffer(curve25519.PointSize)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: allocate shared secret buffer: %w", err)
	}
	err = secmem.ScrubErr(func() error {
		return k.scalarBuf.WithBytesErr(func(scalar []byte) error {
			shared, e := curve25519.X25519(scalar, peerPub[:])
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
		return nil, fmt.Errorf("secmemcrypto: shared secret: %w", err)
	}
	return out, nil
}

// WithScalar borrows the 32-byte scalar for the duration of fn — the
// deliberate egress point for persisting a generated key. The slice is
// valid ONLY inside fn and must not be retained; any copy fn makes leaves
// secmem's protection and becomes the caller's responsibility. Returns an
// error wrapping [secmem.ErrDestroyed] or [secmem.ErrSealed] when the
// scalar is no longer accessible.
func (k *X25519Key) WithScalar(fn func(scalar []byte) error) error {
	if k == nil || k.scalarBuf == nil {
		return fmt.Errorf("secmemcrypto: with scalar: %w", secmem.ErrDestroyed)
	}
	return k.scalarBuf.WithBytesErr(fn)
}

// ConstantTimeEqual reports, in constant time, whether k and other hold the same
// scalar. Returns false if either key is nil, destroyed, or sealed.
func (k *X25519Key) ConstantTimeEqual(other *X25519Key) bool {
	if k == nil || other == nil || k.scalarBuf == nil || other.scalarBuf == nil {
		return false
	}
	if k.scalarBuf == other.scalarBuf {
		// Same backing buffer — equal by identity, which also avoids a
		// re-entrant read lock. A destroyed or sealed buffer is not "equal",
		// matching the distinct-key path below (where those states surface as
		// ErrDestroyed/ErrSealed and yield false).
		return !k.scalarBuf.IsDestroyed() && !k.scalarBuf.IsSealed()
	}
	var equal bool
	err := k.scalarBuf.WithBytesErr(func(a []byte) error {
		return other.scalarBuf.WithBytesErr(func(b []byte) error {
			equal = subtle.ConstantTimeCompare(a, b) == 1
			return nil
		})
	})
	return err == nil && equal
}

// Destroy wipes and releases the underlying scalar buffer. Destroy is
// idempotent and nil-receiver safe.
func (k *X25519Key) Destroy() error {
	if k == nil {
		return nil
	}
	return k.scalarBuf.Destroy()
}
