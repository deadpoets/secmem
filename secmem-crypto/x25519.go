// x25519.go provides X25519Key, an X25519 Diffie-Hellman key whose private
// scalar lives in a SecureBuffer.
package secmemcrypto

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/secmem-crypto/internal/x25519"
)

// ErrBadScalarLength is returned when a raw private scalar does not have
// the exact length its algorithm requires: 32 bytes for X25519 ([X25519Key]),
// or the curve's fixed encoding size for ECDSA ([ECDSASigner] — 28/32/48/66
// bytes for P-224/P-256/P-384/P-521).
var ErrBadScalarLength = errors.New("secmemcrypto: bad scalar length")

// errLowOrderPoint is returned by SharedSecret for a peer public key whose
// shared secret would be all zero.
var errLowOrderPoint = errors.New("bad input point: low order point")

// x25519Basepoint is the canonical base point, u = 9.
var x25519Basepoint = [x25519.PointSize]byte{9}

// X25519Key is an X25519 (Curve25519) Diffie-Hellman private key whose
// 32-byte scalar lives in a [secmem.SecureBuffer] for its entire lifetime
// and is used where it lies: PublicKey and SharedSecret run the RFC 7748
// ladder directly over the borrowed scalar, inside [secmem.ScrubErr], and
// SharedSecret writes the result straight into the SecureBuffer it returns.
//
// The ladder is the standard library's own (crypto/ecdh's x25519ScalarMult,
// copied verbatim into internal/x25519 and pinned to the toolchain's source
// by a test). It is called directly because everything around it in the
// standard library puts the key on the heap: crypto/ecdh copies the scalar
// into a heap PrivateKey, and golang.org/x/crypto/curve25519 builds one per
// call and returns the shared secret as a fresh heap slice. With the ladder
// called in place, the clamped scalar and the field elements are locals of a
// function that allocates nothing, so they live only on the stack the
// Scrub window wipes. The out-of-process residue test finds neither the
// scalar nor the shared secret outside locked memory, on either build mode.
//
// What is left is the operation itself: while PublicKey or SharedSecret is
// running, its stack holds key-dependent state, as any implementation's does.
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
	buf, err := secmem.NewEmptyBuffer(x25519.ScalarSize)
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
	if n := scalarBuf.Len(); n != x25519.ScalarSize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrBadScalarLength, n, x25519.ScalarSize)
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
			x25519.ScalarMult(&pub, (*[x25519.ScalarSize]byte)(scalar), &x25519Basepoint)
			return nil
		})
	})
	if err != nil {
		return [32]byte{}, fmt.Errorf("secmemcrypto: public key: %w", err)
	}
	return pub, nil
}

// SharedSecret computes the X25519 shared secret with peerPub and returns it
// in a new SecureBuffer (the caller owns and must Destroy it). The secret is
// computed directly into that buffer. It errors if peerPub is a low-order
// point — X25519 would yield an all-zero shared secret, which must never be
// used as key material — or if this key is destroyed or sealed.
func (k *X25519Key) SharedSecret(peerPub [32]byte) (*secmem.SecureBuffer, error) {
	if k == nil || k.scalarBuf == nil || k.scalarBuf.IsDestroyed() {
		return nil, fmt.Errorf("secmemcrypto: shared secret: %w", secmem.ErrDestroyed)
	}
	if k.scalarBuf.IsSealed() {
		return nil, fmt.Errorf("secmemcrypto: shared secret: %w", secmem.ErrSealed)
	}
	out, err := secmem.NewEmptyBuffer(x25519.PointSize)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: allocate shared secret buffer: %w", err)
	}
	err = secmem.ScrubErr(func() error {
		return k.scalarBuf.WithBytesErr(func(scalar []byte) error {
			return out.WithBytesErr(func(dst []byte) error {
				x25519.ScalarMult((*[x25519.PointSize]byte)(dst), (*[x25519.ScalarSize]byte)(scalar), &peerPub)
				var zero [x25519.PointSize]byte
				if subtle.ConstantTimeCompare(dst, zero[:]) == 1 {
					return errLowOrderPoint
				}
				return nil
			})
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
	// Acquire the two read locks in a FIXED GLOBAL ORDER. Taking them in
	// argument order is an ABBA deadlock: k.ConstantTimeEqual(other) and
	// other.ConstantTimeEqual(k) running concurrently grab them in opposite
	// directions, and secmem's lock is writer-preferring, so a read acquire
	// blocks behind any queued writer — each goroutine then holds one and waits
	// forever for the other, wedging Destroy and WipeAllSecrets with them.
	//
	// Ordered by LockOrder, the buffer's process-unique registration ordinal:
	// stable for the buffer's lifetime and independent of object placement, so
	// unlike an address it needs no assumption about GC behaviour. The core
	// orders Secret.ConstantTimeEqual by the same ordinal.
	//
	// Swapping the operands is safe because equality is symmetric.
	first, second := k.scalarBuf, other.scalarBuf
	if first.LockOrder() > second.LockOrder() {
		first, second = second, first
	}
	var equal bool
	err := first.WithBytesErr(func(a []byte) error {
		return second.WithBytesErr(func(b []byte) error {
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
