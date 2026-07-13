// Package secmemcrypto adapts secmem's hardened memory primitives to the
// standard library's crypto interfaces — an [Ed25519Signer] satisfying crypto.Signer
// with its key material living in a [secmem.SecureBuffer], never a plain
// heap-backed key.
package secmemcrypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/deadpoets/secmem"
)

// Ed25519Signer is a crypto.Signer whose Ed25519 seed lives in a [secmem.SecureBuffer]
// for its entire lifetime — it is read only inside a borrowing closure during
// Sign, never copied to a plain heap-backed key.
//
// The public key is derived once at construction and cached in an ordinary
// field: it is not secret, and crypto.Signer.Public must not fail or block.
//
// Concurrent Sign calls are safe: the underlying buffer takes a read lock
// per borrow. Sealing the underlying buffer (via a retained *SecureBuffer
// reference) makes Sign return an error wrapping [secmem.ErrSealed] until
// Unseal; sealing is a caller-side lifecycle tool, not something Ed25519Signer
// does on its own.
type Ed25519Signer struct {
	seedBuf *secmem.SecureBuffer
	pubKey  ed25519.PublicKey
}

// NewEd25519Signer wraps an existing 32-byte Ed25519 seed already held in a
// SecureBuffer. On success, the Ed25519Signer owns seedBuf — call [Ed25519Signer.Destroy]
// to release it, not seedBuf.Destroy directly. On failure, ownership is not
// transferred; the caller is still responsible for seedBuf.
func NewEd25519Signer(seedBuf *secmem.SecureBuffer) (*Ed25519Signer, error) {
	if seedBuf == nil {
		return nil, errors.New("secmemcrypto: nil SecureBuffer")
	}
	if seedBuf.IsDestroyed() {
		return nil, fmt.Errorf("secmemcrypto: new signer: %w", secmem.ErrDestroyed)
	}
	if n := seedBuf.Len(); n != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrBadSeedLength, n, ed25519.SeedSize)
	}

	var pub ed25519.PublicKey
	err := secmem.ScrubErr(func() error {
		return seedBuf.WithBytesErr(func(seed []byte) error {
			var derr error
			pub, derr = deriveEd25519PublicKey(seed)
			return derr
		})
	})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: derive public key: %w", err)
	}

	return &Ed25519Signer{seedBuf: seedBuf, pubKey: pub}, nil
}

// GenerateEd25519Signer generates a fresh Ed25519 seed directly into a new
// SecureBuffer using crypto/rand. With the default [crypto/rand.Reader]
// (every platform path in Go 1.26 writes directly into the destination
// slice) the seed is never materialized on the Go heap; an application
// that replaces rand.Reader with a buffering reader routes seed bytes
// through that reader's own memory, outside this library's control.
//
// To persist the generated key, use [Ed25519Signer.WithSeed].
func GenerateEd25519Signer() (*Ed25519Signer, error) {
	seedBuf, err := secmem.NewEmptyBuffer(ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: allocate seed buffer: %w", err)
	}

	if err := seedBuf.WithBytesErr(func(seed []byte) error {
		_, err := io.ReadFull(rand.Reader, seed)
		return err
	}); err != nil {
		_ = seedBuf.Destroy()
		return nil, fmt.Errorf("secmemcrypto: generate seed: %w", err)
	}

	signer, err := NewEd25519Signer(seedBuf)
	if err != nil {
		_ = seedBuf.Destroy()
		return nil, err
	}
	return signer, nil
}

// Public implements crypto.Signer. It returns a fresh copy on every call —
// matching crypto/ed25519's own behavior — so a caller mutating the
// returned slice cannot corrupt the Ed25519Signer's cached key. Returns nil on a
// nil receiver.
func (s *Ed25519Signer) Public() crypto.PublicKey {
	if s == nil || s.pubKey == nil {
		return nil
	}
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, s.pubKey)
	return pub
}

// Sign implements crypto.Signer.
//
// Only pure Ed25519 (RFC 8032, opts.HashFunc() == crypto.Hash(0), no
// context string) is supported — matching the overwhelming majority of
// real usage (TLS certificates, x509, SSH). Ed25519ph (prehashed,
// requested via a SHA-512 opts hash) and Ed25519ctx (requested via a
// non-empty [ed25519.Options].Context) are not implemented; Sign returns
// an error for both rather than silently producing a signature under the
// wrong domain separation. rand is ignored: Ed25519 signing is
// deterministic per RFC 8032, deriving its nonce from the seed and
// message — this matches crypto/ed25519.Sign's own behavior.
//
// digest is the message to sign, not a pre-hashed digest — Ed25519 signs
// the message directly (PureEdDSA); the crypto.Signer parameter name is
// stdlib convention, not a hint that pre-hashing is expected here.
func (s *Ed25519Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s == nil || s.seedBuf == nil {
		return nil, fmt.Errorf("secmemcrypto: sign: %w", secmem.ErrDestroyed)
	}
	if opts != nil && opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("secmemcrypto: only pure Ed25519 is supported (Ed25519ph is not implemented)")
	}
	if o, ok := opts.(*ed25519.Options); ok && o.Context != "" {
		return nil, errors.New("secmemcrypto: only pure Ed25519 is supported (Ed25519ctx is not implemented)")
	}

	var sig []byte
	err := secmem.ScrubErr(func() error {
		return s.seedBuf.WithBytesErr(func(seed []byte) error {
			var signErr error
			sig, signErr = signEd25519Direct(seed, digest)
			return signErr
		})
	})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: sign: %w", err)
	}
	return sig, nil
}

// SignMessage implements [crypto.MessageSigner]. For pure Ed25519 the
// message-signing and Ed25519Signer contracts coincide (the "digest" IS the
// message), so this delegates to [Ed25519Signer.Sign] unchanged; stdlib callers
// (crypto/x509, crypto/tls) interface-upgrade to MessageSigner when
// available and get identical signatures either way.
func (s *Ed25519Signer) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.Sign(rand, msg, opts)
}

// WithSeed borrows the 32-byte seed for the duration of fn — the
// deliberate egress point for persisting a generated key (writing it to a
// keyring, sealing it to disk). The slice is valid ONLY inside fn and must
// not be retained; any copy fn makes leaves secmem's protection and
// becomes the caller's responsibility to place somewhere equally guarded
// and to wipe. Returns an error wrapping [secmem.ErrDestroyed] or
// [secmem.ErrSealed] when the seed is no longer accessible.
func (s *Ed25519Signer) WithSeed(fn func(seed []byte) error) error {
	if s == nil || s.seedBuf == nil {
		return fmt.Errorf("secmemcrypto: with seed: %w", secmem.ErrDestroyed)
	}
	return s.seedBuf.WithBytesErr(fn)
}

// Equal reports whether s's public key equals x. Pass a public key
// (typically other.Public()), not another *Ed25519Signer: like all stdlib key
// types, the comparison type-asserts x to [ed25519.PublicKey] and any
// other type — including *Ed25519Signer itself — compares false without error.
// Returns false on a nil receiver.
func (s *Ed25519Signer) Equal(x crypto.PublicKey) bool {
	if s == nil || s.pubKey == nil {
		return false
	}
	return s.pubKey.Equal(x)
}

// Destroy wipes and releases the underlying seed buffer. Destroy is
// idempotent and nil-receiver safe. Further calls to Sign or WithSeed
// return an error wrapping [secmem.ErrDestroyed]; Public and Equal remain
// safe to call, since the cached public key is not secret.
func (s *Ed25519Signer) Destroy() error {
	if s == nil {
		return nil
	}
	return s.seedBuf.Destroy()
}
