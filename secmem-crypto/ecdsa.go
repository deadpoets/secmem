// ecdsa.go provides ECDSASigner, a crypto.Signer for the NIST prime curves
// whose private scalar lives in a SecureBuffer between operations.
package secmemcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"

	"github.com/deadpoets/secmem"
)

// ErrUnsupportedCurve is returned for curves other than P-224, P-256,
// P-384, and P-521 — the curves crypto/ecdsa can parse a raw scalar for.
var ErrUnsupportedCurve = errors.New("secmemcrypto: unsupported curve (want P-224, P-256, P-384, or P-521)")

// errCandidateRejected signals an out-of-range key-generation candidate to
// the retry loop in GenerateECDSASigner. Never returned to callers.
var errCandidateRejected = errors.New("candidate rejected")

// ECDSASigner is a crypto.Signer for the NIST prime curves (P-224, P-256,
// P-384, P-521) whose private scalar lives in a [secmem.SecureBuffer]
// between operations.
//
// Honesty caveat — transient materialization: unlike [Ed25519Signer],
// ECDSASigner does not sign inside hardened memory. crypto/ecdsa exposes no
// API that borrows key bytes in place, and this library will not
// reimplement ECDSA: per-signature nonce arithmetic is exactly where a
// subtle implementation bug leaks the private key, and a from-scratch
// implementation could not prove itself against the timing side channels
// stdlib's constant-time code already handles. Each Sign call instead
// re-materializes the key on the Go heap via [ecdsa.ParseRawPrivateKey],
// signs with the standard library, and zeroes the transient's D limbs
// before dropping it.
//
// What that leaves on the heap, per operation, in go1.26 — none of it
// reachable from here, and none of it zeroed on a build without
// GOEXPERIMENT=runtimesecret:
//
//   - From the parse: a bigmod.Nat of the scalar and a FIPS-form key
//     holding the scalar's bytes, both dropped as soon as the *PrivateKey
//     is built (not cached; a fresh expansion each time).
//   - From the sign: the scalar filled into a fresh []byte, a second
//     FIPS-form key built from it, and a bigmod.Nat of the scalar inside
//     the signature arithmetic. The FIPS-form key is stored in
//     crypto/ecdsa's package-level cache (crypto/internal/fips140cache)
//     keyed by a weak pointer to the transient *ecdsa.PrivateKey, and is
//     evicted only after the collector finds that transient unreachable
//     and runs its cleanup — one to two GC cycles after Sign returns.
//     This module does not retain the transient between operations, which
//     is what keeps that lifetime short; nothing can make it zero.
//
// On a runtimesecret build every one of those objects is allocated inside
// the surrounding [secmem.ScrubErr] and erased by the runtime at the first
// garbage collection after it becomes unreachable — not when Sign returns,
// so a key that signs often has the copies of its latest signatures on the
// heap almost all the time. On every other build (Windows, macOS, Linux without the
// experiment) they are reclaimed by the collector, not zeroed, and the
// cached copy is the longest-lived. What ECDSASigner guarantees is custody
// at rest: the durable, wipeable copy of the scalar lives only inside the
// SecureBuffer.
//
// Because every signature leaves those copies, the constructors refuse on a
// build where they are never erased — every build without
// GOEXPERIMENT=runtimesecret — with an error wrapping [ErrHeapTransients],
// unless the caller passes [AllowHeapTransients]. The refusal is the default
// so that choosing this residual is visible at the call site rather than
// discovered in a heap dump. README, "What each signer actually buys you",
// sets out when opting in is reasonable.
//
// The per-operation parse recomputes the public key (one scalar-base
// multiplication), making a P-256 signature roughly half again as
// expensive as with a plain *ecdsa.PrivateKey kept on the heap. The exact
// delta is hardware-dependent; the benchmark pair in bench_block3_test.go
// measures it on yours. That price is deliberate.
//
// The public key is derived once at construction and cached: Public and
// Equal keep working after Destroy or while sealed. Concurrent Sign calls
// are safe (the underlying buffer takes a read lock per borrow).
type ECDSASigner struct {
	curve     elliptic.Curve
	scalarBuf *secmem.SecureBuffer
	pub       *ecdsa.PublicKey // construction-time copy; never handed out (Equal uses it)
	pubBytes  []byte           // uncompressed SEC 1 encoding; Public() decodes fresh copies from it
}

// supportedCurve mirrors the switch in [ecdsa.ParseRawPrivateKey]: checking
// upfront lets GenerateECDSASigner distinguish "this curve can never work"
// from "this candidate scalar was out of range, redraw".
func supportedCurve(curve elliptic.Curve) bool {
	switch curve {
	case elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521():
		return true
	}
	return false
}

// scalarSize returns the fixed big-endian scalar encoding size for curve:
// 28, 32, 48, and 66 bytes for P-224, P-256, P-384, and P-521.
func scalarSize(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}

// NewECDSASigner wraps an existing raw ECDSA private scalar (big-endian,
// exactly the curve's scalar length: 28/32/48/66 bytes for P-224/P-256/
// P-384/P-521) already held in a SecureBuffer. The scalar must be in
// [1, n-1]; [ecdsa.ParseRawPrivateKey] validates it and derives the public
// key. On success the ECDSASigner owns scalarBuf — call
// [ECDSASigner.Destroy] to release it. On failure, ownership is not
// transferred.
//
// To load a key that exists as SEC 1 or PKCS#8 DER, parse it with
// crypto/x509, copy the scalar into a SecureBuffer with D.FillBytes into
// the borrowed slice, and wipe the parsed key's D limbs. [ParsePrivateKey]
// does all of that for you, without the x509 heap copy.
//
// On a build without GOEXPERIMENT=runtimesecret (Windows, macOS, and Linux
// without the experiment) this refuses with an error wrapping
// [ErrHeapTransients] unless opts include [AllowHeapTransients], because
// every signature this type makes leaves copies of the private key on the
// heap that nothing erases there. The check runs before the key is read.
func NewECDSASigner(curve elliptic.Curve, scalarBuf *secmem.SecureBuffer, opts ...Option) (*ECDSASigner, error) {
	return newECDSASigner(curve, scalarBuf, resolveOptions(opts))
}

// newECDSASigner is NewECDSASigner with its options already resolved, shared
// with the parsers so the gate is decided once per call.
func newECDSASigner(curve elliptic.Curve, scalarBuf *secmem.SecureBuffer, o options) (*ECDSASigner, error) {
	if err := o.checkHeapTransients("secmemcrypto: new ecdsa signer"); err != nil {
		return nil, err
	}
	if curve == nil || !supportedCurve(curve) {
		return nil, ErrUnsupportedCurve
	}
	if scalarBuf == nil {
		return nil, errors.New("secmemcrypto: nil SecureBuffer")
	}
	if scalarBuf.IsDestroyed() {
		return nil, fmt.Errorf("secmemcrypto: new ecdsa signer: %w", secmem.ErrDestroyed)
	}
	if n, want := scalarBuf.Len(), scalarSize(curve); n != want {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrBadScalarLength, n, want)
	}

	var (
		pub      *ecdsa.PublicKey
		pubBytes []byte
	)
	err := secmem.ScrubErr(func() error {
		return scalarBuf.WithBytesErr(func(scalar []byte) error {
			priv, perr := ecdsa.ParseRawPrivateKey(curve, scalar)
			if perr != nil {
				return perr
			}
			defer wipeECDSAPrivateKey(priv)
			// Copy the embedded struct out so nothing retains the transient
			// *PrivateKey (X and Y are public; sharing them is fine).
			pubCopy := priv.PublicKey
			pub = &pubCopy
			var berr error
			pubBytes, berr = pubCopy.Bytes()
			return berr
		})
	})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: new ecdsa signer: %w", err)
	}
	return &ECDSASigner{curve: curve, scalarBuf: scalarBuf, pub: pub, pubBytes: pubBytes}, nil
}

// GenerateECDSASigner generates a fresh private scalar for curve directly
// into a new SecureBuffer using crypto/rand, by candidate testing (the
// FIPS 186-5 B.4.2 shape): uniform random bytes, masked down to the curve's
// bit length, are accepted iff [ecdsa.ParseRawPrivateKey] accepts them as a
// scalar in [1, n-1] — validation and public-key derivation are stdlib's,
// not this library's. For every supported curve the rejection probability
// is at most ~2⁻³², so the first draw virtually always succeeds, and
// accepted scalars are uniform over [1, n-1].
//
// The scalar is born inside the SecureBuffer; the only heap exposure is the
// same transient parse Sign performs (see the type comment). With the
// default [crypto/rand.Reader] the candidate bytes are written directly
// into hardened memory; see [GenerateEd25519Signer] for the caveat about a
// replaced Reader.
//
// To persist the generated key, use [ECDSASigner.WithScalar].
//
// On a build without GOEXPERIMENT=runtimesecret (Windows, macOS, and Linux
// without the experiment) this refuses with an error wrapping
// [ErrHeapTransients] unless opts include [AllowHeapTransients], because
// every signature this type makes leaves copies of the private key on the
// heap that nothing erases there. The check runs before a scalar is drawn.
func GenerateECDSASigner(curve elliptic.Curve, opts ...Option) (*ECDSASigner, error) {
	if err := resolveOptions(opts).checkHeapTransients("secmemcrypto: generate ecdsa scalar"); err != nil {
		return nil, err
	}
	if curve == nil || !supportedCurve(curve) {
		return nil, ErrUnsupportedCurve
	}
	size := scalarSize(curve)
	// Mask the top byte down to the curve's bit length. Only P-521 is not
	// byte-aligned (521 bits in 66 bytes): unmasked candidates there would
	// be rejected ~127/128 of the time.
	topMask := byte(0xFF)
	if excess := size*8 - curve.Params().BitSize; excess > 0 {
		topMask = 0xFF >> excess
	}

	buf, err := secmem.NewEmptyBuffer(size)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: allocate scalar buffer: %w", err)
	}

	// After masking, every supported curve's group order is close enough to
	// the masked range that rejection is ≤ ~2⁻³² per draw; 100 attempts is
	// unreachable without a logic bug, and failing closed beats looping.
	const maxAttempts = 100
	for range maxAttempts {
		var (
			pub      *ecdsa.PublicKey
			pubBytes []byte
		)
		err := secmem.ScrubErr(func() error {
			return buf.WithBytesErr(func(scalar []byte) error {
				if _, rerr := io.ReadFull(rand.Reader, scalar); rerr != nil {
					return rerr
				}
				scalar[0] &= topMask
				priv, perr := ecdsa.ParseRawPrivateKey(curve, scalar)
				if perr != nil {
					return errCandidateRejected
				}
				defer wipeECDSAPrivateKey(priv)
				pubCopy := priv.PublicKey
				pub = &pubCopy
				var berr error
				pubBytes, berr = pubCopy.Bytes()
				return berr
			})
		})
		if errors.Is(err, errCandidateRejected) {
			continue
		}
		if err != nil {
			_ = buf.Destroy()
			return nil, fmt.Errorf("secmemcrypto: generate ecdsa scalar: %w", err)
		}
		return &ECDSASigner{curve: curve, scalarBuf: buf, pub: pub, pubBytes: pubBytes}, nil
	}
	_ = buf.Destroy()
	return nil, errors.New("secmemcrypto: generate ecdsa scalar: internal error: no valid candidate after 100 draws")
}

// Public implements crypto.Signer. Each call decodes a fresh
// *ecdsa.PublicKey from the encoding cached at construction, so a caller
// mutating the returned key cannot corrupt the signer's copy. Returns nil
// on a nil receiver.
func (s *ECDSASigner) Public() crypto.PublicKey {
	if s == nil || s.pubBytes == nil {
		return nil
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(s.curve, s.pubBytes)
	if err != nil {
		// Unreachable: pubBytes came from stdlib's own encoder at
		// construction and is never modified.
		return nil
	}
	return pub
}

// Sign implements crypto.Signer, returning an ASN.1 DER-encoded ECDSA
// signature. digest must be a hash of the message — unlike Ed25519, ECDSA
// signs a digest, typically with opts set to the [crypto.Hash] that
// produced it.
//
// If random is non-nil the signature is randomized; since Go 1.26 the
// standard library always draws from a secure internal source and ignores
// the actual Reader (unless GODEBUG=cryptocustomrand=1). If random is nil
// the signature is deterministic per RFC 6979, and opts must be non-nil and
// name the hash function that produced digest.
//
// See the type comment for what Sign does and does not guarantee about
// where key bytes live during the operation.
func (s *ECDSASigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s == nil || s.scalarBuf == nil {
		return nil, fmt.Errorf("secmemcrypto: ecdsa sign: %w", secmem.ErrDestroyed)
	}
	if random == nil && (opts == nil || opts.HashFunc() == crypto.Hash(0)) {
		return nil, errors.New("secmemcrypto: ecdsa sign: deterministic signing (nil random) requires opts naming the digest's hash")
	}
	var sig []byte
	err := secmem.ScrubErr(func() error {
		return s.scalarBuf.WithBytesErr(func(scalar []byte) error {
			priv, perr := ecdsa.ParseRawPrivateKey(s.curve, scalar)
			if perr != nil {
				return perr
			}
			defer wipeECDSAPrivateKey(priv)
			var serr error
			sig, serr = priv.Sign(random, digest, opts)
			return serr
		})
	})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: ecdsa sign: %w", err)
	}
	return sig, nil
}

// WithScalar borrows the raw big-endian scalar for the duration of fn — the
// deliberate egress point for persisting a generated key. The slice is
// valid ONLY inside fn and must not be retained; any copy fn makes leaves
// secmem's protection and becomes the caller's responsibility. Returns an
// error wrapping [secmem.ErrDestroyed] or [secmem.ErrSealed] when the
// scalar is no longer accessible.
func (s *ECDSASigner) WithScalar(fn func(scalar []byte) error) error {
	if s == nil || s.scalarBuf == nil {
		return fmt.Errorf("secmemcrypto: with scalar: %w", secmem.ErrDestroyed)
	}
	return s.scalarBuf.WithBytesErr(fn)
}

// Equal reports whether s's public key equals x. Pass a public key
// (typically other.Public()), not another *ECDSASigner: the comparison
// type-asserts x to *ecdsa.PublicKey and any other type compares false
// without error. Returns false on a nil receiver.
func (s *ECDSASigner) Equal(x crypto.PublicKey) bool {
	if s == nil || s.pub == nil {
		return false
	}
	return s.pub.Equal(x)
}

// Destroy wipes and releases the underlying scalar buffer. Destroy is
// idempotent and nil-receiver safe. Further calls to Sign or WithScalar
// return an error wrapping [secmem.ErrDestroyed]; Public and Equal remain
// safe to call, since the cached public key is not secret.
func (s *ECDSASigner) Destroy() error {
	if s == nil {
		return nil
	}
	return s.scalarBuf.Destroy()
}

// wipeBigInt zeroes x's absolute-value limbs in place. The Int is left
// denormalized (all-zero limbs under a stale bit length) and must be
// discarded, never used again — this is a disposal helper for transient
// key material, not a Set(0).
func wipeBigInt(x *big.Int) {
	if x == nil {
		return
	}
	limbs := x.Bits()
	for i := range limbs {
		limbs[i] = 0
	}
	runtime.KeepAlive(x)
}

// wipeECDSAPrivateKey zeroes the secret limbs of a transiently materialized
// *ecdsa.PrivateKey. The public X/Y are left intact (callers may have
// copied the embedded PublicKey, which shares them).
//
// It is a package var, not a plain func, solely so a test can wrap it to
// prove the deferred wipe in Sign actually fires on the live transient (see
// livewipe_test.go); production always runs the value defined here. A
// swapped value is an in-process concern, which the threat model already
// excludes.
var wipeECDSAPrivateKey = func(priv *ecdsa.PrivateKey) {
	if priv == nil {
		return
	}
	// Reaching the deprecated raw D field is deliberate: zeroing the
	// transient's secret limbs is this helper's job, and no non-deprecated
	// API exposes them.
	//nolint:staticcheck // SA1019: see above
	//lint:ignore SA1019 zeroing the deprecated raw D field is the point; no non-deprecated API exposes it
	wipeBigInt(priv.D)
	runtime.KeepAlive(priv)
}
