// ed25519direct.go implements Ed25519 signing directly from a byte seed,
// bypassing crypto/ed25519.Sign.
//
// # Why not crypto/ed25519.Sign()?
//
// Go's crypto/ed25519 uses an internal FIPS 140 cache (fips140cache) that
// creates weak.Pointer references to the private key's backing array.
// weak.Pointer requires GC-managed (heap) memory — a [secmem.SecureBuffer]
// is mmap'd (off-heap, mlocked), so weak.Make panics against it. Even with a
// heap-copy workaround, the FIPS cache would retain derived key material on
// the heap for an indeterminate period, entirely outside SecureBuffer's
// Destroy lifecycle.
//
// # Solution
//
// RFC 8032 §5.1.6 Ed25519 signing implemented directly with
// filippo.io/edwards25519 scalar arithmetic and crypto/sha512, bypassing
// crypto/ed25519.Sign entirely while producing byte-identical signatures
// that crypto/ed25519.Verify accepts. Every secret intermediate (the
// SHA-512 hash, the private scalar, the nonce scalar, the nonce pre-image)
// lives on the stack and is wiped after use — the edwards25519 scalars and
// points do not escape — so for a message of up to ed25519NonceStackBytes
// the only heap allocation of a signature is the signature; a longer
// message puts its nonce pre-image on the heap, wiped before return
// (classification_test.go pins both counts). The seed itself is read in place
// from the caller's buffer and never copied to the heap; it is copied
// twice on the stack, inside sha512.Sum512 — once into the digest's block
// buffer and once, as the digest, into the returned array — both in
// frames that die before the enclosing Scrub window closes and are wiped
// with it (on the legacy path, the 32 KiB band below the window; under
// runtime/secret, the whole call tree). A streaming sha512.New() digest
// would not improve on that: it is a heap object whose block buffer would
// hold the seed, Reset does not clear that buffer, and it would need the
// same reflection wipe the AES schedule needs — so the one-shot stays.
//
// Verification remains via crypto/ed25519.Verify — public keys are not
// sensitive and have no FIPS-cache issue.
package secmemcrypto

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"

	"filippo.io/edwards25519"

	"github.com/deadpoets/secmem"
)

// ErrBadSeedLength is returned when a raw seed does not have the exact
// length its algorithm requires: 32 bytes for Ed25519 ([Ed25519Signer]), or
// 64 bytes for ML-KEM-768 ([MLKEM768Key] — see [crypto/mlkem.SeedSize]).
var ErrBadSeedLength = errors.New("secmemcrypto: bad seed length")

// ed25519NonceStackBytes is the longest message whose nonce pre-image
// (the 32-byte secret prefix followed by the message) is assembled on the
// stack rather than the heap. 4 KiB covers TLS and SSH transcripts and most
// X.509 TBS structures, and stays well inside the 32 KiB band the legacy
// Scrub wipes.
const ed25519NonceStackBytes = 4096

// signEd25519Direct signs message using the 32-byte Ed25519 seed, following
// RFC 8032 §5.1.6 exactly. It produces signatures byte-identical to
// crypto/ed25519.Sign.
//
// seed is read but never modified. All secret intermediates this function
// allocates (the SHA-512 hash, the private scalar, the nonce scalar, the
// nonce pre-image) are wiped before return; the two stack copies of the
// seed inside sha512.Sum512 are covered by the caller's Scrub window (see
// the file comment).
func signEd25519Direct(seed, message []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrBadSeedLength, len(seed), ed25519.SeedSize)
	}

	// Step 1: h = SHA-512(seed) — 64-byte hash.
	var h [64]byte
	digest := sha512.Sum512(seed)
	copy(h[:], digest[:])
	secmem.SecureWipe(digest[:])

	// Step 2: s = clamp(h[0:32]) — private scalar.
	s, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		secmem.SecureWipe(h[:])
		return nil, fmt.Errorf("clamp: %w", err)
	}

	// Step 3: A = s * B — public key point (not secret, but needed for k).
	A := (&edwards25519.Point{}).ScalarBaseMult(s)

	// Step 4: r = SHA-512(h[32:64] || message) — nonce scalar. nonceDigest is
	// SECRET (derived from the private prefix h[32:64]). Hash a single scratch
	// buffer with sha512.Sum512 (whose digest is a stack local) rather than a
	// streaming sha512.New() hasher: the streaming hasher is a heap allocation
	// that retains the written prefix in its unexported block buffer, which no
	// wipe here can reach. The scratch lives on the stack for messages up to
	// ed25519NonceStackBytes — the common case, and then nothing secret in
	// this function touches the heap at all (classification_test.go pins Sign
	// at one allocation, the signature) — and on the heap, wiped immediately
	// after, for longer ones. Leaking two nonce pre-images for the same key
	// recovers the private scalar.
	var nonceStack [32 + ed25519NonceStackBytes]byte
	nonceInput := nonceStack[:0]
	if len(message) > ed25519NonceStackBytes {
		nonceInput = make([]byte, 0, 32+len(message))
	}
	nonceInput = append(nonceInput, h[32:]...)
	nonceInput = append(nonceInput, message...)
	nonceDigest := sha512.Sum512(nonceInput)
	secmem.SecureWipe(nonceInput)
	r, err := edwards25519.NewScalar().SetUniformBytes(nonceDigest[:])
	secmem.SecureWipe(nonceDigest[:])
	if err != nil {
		secmem.SecureWipe(h[:])
		WipeEd25519Scalar(s)
		return nil, fmt.Errorf("nonce: %w", err)
	}

	// Step 5: R = r * B — nonce point.
	R := (&edwards25519.Point{}).ScalarBaseMult(r)

	// Step 6: k = SHA-512(R || A || message) — challenge scalar. k is
	// derived only from public values (R, A, message) so the digest is not
	// secret, but summing into a stack array (not mh.Sum(nil)) avoids a
	// stray heap allocation and keeps the wipe discipline uniform across
	// the signer.
	kh := sha512.New()
	kh.Write(R.Bytes())
	kh.Write(A.Bytes())
	kh.Write(message)
	var challengeDigest [64]byte
	kh.Sum(challengeDigest[:0])
	k, err := edwards25519.NewScalar().SetUniformBytes(challengeDigest[:])
	secmem.SecureWipe(challengeDigest[:])
	if err != nil {
		secmem.SecureWipe(h[:])
		WipeEd25519Scalar(s)
		WipeEd25519Scalar(r)
		return nil, fmt.Errorf("challenge: %w", err)
	}

	// Step 7: S = r + k*s mod L — response scalar.
	S := edwards25519.NewScalar().MultiplyAdd(k, s, r)

	// Step 8: sig = R || S — 64-byte signature.
	sig := make([]byte, ed25519.SignatureSize)
	copy(sig[:32], R.Bytes())
	copy(sig[32:], S.Bytes())

	// Wipe all secret intermediates. Points (A, R) and S are public.
	secmem.SecureWipe(h[:])
	WipeEd25519Scalar(s)
	WipeEd25519Scalar(r)
	WipeEd25519Scalar(k)

	return sig, nil
}

// deriveEd25519PublicKey derives the Ed25519 public key from a 32-byte seed
// using the same SHA-512 + clamping + base-point multiplication as Ed25519
// key generation (RFC 8032 §5.1.5), so it can be computed on demand from a
// seed that is never otherwise materialized outside a SecureBuffer.
func deriveEd25519PublicKey(seed []byte) (ed25519.PublicKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrBadSeedLength, len(seed), ed25519.SeedSize)
	}

	var h [64]byte
	digest := sha512.Sum512(seed)
	copy(h[:], digest[:])
	secmem.SecureWipe(digest[:])

	s, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		secmem.SecureWipe(h[:])
		return nil, fmt.Errorf("clamp: %w", err)
	}

	A := (&edwards25519.Point{}).ScalarBaseMult(s)
	pub := make([]byte, ed25519.PublicKeySize)
	copy(pub, A.Bytes())

	secmem.SecureWipe(h[:])
	WipeEd25519Scalar(s)

	return ed25519.PublicKey(pub), nil
}
