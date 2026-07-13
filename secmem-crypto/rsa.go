// rsa.go provides RSASigner, a crypto.Signer whose RSA private key lives
// DER-encoded in a SecureBuffer between operations.
package secmemcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"

	"github.com/deadpoets/secmem"
)

// RSASigner is a crypto.Signer whose RSA private key lives DER-encoded
// (PKCS#1 or PKCS#8) in a [secmem.SecureBuffer] between operations.
//
// Honesty caveat — transient materialization, at RSA scale: every Sign call
// parses the DER into a full *rsa.PrivateKey on the Go heap — D, both
// primes, and the CRT exponents as big.Ints, plus the standard library's
// internal FIPS-form key — signs with the standard library, then zeroes
// every exported big.Int limb before dropping the key. The internal FIPS
// form and stdlib's modular-arithmetic scratch are unreachable from here:
// on GOEXPERIMENT=runtimesecret builds the surrounding [secmem.ScrubErr]
// erases them; otherwise they are reclaimed by the garbage collector, not
// explicitly zeroed. RSA has no compact secret form — no 32-byte seed to
// guard — so custody at rest means custody of the whole DER blob, and the
// per-operation heap exposure is proportionally larger than
// [ECDSASigner]'s. If transient heap copies of the full private key are
// outside your threat model's tolerance, keep RSA keys in an HSM or KMS;
// this type's job is to be honest about that line, not to blur it.
//
// Each Sign re-runs DER parsing, key validation, and CRT precomputation —
// the price of not keeping a live heap key; the benchmarks measure it. The
// modular exponentiation dominates for 2048-bit keys and up.
//
// RSASigner deliberately implements only crypto.Signer, not
// crypto.Decrypter: RSA decryption (and PKCS#1 v1.5 decryption especially)
// carries padding-oracle risk that deserves its own design pass, not a
// free ride on a signing type.
//
// The public key is captured once at construction and cached: Public and
// Equal keep working after Destroy or while sealed. Concurrent Sign calls
// are safe (the underlying buffer takes a read lock per borrow).
type RSASigner struct {
	derBuf *secmem.SecureBuffer
	pkcs8  bool
	pub    *rsa.PublicKey
}

// NewRSASigner wraps an RSA private key, DER-encoded as PKCS#1 ("RSA
// PRIVATE KEY") or PKCS#8 ("PRIVATE KEY"), already held in a SecureBuffer.
// The encoding is auto-detected once at construction; the key is validated
// (n = p·q, e·d ≡ 1) by crypto/x509's parser. On success the RSASigner owns
// derBuf — call [RSASigner.Destroy] to release it. On failure, ownership is
// not transferred.
//
// Callers starting from PEM must decode the PEM block themselves and place
// only the DER bytes in the SecureBuffer — and wipe the intermediate
// decode, which lived on the plain heap.
//
// Key size is not checked here: the standard library rejects keys smaller
// than 1024 bits at Sign time (see the crypto/rsa package documentation,
// including the rsa1024min GODEBUG escape hatch for tests).
func NewRSASigner(derBuf *secmem.SecureBuffer) (*RSASigner, error) {
	if derBuf == nil {
		return nil, errors.New("secmemcrypto: nil SecureBuffer")
	}
	if derBuf.IsDestroyed() {
		return nil, fmt.Errorf("secmemcrypto: new rsa signer: %w", secmem.ErrDestroyed)
	}

	var (
		pub   *rsa.PublicKey
		pkcs8 bool
	)
	err := secmem.ScrubErr(func() error {
		return derBuf.WithBytesErr(func(der []byte) error {
			key, perr := parseRSAPrivateKey(der, false)
			if perr != nil {
				var p8err error
				key, p8err = parseRSAPrivateKey(der, true)
				if p8err != nil {
					return errors.Join(perr, p8err)
				}
				pkcs8 = true
			}
			defer wipeRSAPrivateKey(key)
			// Copy the embedded struct out so nothing retains the transient
			// *PrivateKey — holding &key.PublicKey would keep the whole key,
			// including its internal FIPS form, reachable forever.
			pubCopy := key.PublicKey
			pub = &pubCopy
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: new rsa signer: %w", err)
	}
	return &RSASigner{derBuf: derBuf, pkcs8: pkcs8, pub: pub}, nil
}

// GenerateRSASigner generates a fresh RSA key of the given bit size with
// [rsa.GenerateKey] and stores it PKCS#1-DER-encoded in a new SecureBuffer.
//
// Honesty caveat: RSA key generation is inherently a heap operation —
// candidate primes, primality-test scratch, and the finished key all
// materialize in ordinary memory, and only the finished key's exported
// limbs and the DER copy can be wiped from here (the rest is erased by
// [secmem.ScrubErr] on GOEXPERIMENT=runtimesecret builds, otherwise
// GC-reclaimed, not zeroed). If that one-time window matters to your threat
// model, generate RSA keys in an HSM/KMS and import the DER instead.
//
// The standard library rejects bits < 1024.
func GenerateRSASigner(bits int) (*RSASigner, error) {
	var buf *secmem.SecureBuffer
	err := secmem.ScrubErr(func() error {
		key, gerr := rsa.GenerateKey(rand.Reader, bits)
		if gerr != nil {
			return gerr
		}
		defer wipeRSAPrivateKey(key)
		// NewBuffer zeroes its source slice after copying — but only on
		// success. On failure (no lockable memory, mlock limit) the DER is a
		// complete private key stranded on the plain heap; wipe it ourselves.
		der := x509.MarshalPKCS1PrivateKey(key)
		var berr error
		buf, berr = secmem.NewBuffer(der)
		if berr != nil {
			secmem.SecureWipe(der)
		}
		return berr
	})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: generate rsa key: %w", err)
	}
	s, err := NewRSASigner(buf)
	if err != nil {
		_ = buf.Destroy()
		return nil, err
	}
	return s, nil
}

// Public implements crypto.Signer. It returns a fresh *rsa.PublicKey copy
// on every call, so a caller mutating the returned key's N cannot corrupt
// the cached one. Returns nil on a nil receiver.
func (s *RSASigner) Public() crypto.PublicKey {
	if s == nil || s.pub == nil {
		return nil
	}
	return &rsa.PublicKey{N: new(big.Int).Set(s.pub.N), E: s.pub.E}
}

// Sign implements crypto.Signer, delegating to [rsa.PrivateKey.Sign]:
// pass a [crypto.Hash] as opts for PKCS#1 v1.5 signatures, or
// *[rsa.PSSOptions] for PSS. opts must be non-nil. digest must be the
// opts-hash of the message (with the PKCS#1 v1.5 legacy exception that
// opts.HashFunc() == 0 signs digest directly).
//
// random is passed through to the standard library; pass
// [crypto/rand.Reader]. (PKCS#1 v1.5 signing is deterministic and ignores
// it; since Go 1.26, PSS always draws salt from a secure internal source
// and ignores the actual Reader unless GODEBUG=cryptocustomrand=1.)
//
// See the type comment for what Sign does and does not guarantee about
// where key bytes live during the operation.
func (s *RSASigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s == nil || s.derBuf == nil {
		return nil, fmt.Errorf("secmemcrypto: rsa sign: %w", secmem.ErrDestroyed)
	}
	if opts == nil {
		return nil, errors.New("secmemcrypto: rsa sign: nil opts (pass the digest's crypto.Hash, or *rsa.PSSOptions)")
	}
	// A typed nil passes the interface check above but would nil-deref
	// inside crypto/rsa after the key is already materialized.
	if pss, ok := opts.(*rsa.PSSOptions); ok && pss == nil {
		return nil, errors.New("secmemcrypto: rsa sign: nil *rsa.PSSOptions (pass a non-nil *rsa.PSSOptions, or the digest's crypto.Hash for PKCS#1 v1.5)")
	}
	var sig []byte
	err := secmem.ScrubErr(func() error {
		return s.derBuf.WithBytesErr(func(der []byte) error {
			priv, perr := parseRSAPrivateKey(der, s.pkcs8)
			if perr != nil {
				return perr
			}
			defer wipeRSAPrivateKey(priv)
			var serr error
			sig, serr = priv.Sign(random, digest, opts)
			return serr
		})
	})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: rsa sign: %w", err)
	}
	return sig, nil
}

// WithDER borrows the DER-encoded private key for the duration of fn — the
// deliberate egress point for persisting the key. The bytes are exactly
// what was provided to [NewRSASigner] (or PKCS#1 DER for a generated key).
// The slice is valid ONLY inside fn and must not be retained; any copy fn
// makes leaves secmem's protection and becomes the caller's responsibility.
// Returns an error wrapping [secmem.ErrDestroyed] or [secmem.ErrSealed]
// when the key is no longer accessible.
func (s *RSASigner) WithDER(fn func(der []byte) error) error {
	if s == nil || s.derBuf == nil {
		return fmt.Errorf("secmemcrypto: with der: %w", secmem.ErrDestroyed)
	}
	return s.derBuf.WithBytesErr(fn)
}

// Equal reports whether s's public key equals x. Pass a public key
// (typically other.Public()), not another *RSASigner: the comparison
// type-asserts x to *rsa.PublicKey and any other type compares false
// without error. Returns false on a nil receiver.
func (s *RSASigner) Equal(x crypto.PublicKey) bool {
	if s == nil || s.pub == nil {
		return false
	}
	return s.pub.Equal(x)
}

// Destroy wipes and releases the underlying DER buffer. Destroy is
// idempotent and nil-receiver safe. Further calls to Sign or WithDER return
// an error wrapping [secmem.ErrDestroyed]; Public and Equal remain safe to
// call, since the cached public key is not secret.
func (s *RSASigner) Destroy() error {
	if s == nil {
		return nil
	}
	return s.derBuf.Destroy()
}

// parseRSAPrivateKey parses der as PKCS#1 (pkcs8 false) or PKCS#8 (pkcs8
// true). A PKCS#8 blob holding a non-RSA key is rejected — after wiping
// what the parse materialized, where the key type allows it.
func parseRSAPrivateKey(der []byte, pkcs8 bool) (*rsa.PrivateKey, error) {
	if !pkcs8 {
		key, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("secmemcrypto: parse PKCS#1: %w", err)
		}
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: parse PKCS#8: %w", err)
	}
	switch k := keyAny.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		wipeECDSAPrivateKey(k)
		return nil, errors.New("secmemcrypto: PKCS#8 DER holds an ECDSA key, not RSA (store its raw scalar in a SecureBuffer and use NewECDSASigner)")
	case ed25519.PrivateKey:
		secmem.SecureWipe(k)
		return nil, errors.New("secmemcrypto: PKCS#8 DER holds an Ed25519 key, not RSA (store its seed in a SecureBuffer and use NewEd25519Signer)")
	default:
		return nil, fmt.Errorf("secmemcrypto: PKCS#8 DER holds a %T, not an RSA key", keyAny)
	}
}

// wipeRSAPrivateKey zeroes the secret limbs of a transiently materialized
// *rsa.PrivateKey: D, the primes, and every CRT precomputation big.Int.
// The public N/E are left intact (callers may have copied the embedded
// PublicKey, which shares N). The unexported FIPS-form key inside
// Precomputed is not reachable; see the RSASigner type comment.
func wipeRSAPrivateKey(key *rsa.PrivateKey) {
	if key == nil {
		return
	}
	wipeBigInt(key.D)
	for _, p := range key.Primes {
		wipeBigInt(p)
	}
	wipeBigInt(key.Precomputed.Dp)
	wipeBigInt(key.Precomputed.Dq)
	wipeBigInt(key.Precomputed.Qinv)
	//nolint:staticcheck // SA1019: CRTValues is deprecated but Precompute
	// still fills it in — deprecated secrets need wiping too.
	crt := key.Precomputed.CRTValues
	for i := range crt {
		wipeBigInt(crt[i].Exp)
		wipeBigInt(crt[i].Coeff)
		wipeBigInt(crt[i].R)
	}
	runtime.KeepAlive(key)
}
