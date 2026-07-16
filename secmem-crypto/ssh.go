// ssh.go provides AsSSH, adapting this package's signers (or any
// crypto.Signer) to golang.org/x/crypto/ssh with legacy ssh-rsa (SHA-1)
// unreachable, and Ed25519Signer.MarshalOpenSSHPrivateKey, the matching
// egress path for persisting a generated key as an OpenSSH private-key file.
package secmemcrypto

import (
	"crypto"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/deadpoets/secmem"
)

// AsSSH adapts a crypto.Signer into an [ssh.Signer].
//
// For Ed25519 and ECDSA keys this is [ssh.NewSignerFromSigner] unchanged —
// each of those key types has exactly one SSH signature algorithm, so there
// is nothing to negotiate, and [Ed25519Signer] and [ECDSASigner] already work with
// x/crypto/ssh directly.
//
// RSA is why this function exists. The SSH algorithm family for an RSA key
// includes legacy ssh-rsa — SHA-1, broken for collision resistance and
// disabled by default in OpenSSH since 8.8 — and a bare
// ssh.NewSignerFromSigner will still negotiate it, and even defaults to it
// for direct Sign calls. For RSA keys AsSSH returns a signer restricted to
// rsa-sha2-512 and rsa-sha2-256 (in that preference order): negotiation
// never offers ssh-rsa, SignWithAlgorithm("ssh-rsa") returns an error, and
// plain Sign uses rsa-sha2-512. Callers who genuinely must speak SHA-1 to
// ancient servers can wire x/crypto/ssh themselves; this library will not.
func AsSSH(signer crypto.Signer) (ssh.Signer, error) {
	if signer == nil {
		return nil, errors.New("secmemcrypto: as ssh: nil signer")
	}
	base, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: as ssh: %w", err)
	}
	if base.PublicKey().Type() != ssh.KeyAlgoRSA {
		return base, nil
	}
	algo, ok := base.(ssh.AlgorithmSigner)
	if !ok {
		// Unreachable with current x/crypto/ssh, whose wrapped signers all
		// implement AlgorithmSigner; guarded so a regression fails closed
		// instead of silently keeping SHA-1 reachable.
		return nil, errors.New("secmemcrypto: as ssh: RSA signer does not support algorithm selection")
	}
	multi, err := ssh.NewSignerWithAlgorithms(algo, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: as ssh: %w", err)
	}
	return rsaSHA2Signer{multi}, nil
}

// rsaSHA2Signer pins the plain Sign path to rsa-sha2-512.
// [ssh.NewSignerWithAlgorithms] restricts protocol negotiation and
// SignWithAlgorithm, but its plain Sign method falls through to the
// embedded signer's default — legacy ssh-rsa (SHA-1) for RSA keys. This
// override routes Sign through SignWithAlgorithm with the strongest
// restricted algorithm, so no path on an AsSSH signer produces a SHA-1
// signature.
type rsaSHA2Signer struct {
	ssh.MultiAlgorithmSigner
}

func (s rsaSHA2Signer) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data, s.Algorithms()[0])
}

// MarshalOpenSSHPrivateKey renders s as an unencrypted OpenSSH private-key
// PEM file (the "-----BEGIN OPENSSH PRIVATE KEY-----" format ssh-keygen and
// authorized_keys tooling expect) and returns it in a fresh SecureBuffer —
// the caller owns it and must call Destroy. This is the egress point for
// persisting a generated key: writing it to disk, registering it with a
// cloud provider's SSH-key API, or handing it to another process. AsSSH
// covers the complementary case — signing over a live connection without
// ever exporting key material at all; use that when you don't actually need
// a portable file.
//
// The size of the output depends on comment's length, so — unlike this
// package's *Into functions — this allocates internally rather than asking
// the caller to pre-size a destination; the caller does not need to compute
// anything.
//
// A fingerprint does not require this method: it is computed over the
// public key alone, which is not secret — ssh.FingerprintSHA256(pub) on
// the AsSSH-adapted signer's PublicKey() needs nothing from here.
//
// Returns an error wrapping [secmem.ErrDestroyed] or [secmem.ErrSealed]
// when the seed is no longer accessible.
func (s *Ed25519Signer) MarshalOpenSSHPrivateKey(comment string) (*secmem.SecureBuffer, error) {
	if s == nil || s.seedBuf == nil {
		return nil, fmt.Errorf("secmemcrypto: marshal openssh private key: %w", secmem.ErrDestroyed)
	}

	var pemBytes []byte
	err := secmem.ScrubErr(func() error {
		return s.seedBuf.WithBytesErr(func(seed []byte) error {
			// ed25519.NewKeyFromSeed's FIPS self-check panics on a mmap'd
			// (off-heap) input — copy to an ordinary heap slice first. This
			// copy, and every derived form below, is wiped before returning.
			seedCopy := make([]byte, len(seed))
			copy(seedCopy, seed) //nolint:secmem-lint // required: ed25519.NewKeyFromSeed panics on mmap'd input, wiped via defer above
			defer secmem.SecureWipe(seedCopy)

			priv := ed25519.NewKeyFromSeed(seedCopy)
			defer secmem.SecureWipe(priv)

			block, err := ssh.MarshalPrivateKey(priv, comment)
			if err != nil {
				return fmt.Errorf("marshal: %w", err)
			}
			defer secmem.SecureWipe(block.Bytes)

			pemBytes = pem.EncodeToMemory(block)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: marshal openssh private key: %w", err)
	}
	defer secmem.SecureWipe(pemBytes)

	out, err := secmem.NewEmptyBuffer(len(pemBytes))
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: allocate openssh private key buffer: %w", err)
	}
	if err := out.WithBytesErr(func(dst []byte) error {
		copy(dst, pemBytes)
		return nil
	}); err != nil {
		_ = out.Destroy()
		return nil, fmt.Errorf("secmemcrypto: marshal openssh private key: %w", err)
	}
	return out, nil
}
