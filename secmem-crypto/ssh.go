// ssh.go provides AsSSH, adapting this package's signers (or any
// crypto.Signer) to golang.org/x/crypto/ssh with legacy ssh-rsa (SHA-1)
// unreachable.
package secmemcrypto

import (
	"crypto"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
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
