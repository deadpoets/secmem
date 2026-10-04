// Package secmemcrypto is a minimal stand-in for
// github.com/deadpoets/secmem/secmem-crypto: the borrowing accessors the
// analyzer recognizes on that package's types, and the methods that borrow
// the same buffer again (signing, key agreement, marshalling) next to the
// ones that only read the cached public half.
package secmemcrypto

import (
	"crypto"
	"io"

	"github.com/deadpoets/secmem"
)

// Signer mirrors the interface the parsers return.
type Signer interface {
	crypto.Signer
	Destroy() error
}

type Ed25519Signer struct{}

func (s *Ed25519Signer) WithSeed(fn func(seed []byte) error) error { return nil }
func (s *Ed25519Signer) Destroy() error                            { return nil }
func (s *Ed25519Signer) Public() crypto.PublicKey                  { return nil }
func (s *Ed25519Signer) Equal(x crypto.PublicKey) bool             { return false }

func (s *Ed25519Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func (s *Ed25519Signer) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func (s *Ed25519Signer) MarshalOpenSSHPrivateKey(comment string) (*secmem.SecureBuffer, error) {
	return nil, nil
}

func (s *Ed25519Signer) MarshalOpenSSHPrivateKeyWithPassphrase(comment string, passphrase []byte) (*secmem.SecureBuffer, error) {
	return nil, nil
}

type ECDSASigner struct{}

func (s *ECDSASigner) WithScalar(fn func(scalar []byte) error) error { return nil }
func (s *ECDSASigner) Destroy() error                                { return nil }
func (s *ECDSASigner) Public() crypto.PublicKey                      { return nil }

func (s *ECDSASigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

type X25519Key struct{}

func (k *X25519Key) WithScalar(fn func(scalar []byte) error) error { return nil }
func (k *X25519Key) Destroy() error                                { return nil }
func (k *X25519Key) PublicKey() ([32]byte, error)                  { return [32]byte{}, nil }
func (k *X25519Key) ConstantTimeEqual(other *X25519Key) bool       { return false }

func (k *X25519Key) SharedSecret(peerPub [32]byte) (*secmem.SecureBuffer, error) {
	return nil, nil
}

type RSASigner struct{}

func (s *RSASigner) WithDER(fn func(der []byte) error) error { return nil }
func (s *RSASigner) Destroy() error                          { return nil }
func (s *RSASigner) Public() crypto.PublicKey                { return nil }

func (s *RSASigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

type MLKEM768Key struct{}

func (k *MLKEM768Key) WithSeed(fn func(seed []byte) error) error { return nil }
func (k *MLKEM768Key) Destroy() error                            { return nil }
func (k *MLKEM768Key) EncapsulationKeyBytes() ([]byte, error)    { return nil, nil }

func (k *MLKEM768Key) Decapsulate(ciphertext []byte) (*secmem.SecureBuffer, error) {
	return nil, nil
}

// Constructors and owned types for the strict fixtures. Every one hands the
// caller something with a Destroy to call: a concrete key, the Signer
// interface the parsers return, a locked Argon2 workspace.
type Option func()

func GenerateX25519Key(opts ...Option) (*X25519Key, error) { return &X25519Key{}, nil }

func ParsePrivateKey(data []byte, opts ...Option) (Signer, error) { return &Ed25519Signer{}, nil }

type Argon2Workspace struct{}

func (w *Argon2Workspace) Destroy() error { return nil }
func (w *Argon2Workspace) Size() int      { return 0 }

func NewArgon2Workspace(memory uint32, threads uint8, opts ...Option) (*Argon2Workspace, error) {
	return &Argon2Workspace{}, nil
}
