// Package secmemcrypto is a minimal stand-in for
// github.com/deadpoets/secmem/secmem-crypto: the borrowing accessors the
// analyzer recognizes on that package's types.
package secmemcrypto

type Ed25519Signer struct{}

func (s *Ed25519Signer) WithSeed(fn func(seed []byte) error) error { return nil }
func (s *Ed25519Signer) Destroy() error                            { return nil }

type X25519Key struct{}

func (k *X25519Key) WithScalar(fn func(scalar []byte) error) error { return nil }

type RSASigner struct{}

func (s *RSASigner) WithDER(fn func(der []byte) error) error { return nil }
