// Package wrapdep declares a borrowing wrapper that package wrappers calls
// across the package boundary, so the fact has to travel.
package wrapdep

import "github.com/deadpoets/secmem"

type KeyPair struct{ Private *secmem.SecureBuffer }

// WithSeed forwards fn to the key's buffer.
func (kp *KeyPair) WithSeed(fn func([]byte) error) error {
	if kp.Private == nil {
		return nil
	}
	return kp.Private.WithBytesErr(fn)
}
