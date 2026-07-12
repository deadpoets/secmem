package secmemcrypto

import (
	"runtime"

	"filippo.io/edwards25519"
)

// WipeScalar overwrites s with the zero scalar.
//
// [edwards25519.Scalar.Set] performs a field-by-field copy of the zero
// scalar's internal representation, which the compiler cannot elide (the
// receiver escapes to the caller). runtime.KeepAlive prevents a future
// compiler or LTO pass from treating s as dead before the Set write
// completes.
func WipeScalar(s *edwards25519.Scalar) {
	if s == nil {
		return
	}
	s.Set(edwards25519.NewScalar())
	runtime.KeepAlive(s)
}
