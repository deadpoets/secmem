// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// x25519ScalarMult is copied verbatim from crypto/ecdh/x25519.go (go1.26)
// for secmem-crypto, with the import of the standard library's internal
// field package replaced by filippo.io/edwards25519/field, the module the
// standard library's copy is vendored from. See doc.go for why, and for the
// one change outside that function.

package x25519

import "filippo.io/edwards25519/field"

// Sizes of an X25519 scalar, point and output, in bytes.
const (
	ScalarSize = 32
	PointSize  = 32
)

// ScalarMult sets dst to scalar × point per RFC 7748 §5, clamping a copy of
// scalar first. Every intermediate — the clamped scalar and the seven field
// elements of the ladder — is a local of x25519ScalarMult, so the caller's
// Scrub window covers them; nothing here allocates, and scalar is not
// retained. The caller rejects an all-zero dst (a low-order point).
func ScalarMult(dst, scalar, point *[32]byte) {
	x25519ScalarMult(dst[:], scalar[:], point[:])
}

func x25519ScalarMult(dst, scalar, point []byte) {
	var e [32]byte

	copy(e[:], scalar[:])
	e[0] &= 248
	e[31] &= 127
	e[31] |= 64

	var x1, x2, z2, x3, z3, tmp0, tmp1 field.Element
	x1.SetBytes(point[:])
	x2.One()
	x3.Set(&x1)
	z3.One()

	swap := 0
	for pos := 254; pos >= 0; pos-- {
		b := e[pos/8] >> uint(pos&7)
		b &= 1
		swap ^= int(b)
		x2.Swap(&x3, swap)
		z2.Swap(&z3, swap)
		swap = int(b)

		tmp0.Subtract(&x3, &z3)
		tmp1.Subtract(&x2, &z2)
		x2.Add(&x2, &z2)
		z2.Add(&x3, &z3)
		z3.Multiply(&tmp0, &x2)
		z2.Multiply(&z2, &tmp1)
		tmp0.Square(&tmp1)
		tmp1.Square(&x2)
		x3.Add(&z3, &z2)
		z2.Subtract(&z3, &z2)
		x2.Multiply(&tmp1, &tmp0)
		tmp1.Subtract(&tmp1, &tmp0)
		z2.Square(&z2)

		z3.Mult32(&tmp1, 121666)
		x3.Square(&x3)
		tmp0.Add(&tmp0, &z3)
		z3.Multiply(&x1, &z2)
		z2.Multiply(&tmp1, &tmp0)
	}

	x2.Swap(&x3, swap)
	z2.Swap(&z3, swap)

	z2.Invert(&z2)
	x2.Multiply(&x2, &z2)
	copy(dst[:], x2.Bytes())
}
