// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Forked from golang.org/x/crypto/argon2 v0.56.0 for secmem-crypto.

package argon2

import (
	"encoding/binary"

	"golang.org/x/crypto/blake2b"

	"github.com/deadpoets/secmem"
)

// blake2bHash is Argon2's variable-length hash H'(out, in): it writes a
// len(out)-byte digest of in into out.
//
// secmem: upstream streams into blake2b.New/New512 digests, which are heap
// objects whose 128-byte block buffer keeps the tail of the input after Sum
// and after Reset. Here the input is assembled in ws.hashIn (length prefix
// plus in, at most one 1 KiB block) and hashed with one-shot functions
// whose state is entirely on the stack — and the stack is what the
// enclosing secmem.Scrub erases. Every output length goes this way; see
// sumTo.
//
// in must be ws.h0[:] or ws.block0[:]; anything longer than one block is a
// bug in this package, not a caller error.
func (ws *Workspace) blake2bHash(out, in []byte) {
	if len(in) > len(ws.hashIn)-4 {
		panic("argon2: H' input exceeds one block")
	}
	outLen := len(out)
	//nolint:gosec // G115: len(out) is bounded by the caller to uint32 range.
	binary.LittleEndian.PutUint32(ws.hashIn[:4], uint32(outLen))
	n := 4 + copy(ws.hashIn[4:], in)
	msg := ws.hashIn[:n]

	if outLen <= blake2b.Size {
		sumTo(out, msg)
		secmem.SecureWipe(msg)
		return
	}

	// τ > 64: V1 = H^64(τ ‖ in); V_i = H^64(V_{i-1}); 32 bytes of each are
	// output, the last block is H^{τ-32r}(V_r) in full.
	buffer := ws.hashState
	*buffer = blake2b.Sum512(msg)
	secmem.SecureWipe(msg)
	copy(out, buffer[:32])
	out = out[32:]
	for len(out) > blake2b.Size {
		*buffer = blake2b.Sum512(buffer[:])
		copy(out, buffer[:32])
		out = out[32:]
	}
	// Upstream sizes the final digest as outLen-32*r with
	// r = ⌈outLen/32⌉-2, which is exactly len(out) at this point.
	sumTo(out, buffer[:])
	secmem.SecureWipe(buffer[:])
}

// sumTo writes a len(out)-byte BLAKE2b digest of in into out, 1 ≤ len(out)
// ≤ 64, with the whole digest state on the stack. The three lengths that
// have one-shot functions in x/crypto/blake2b use them (assembly where the
// CPU has it); every other length goes through the forked portable
// finalisation in blake2b_generic.go, which is the same computation with
// the same parameter block and no heap object. The returned arrays are
// stack values; they are wiped here as well as being inside the caller's
// Scrub window.
func sumTo(out, in []byte) {
	var sum [blake2b.Size]byte
	switch n := len(out); n {
	case blake2b.Size:
		sum = blake2b.Sum512(in)
	case blake2b.Size384:
		s := blake2b.Sum384(in)
		copy(sum[:], s[:])
		secmem.SecureWipe(s[:])
	case blake2b.Size256:
		s := blake2b.Sum256(in)
		copy(sum[:], s[:])
		secmem.SecureWipe(s[:])
	default:
		if n < 1 || n > blake2b.Size {
			panic("argon2: H' digest length out of range") // a bug here, not input
		}
		checkSum(&sum, n, in)
	}
	copy(out, sum[:len(out)])
	secmem.SecureWipe(sum[:])
}
