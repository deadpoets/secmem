// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Forked from golang.org/x/crypto/argon2 v0.56.0 for secmem-crypto.

package argon2

import (
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/blake2b"

	"github.com/deadpoets/secmem"
)

// blake2bHash is Argon2's variable-length hash H'(out, in): it writes a
// len(out)-byte digest of in into out.
//
// secmem: upstream streams into blake2b.New/New512 digests, which are heap
// objects whose 128-byte block buffer keeps the tail of the input after Sum
// and after Reset. Here the input is assembled in ws.hashIn (length prefix
// plus in, at most one 1 KiB block) and hashed with the one-shot
// blake2b.Sum512/Sum384/Sum256, whose state is entirely on the stack — and
// the stack is what the enclosing secmem.Scrub erases. The only remaining
// heap digest is the final step for output lengths that are none of 32, 48
// or 64 (see sumTo), which is scrubbed and tripwire-tested.
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
	buffer := &ws.hashState
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
// ≤ 64. The three lengths that have one-shot functions in x/crypto/blake2b
// (which keep the whole digest state on the stack) use them; any other
// length falls back to blake2b.New(n), the heap digest, followed by
// scrubDigest. The returned arrays are stack values; they are wiped here
// as well as being inside the caller's Scrub window.
func sumTo(out, in []byte) {
	switch len(out) {
	case blake2b.Size:
		sum := blake2b.Sum512(in)
		copy(out, sum[:])
		secmem.SecureWipe(sum[:])
	case blake2b.Size384:
		sum := blake2b.Sum384(in)
		copy(out, sum[:])
		secmem.SecureWipe(sum[:])
	case blake2b.Size256:
		sum := blake2b.Sum256(in)
		copy(out, sum[:])
		secmem.SecureWipe(sum[:])
	default:
		h, err := blake2b.New(len(out), nil)
		if err != nil {
			panic("argon2: " + err.Error()) // len(out) outside 1..64: a bug here, not input
		}
		h.Write(in)
		h.Sum(out[:0])
		scrubDigest(h)
	}
}

// scrubDigest zeroes the internal state of an x/crypto/blake2b digest
// through its public interface only.
//
// The digest keeps the unconsumed tail of its input in a 128-byte block
// buffer, and Sum leaves that buffer in place: it finalises a copy. Reset
// restores the chaining value and counters but, for an unkeyed digest,
// does not touch the block buffer either. Write of exactly one full block
// does: with offset > 0 it fills block[offset:] from the new data,
// compresses, then copies the remaining offset bytes over block[:offset];
// with offset == 0 it copies the whole block. Either way the buffer is now
// the zeros written. Reset afterwards puts the chaining value back to the
// IV (the compressed-zeros state is itself input-dependent) and zeroes the
// counters.
//
// This relies on Write's retain-the-last-block behaviour, which is a
// property of the upstream implementation and not of hash.Hash.
// blake2b_scrub_test.go pins it by reading the digest's fields back
// through reflection and fails the moment an x/crypto bump changes them.
func scrubDigest(h hash.Hash) {
	var zeros [blake2b.BlockSize]byte
	h.Write(zeros[:])
	h.Reset()
}
