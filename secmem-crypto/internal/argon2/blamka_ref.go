// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Forked from golang.org/x/crypto/argon2 v0.56.0 for secmem-crypto.
// processBlockGeneric lives here rather than in blamka_generic.go because
// this is the only build that uses it; its one change from upstream is
// that the temporary block comes from the caller (the lane scratch)
// instead of the stack.

//go:build !amd64 || purego || !gc

package argon2

func processBlockGeneric(out, in1, in2, t *block, xor bool) {
	for i := range t {
		t[i] = in1[i] ^ in2[i]
	}
	for i := 0; i < blockLength; i += 16 {
		blamkaGeneric(
			&t[i+0], &t[i+1], &t[i+2], &t[i+3],
			&t[i+4], &t[i+5], &t[i+6], &t[i+7],
			&t[i+8], &t[i+9], &t[i+10], &t[i+11],
			&t[i+12], &t[i+13], &t[i+14], &t[i+15],
		)
	}
	for i := 0; i < blockLength/8; i += 2 {
		blamkaGeneric(
			&t[i], &t[i+1], &t[16+i], &t[16+i+1],
			&t[32+i], &t[32+i+1], &t[48+i], &t[48+i+1],
			&t[64+i], &t[64+i+1], &t[80+i], &t[80+i+1],
			&t[96+i], &t[96+i+1], &t[112+i], &t[112+i+1],
		)
	}
	if xor {
		for i := range t {
			out[i] ^= in1[i] ^ in2[i] ^ t[i]
		}
	} else {
		for i := range t {
			out[i] = in1[i] ^ in2[i] ^ t[i]
		}
	}
}

func processBlock(out, in1, in2 *block, s *laneScratch) {
	processBlockGeneric(out, in1, in2, &s.tmp, false)
}

func processBlockXOR(out, in1, in2 *block, s *laneScratch) {
	processBlockGeneric(out, in1, in2, &s.tmp, true)
}
