// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Forked from golang.org/x/crypto/argon2 v0.56.0 for secmem-crypto.
// blamka_amd64.s is byte-identical to upstream.

//go:build amd64 && gc && !purego

package argon2

import "golang.org/x/sys/cpu"

func init() {
	useSSE4 = cpu.X86.HasSSE41
}

//go:noescape
func mixBlocksSSE2(out, a, b, c *block)

//go:noescape
func xorBlocksSSE2(out, a, b, c *block)

//go:noescape
func blamkaSSE4(b *block)

// processBlockSSE is upstream's function with the temporary t hoisted into
// the lane scratch. Upstream computed t = in1 ^ in2 ^ t with t a freshly
// zeroed stack local; s.tmp is reused across blocks, so the constant
// zeroBlock takes that fourth operand instead. The pre-SSE4.1 fallback is
// the portable implementation rather than upstream's inlined copy of it,
// so there is one generic blamka to keep correct instead of two.
func processBlockSSE(out, in1, in2 *block, s *laneScratch, xor bool) {
	if !useSSE4 {
		processBlockGeneric(out, in1, in2, &s.tmp, xor)
		return
	}
	t := &s.tmp
	mixBlocksSSE2(t, in1, in2, &zeroBlock)
	blamkaSSE4(t)
	if xor {
		xorBlocksSSE2(out, in1, in2, t)
	} else {
		mixBlocksSSE2(out, in1, in2, t)
	}
}

func processBlock(out, in1, in2 *block, s *laneScratch) {
	processBlockSSE(out, in1, in2, s, false)
}

func processBlockXOR(out, in1, in2 *block, s *laneScratch) {
	processBlockSSE(out, in1, in2, s, true)
}
