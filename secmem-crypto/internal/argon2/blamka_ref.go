// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Forked from golang.org/x/crypto/argon2 v0.56.0 for secmem-crypto.

//go:build !amd64 || purego || !gc

package argon2

func processBlock(out, in1, in2 *block, s *laneScratch) {
	processBlockGeneric(out, in1, in2, &s.tmp, false)
}

func processBlockXOR(out, in1, in2 *block, s *laneScratch) {
	processBlockGeneric(out, in1, in2, &s.tmp, true)
}
