// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Forked into secmem-crypto/internal/bcryptpbkdf from golang.org/x/crypto/blowfish
// v0.56.0 (cipher.go and block.go). Modifications, all for secmem-crypto and
// listed in doc.go: the constructors that allocated a fresh Cipher are
// replaced by initSaltedCipher, which resets a caller-owned Cipher in place;
// the decryption direction and the KeySizeError type are dropped as unused.
// encryptBlock, ExpandKey, expandKeyWithSalt, getNextWord, initCipher and
// Encrypt are verbatim; upstream_identity_test.go checks that against the
// x/crypto the module resolves.

package bcryptpbkdf

// The code is a port of Bruce Schneier's C implementation.
// See https://www.schneier.com/blowfish.html.

// The Blowfish block size in bytes.
const BlockSize = 8

// A Cipher is an instance of Blowfish encryption using a particular key.
// bcrypt_pbkdf keys it afresh for every hash, from the caller's Workspace,
// so the 4 KiB key schedule derived from the passphrase hash never lands on
// the heap.
type Cipher struct {
	p              [18]uint32
	s0, s1, s2, s3 [256]uint32
}

// initSaltedCipher is upstream's NewSaltedCipher with the Cipher supplied by
// the caller instead of allocated: it restores the pristine π tables and
// folds key and salt into the schedule. As upstream, an empty salt degrades
// to the plain key schedule (NewCipher's), and an empty key is a programming
// error. Blowfish's 56-byte key limit does not apply here, for bcrypt
// compatibility, exactly as in NewSaltedCipher.
func initSaltedCipher(c *Cipher, key, salt []byte) {
	if len(key) < 1 {
		panic("bcrypt_pbkdf: empty blowfish key")
	}
	initCipher(c)
	if len(salt) == 0 {
		ExpandKey(key, c)
		return
	}
	expandKeyWithSalt(key, salt, c)
}

// BlockSize returns the Blowfish block size, 8 bytes.
// It is necessary to satisfy the Block interface in the
// package "crypto/cipher".
func (c *Cipher) BlockSize() int { return BlockSize }

// Encrypt encrypts the 8-byte buffer src using the key k
// and stores the result in dst.
// Note that for amounts of data larger than a block,
// it is not safe to just call Encrypt on successive blocks;
// instead, use an encryption mode like CBC (see crypto/cipher/cbc.go).
func (c *Cipher) Encrypt(dst, src []byte) {
	l := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	l, r = encryptBlock(l, r, c)
	dst[0], dst[1], dst[2], dst[3] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
	dst[4], dst[5], dst[6], dst[7] = byte(r>>24), byte(r>>16), byte(r>>8), byte(r)
}

func initCipher(c *Cipher) {
	copy(c.p[0:], p[0:])
	copy(c.s0[0:], s0[0:])
	copy(c.s1[0:], s1[0:])
	copy(c.s2[0:], s2[0:])
	copy(c.s3[0:], s3[0:])
}

// getNextWord returns the next big-endian uint32 value from the byte slice
// at the given position in a circular manner, updating the position.
func getNextWord(b []byte, pos *int) uint32 {
	var w uint32
	j := *pos
	for i := 0; i < 4; i++ {
		w = w<<8 | uint32(b[j])
		j++
		if j >= len(b) {
			j = 0
		}
	}
	*pos = j
	return w
}

// ExpandKey performs a key expansion on the given *Cipher. Specifically, it
// performs the Blowfish algorithm's key schedule which sets up the *Cipher's
// pi and substitution tables for calls to Encrypt. This is used, primarily,
// by the bcrypt package to reuse the Blowfish key schedule during its
// set up. It's unlikely that you need to use this directly.
func ExpandKey(key []byte, c *Cipher) {
	j := 0
	for i := 0; i < 18; i++ {
		// Using inlined getNextWord for performance.
		var d uint32
		for k := 0; k < 4; k++ {
			d = d<<8 | uint32(key[j])
			j++
			if j >= len(key) {
				j = 0
			}
		}
		c.p[i] ^= d
	}

	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.p[i], c.p[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s0[i], c.s0[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s1[i], c.s1[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s2[i], c.s2[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s3[i], c.s3[i+1] = l, r
	}
}

// This is similar to ExpandKey, but folds the salt during the key
// schedule. While ExpandKey is essentially expandKeyWithSalt with an all-zero
// salt passed in, reusing ExpandKey turns out to be a place of inefficiency
// and specializing it here is useful.
func expandKeyWithSalt(key []byte, salt []byte, c *Cipher) {
	j := 0
	for i := 0; i < 18; i++ {
		c.p[i] ^= getNextWord(key, &j)
	}

	j = 0
	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.p[i], c.p[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s0[i], c.s0[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s1[i], c.s1[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s2[i], c.s2[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s3[i], c.s3[i+1] = l, r
	}
}

func encryptBlock(l, r uint32, c *Cipher) (uint32, uint32) {
	xl, xr := l, r
	xl ^= c.p[0]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[1]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[2]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[3]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[4]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[5]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[6]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[7]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[8]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[9]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[10]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[11]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[12]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[13]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[14]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[15]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[16]
	xr ^= c.p[17]
	return xr, xl
}
