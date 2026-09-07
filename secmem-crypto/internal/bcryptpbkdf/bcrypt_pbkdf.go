// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Forked into secmem-crypto/internal/bcryptpbkdf from
// golang.org/x/crypto/ssh/internal/bcrypt_pbkdf v0.56.0. Modifications, all
// for secmem-crypto and listed in doc.go: the working state moves into a
// caller-owned Workspace, the SHA-512 steps are one-shots, and the output
// goes into a caller-supplied slice. bcryptHash's algorithm is unchanged;
// its Cipher is now re-keyed in place.

package bcryptpbkdf

import (
	"crypto/sha512"
	"errors"
	"unsafe"

	"github.com/deadpoets/secmem"
)

const blockSize = 32

// saltReserve is the room a Workspace keeps for salt || counter, the input
// of the per-block SHA-512. OpenSSH salts are 16 bytes; a longer salt (up to
// upstream's 1 MiB bound) spills to a heap buffer that Derive wipes.
const saltReserve = 64

// Workspace is every byte of state a derivation touches, so the caller can
// put it where it wants (a stack frame, a SecureBuffer) and wipe it when done.
// Its fields are the locals upstream's Key and bcryptHash allocate: the
// Blowfish key schedule, the two SHA-512 digests, bcrypt's 32-byte hash and
// the per-block accumulator, plus the salt reserve.
type Workspace struct {
	c       Cipher
	shapass [sha512.Size]byte
	shasalt [sha512.Size]byte
	tmp     [blockSize]byte
	out     [blockSize]byte
	saltIn  [saltReserve]byte
}

// Size is the number of bytes a Workspace occupies; Bind wants at least this
// many.
const Size = int(unsafe.Sizeof(Workspace{}))

// NewWorkspace returns a heap Workspace. Wipe it after use.
func NewWorkspace() *Workspace { return new(Workspace) }

// Bind overlays a Workspace on mem, which must be at least Size bytes and
// 8-byte aligned (a SecureBuffer's mapping is page-aligned). The Workspace
// aliases mem: wiping either wipes both.
func Bind(mem []byte) *Workspace {
	if len(mem) < Size {
		panic("bcrypt_pbkdf: workspace region too small")
	}
	//nolint:gosec // G103: audited — the region is the caller's, and the alignment is checked before any field is touched.
	if uintptr(unsafe.Pointer(&mem[0]))%8 != 0 {
		panic("bcrypt_pbkdf: workspace region not 8-byte aligned")
	}
	//nolint:gosec // G103: audited — same region, bounds checked above.
	return (*Workspace)(unsafe.Pointer(&mem[0]))
}

// Wipe zeroes the whole Workspace with secmem's cache-flushing wipe.
func (ws *Workspace) Wipe() {
	//nolint:gosec // G103: audited — a byte view of the Workspace itself, exactly Size bytes.
	secmem.SecureWipe(unsafe.Slice((*byte)(unsafe.Pointer(ws)), Size))
}

// Errors for the input bounds upstream's Key enforces, plus the empty output.
var (
	ErrRounds   = errors.New("bcrypt_pbkdf: number of rounds is too small")
	ErrPassword = errors.New("bcrypt_pbkdf: empty password")
	ErrSalt     = errors.New("bcrypt_pbkdf: bad salt length")
	ErrKeyLen   = errors.New("bcrypt_pbkdf: keyLen is too large")
	ErrOutput   = errors.New("bcrypt_pbkdf: empty output")
)

// Derive computes bcrypt_pbkdf(password, salt, rounds) into out, whose
// length is the key length (1 to 1024 bytes), using ws for every piece of
// working state. The output is byte-identical to upstream's Key for the same
// inputs. password and salt are only read. ws is left holding the last
// state the derivation used; the caller wipes it.
func Derive(out, password, salt []byte, rounds int, ws *Workspace) error {
	if rounds < 1 {
		return ErrRounds
	}
	if len(password) == 0 {
		return ErrPassword
	}
	if len(salt) == 0 || len(salt) > 1<<20 {
		return ErrSalt
	}
	if len(out) == 0 {
		return ErrOutput
	}
	if len(out) > 1024 {
		return ErrKeyLen
	}
	if ws == nil {
		panic("bcrypt_pbkdf: nil workspace")
	}

	// salt || counter must be contiguous for the one-shot hash. Upstream
	// wrote them in two calls to a streaming digest; here they share the
	// reserve, or a wiped heap buffer for a salt the reserve cannot hold.
	saltIn := ws.saltIn[:]
	if len(salt)+4 > saltReserve {
		saltIn = make([]byte, len(salt)+4)
		defer secmem.SecureWipe(saltIn)
	}
	derive(out, password, salt, rounds, ws, saltIn)
	return nil
}

// derive is Derive after validation, with the salt || counter buffer chosen
// by the caller (the test drives both the reserve and the spill path).
func derive(out, password, salt []byte, rounds int, ws *Workspace, saltIn []byte) {
	keyLen := len(out)
	numBlocks := (keyLen + blockSize - 1) / blockSize

	ws.shapass = sha512.Sum512(password)

	saltIn = saltIn[:len(salt)+4]
	copy(saltIn, salt)
	cnt := saltIn[len(salt):]
	for block := 1; block <= numBlocks; block++ {
		cnt[0] = byte(block >> 24)
		cnt[1] = byte(block >> 16)
		cnt[2] = byte(block >> 8)
		cnt[3] = byte(block)
		ws.shasalt = sha512.Sum512(saltIn)
		bcryptHash(&ws.tmp, ws.shapass[:], ws.shasalt[:], &ws.c)

		ws.out = ws.tmp
		for i := 2; i <= rounds; i++ {
			ws.shasalt = sha512.Sum512(ws.tmp[:])
			bcryptHash(&ws.tmp, ws.shapass[:], ws.shasalt[:], &ws.c)
			for j := range ws.out {
				ws.out[j] ^= ws.tmp[j]
			}
		}

		// Upstream interleaves every block's 32 bytes across a
		// numBlocks*32 buffer and truncates to keyLen; writing only the
		// indices below keyLen is the same bytes without the buffer.
		for i, v := range ws.out {
			if idx := i*numBlocks + (block - 1); idx < keyLen {
				out[idx] = v
			}
		}
	}
}

var magic = []byte("OxychromaticBlowfishSwatDynamite")

// bcryptHash is upstream's, with the Cipher supplied by the caller and
// re-keyed in place instead of allocated per call.
func bcryptHash(out *[blockSize]byte, shapass, shasalt []byte, c *Cipher) {
	initSaltedCipher(c, shapass, shasalt)
	for i := 0; i < 64; i++ {
		ExpandKey(shasalt, c)
		ExpandKey(shapass, c)
	}
	copy(out[:], magic)
	for i := 0; i < 32; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(out[i:i+8], out[i:i+8])
		}
	}
	// Swap bytes due to different endianness.
	for i := 0; i < 32; i += 4 {
		out[i+3], out[i+2], out[i+1], out[i] = out[i], out[i+1], out[i+2], out[i+3]
	}
}
