package secmemcrypto

// pbkdf2_inplace.go is PBKDF2 (RFC 8018 §5.2) over hmac_inplace.go's
// one-shot hashes, for the PKCS#8 PBES2 parser in pbes2.go. The standard
// library's crypto/pbkdf2.Key takes the password as a string — a heap copy
// of the passphrase nothing can wipe — and returns a heap slice, and
// x/crypto/pbkdf2 has the same shape; both also keep crypto/hmac's two
// key-equivalent digest states on the heap. This one keeps every
// intermediate — the padded keys, the running T block, the current U, the
// inner digest and the message buffers — in a region the caller owns,
// which the parser takes from a locked scratch buffer for the call.

import (
	"encoding/binary"

	"github.com/deadpoets/secmem"
)

// pbkdf2RegionSize is the working region pbkdf2Compute needs for a salt of
// saltLen bytes: the running T block, the current U, the pre-hashed
// password, the two padded-key message buffers (ipad || U and
// opad || inner), and hmacInPlace's scratch for the first U of each block,
// whose message is salt || INT(i).
func pbkdf2RegionSize(h inPlaceHash, saltLen int) int {
	block := h.block()
	return 3*maxHashSize + 2*(block+maxHashSize) + block + max(saltLen+4, h.size())
}

// pbkdf2Compute derives len(dst) bytes into dst with iter iterations of
// HMAC-h over password and salt. region must be at least
// pbkdf2RegionSize(h, len(salt)) bytes and is wiped before return; iter
// must be at least 1. It follows hkdfCompute's shape: one region, named
// sub-slices, and no closure capturing an array (a captured array is moved
// to the heap, which is what this file exists to avoid).
//
// The first U of each output block is hmacInPlace over salt || INT(i).
// The remaining iter-1 are the loop that costs: HMAC's two hashes with the
// padded key in front. The two padded keys are laid down once, each at the
// head of its own message buffer, so an iteration is one copy of the
// previous U behind ipad, a hash into the slot behind opad, and a hash of
// that — two one-shots and no per-call wiping, which hmacInPlace would do
// three times a call. A password longer than the block is hashed once up
// front, as RFC 2104 requires. There is no pre-absorbed key state to carry
// between iterations, as crypto/hmac keeps — that state is exactly the heap
// object this file avoids — so each hash absorbs its pad block again; the
// cost at the largest count the parser accepts is about a second.
func pbkdf2Compute(h inPlaceHash, dst, region, password, salt []byte, iter int) {
	pbkdf2Run(h, dst, region, password, salt, iter)
	secmem.SecureWipe(region)
}

// pbkdf2Run is pbkdf2Compute without the final wipe: the derivation, leaving
// its working state in region. Only pbkdf2Compute calls it; it is separate
// so the test of the wipe can first see what there is to wipe.
func pbkdf2Run(h inPlaceHash, dst, region, password, salt []byte, iter int) {
	size, block := h.size(), h.block()
	t := region[:size]
	u := region[maxHashSize : maxHashSize+size]
	hashed := region[2*maxHashSize : 2*maxHashSize+size]
	inStart, outStart := 3*maxHashSize, 3*maxHashSize+block+maxHashSize
	inMsg := region[inStart : inStart+block+size]    // ipad || U
	outMsg := region[outStart : outStart+block+size] // opad || inner
	scratch := region[outStart+block+maxHashSize:]
	if len(password) > block {
		h.sum(hashed, password)
		password = hashed
	}
	ipad, opad := inMsg[:block], outMsg[:block]
	copy(ipad, password)
	copy(opad, password)
	for i := range block {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}
	var ctr [4]byte // the block index: not secret
	for off, i := 0, uint32(1); off < len(dst); i++ {
		binary.BigEndian.PutUint32(ctr[:], i)
		hmacInPlace(h, u, scratch, password, salt, ctr[:])
		copy(t, u)
		for j := 1; j < iter; j++ {
			copy(inMsg[block:], u)
			h.sum(outMsg[block:], inMsg)
			h.sum(u, outMsg)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		off += copy(dst[off:], t)
	}
}
