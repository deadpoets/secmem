package secmemcrypto

import (
	"crypto/cipher"

	"github.com/deadpoets/secmem"
)

// OpenSSH's two AES modes, written out over a cipher.Block instead of taken
// from crypto/cipher. cipher.NewCTR and cipher.NewCBCDecrypter each copy the
// Block by value into a fresh heap object — a second copy of the round keys
// that nothing can reach — and CTR keeps a keystream buffer of its own. A
// few dozen lines here leave exactly one heap object holding the schedule,
// the Block itself, which aeswipe.go clears. Both are tested against
// crypto/cipher byte for byte.
//
// The counter, keystream and chaining blocks are the caller's scratch, not
// locals: a slice handed to an interface method escapes, so a local array
// here would be a heap allocation holding keystream (the allocation proof
// caught exactly that). The callers pass a slice of their locked workspace.

// cipherScratch is the scratch either mode needs: two AES blocks.
const cipherScratch = 2 * opensshAESBlock

// ctrXOR applies AES-CTR with the given IV as the initial counter, XORing
// the keystream into dst from src (dst and src may be the same slice).
// len(src) need not be a block multiple. scratch (at least cipherScratch
// bytes) holds the counter and keystream blocks and is wiped before return.
func ctrXOR(b cipher.Block, iv, dst, src, scratch []byte) {
	ctr, ks := scratch[:opensshAESBlock], scratch[opensshAESBlock:cipherScratch]
	copy(ctr, iv)
	for len(src) > 0 {
		b.Encrypt(ks, ctr)
		n := min(len(src), len(ks))
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ ks[i]
		}
		for i := len(ctr) - 1; i >= 0; i-- {
			ctr[i]++
			if ctr[i] != 0 {
				break
			}
		}
		src, dst = src[n:], dst[n:]
	}
	secmem.SecureWipe(scratch[:cipherScratch])
}

// cbcDecrypt applies AES-CBC decryption from src into dst, which must be
// distinct slices of the same block-multiple length (the ciphertext stays
// in src, so the chaining value is read from there). scratch (at least
// cipherScratch bytes) holds the chaining block and is wiped before return.
func cbcDecrypt(b cipher.Block, iv, dst, src, scratch []byte) {
	if len(src)%b.BlockSize() != 0 || len(dst) < len(src) {
		panic("secmemcrypto: cbcDecrypt: input is not a block multiple")
	}
	prev := scratch[:opensshAESBlock]
	copy(prev, iv)
	for len(src) > 0 {
		b.Decrypt(dst[:opensshAESBlock], src[:opensshAESBlock])
		for i := range prev {
			dst[i] ^= prev[i]
		}
		copy(prev, src[:opensshAESBlock])
		src, dst = src[opensshAESBlock:], dst[opensshAESBlock:]
	}
	secmem.SecureWipe(scratch[:cipherScratch])
}
