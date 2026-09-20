package secmemcrypto

import (
	"crypto/subtle"
	"encoding/binary"
	"math/bits"
	"unsafe"

	//lint:ignore SA1019 the successor lives in x/crypto/internal, which is
	// not importable; this wrapper is the only public Poly1305 in x/crypto.
	"golang.org/x/crypto/poly1305" //nolint:staticcheck // see above

	"github.com/deadpoets/secmem"
)

// chacha20-poly1305@openssh.com, as OpenSSH applies it to a private-key
// file. Two things differ from the IETF AEAD of RFC 8439, so neither
// crypto/cipher's AEAD nor x/crypto/chacha20poly1305 implements this
// construction:
//
//   - The key is 64 bytes: the first half encrypts the payload, the second
//     encrypts packet lengths on the wire. A private-key file has no length
//     field, so the second half is derived and never used.
//   - It is the original ChaCha20 (a 64-bit counter and a 64-bit nonce),
//     not the IETF variant (32-bit counter, 96-bit nonce). The nonce is the
//     packet sequence number, which is zero for a key file. The Poly1305
//     key is the first 32 bytes of the keystream at counter 0, and the
//     payload is encrypted from counter 1.
//
// The core below is written out rather than taken from x/crypto/chacha20
// for the reason openssh_cipher.go gives for AES: that package's Cipher is
// a heap object holding the key and a keystream buffer, and nothing
// exported clears it. Here the state, the keystream block and the Poly1305
// key are locals of a call that runs inside a Scrub window, wiped before it
// returns. chachaBlock is pinned to x/crypto's implementation by a
// differential test and to RFC 8439's vector by a known-answer test.

const (
	chachaBlockSize = 64
	chachaKeyLen    = 32 // one of the two halves of the OpenSSH key
	chachaTagLen    = 16
	// chachaOpenSSHKeyLen is what the KDF must produce: payload key then
	// length key.
	chachaOpenSSHKeyLen = 2 * chachaKeyLen
)

// chachaQR is the ChaCha quarter-round on four words of the state.
func chachaQR(x *[16]uint32, a, b, c, d int) {
	x[a] += x[b]
	x[d] = bits.RotateLeft32(x[d]^x[a], 16)
	x[c] += x[d]
	x[b] = bits.RotateLeft32(x[b]^x[c], 12)
	x[a] += x[b]
	x[d] = bits.RotateLeft32(x[d]^x[a], 8)
	x[c] += x[d]
	x[b] = bits.RotateLeft32(x[b]^x[c], 7)
}

// chachaBlock writes the keystream block for counter into out.
func chachaBlock(out *[chachaBlockSize]byte, key *[chachaKeyLen]byte, nonce *[8]byte, counter uint64) {
	var s [16]uint32
	s[0], s[1], s[2], s[3] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 // "expand 32-byte k"
	for i := range 8 {
		s[4+i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	//nolint:gosec // G115: splitting the 64-bit counter into two words IS the
	// algorithm; the truncation is intended.
	s[12] = uint32(counter)
	s[13] = uint32(counter >> 32) //nolint:gosec // G115: as above, the high half.
	s[14] = binary.LittleEndian.Uint32(nonce[0:])
	s[15] = binary.LittleEndian.Uint32(nonce[4:])

	x := s
	for range 10 { // 20 rounds: a column round and a diagonal round each pass
		chachaQR(&x, 0, 4, 8, 12)
		chachaQR(&x, 1, 5, 9, 13)
		chachaQR(&x, 2, 6, 10, 14)
		chachaQR(&x, 3, 7, 11, 15)
		chachaQR(&x, 0, 5, 10, 15)
		chachaQR(&x, 1, 6, 11, 12)
		chachaQR(&x, 2, 7, 8, 13)
		chachaQR(&x, 3, 4, 9, 14)
	}
	for i := range 16 {
		binary.LittleEndian.PutUint32(out[4*i:], x[i]+s[i])
	}
	// s and x hold the key as words. A plain zeroing loop over them is a
	// dead store the compiler may drop, so they are wiped through
	// SecureWipe over a byte view of each — the same shape the Argon2 fork
	// uses for its block words, and an allocation test pins that taking
	// their address does not move them off the stack.
	secmem.SecureWipe(chachaWords(&x))
	secmem.SecureWipe(chachaWords(&s))
}

// chachaWords views a state array as the bytes SecureWipe takes. The array
// is the caller's local; the view never outlives it.
func chachaWords(s *[16]uint32) []byte {
	//nolint:gosec // G103: a byte view of the caller's own array, so that
	// SecureWipe — which takes bytes — can zero words a plain loop would let
	// the compiler drop. Nothing foreign is addressed and the view does not
	// escape (TestChaCha_NoHeap pins that).
	return unsafe.Slice((*byte)(unsafe.Pointer(s)), unsafe.Sizeof(*s))
}

// chachaXOR XORs the keystream from counter onwards into dst from src, which
// may be the same slice. len(dst) must be at least len(src).
func chachaXOR(key *[chachaKeyLen]byte, nonce *[8]byte, counter uint64, dst, src []byte) {
	var ks [chachaBlockSize]byte
	for len(src) > 0 {
		chachaBlock(&ks, key, nonce, counter)
		n := min(len(src), chachaBlockSize)
		subtle.XORBytes(dst[:n], src[:n], ks[:n])
		src, dst = src[n:], dst[n:]
		counter++
	}
	secmem.SecureWipe(ks[:])
}

// opensshChaChaOpen verifies tag over src and, if it matches, decrypts src
// into dst (which may be src). keyMaterial is the 64 bytes the KDF produced.
// A private-key file authenticates the ciphertext alone: there is no
// additional data, and the sequence number is zero.
//
// It reports whether the tag verified. A mismatch is what a wrong
// passphrase looks like here — unlike the AES modes, where the wrong key
// decrypts to garbage and the format's check integers catch it — so the
// caller turns it into the same error.
func opensshChaChaOpen(dst, src, tag, keyMaterial []byte) bool {
	var key [chachaKeyLen]byte
	var nonce [8]byte // the sequence number of a key file's only "packet"
	var polyKey [chachaKeyLen]byte
	var block [chachaBlockSize]byte
	var want [chachaTagLen]byte
	defer func() {
		secmem.SecureWipe(key[:])
		secmem.SecureWipe(polyKey[:])
		secmem.SecureWipe(block[:])
		secmem.SecureWipe(want[:])
	}()

	copy(key[:], keyMaterial[:chachaKeyLen])
	chachaBlock(&block, &key, &nonce, 0)
	copy(polyKey[:], block[:chachaKeyLen])

	poly1305.Sum(&want, src, &polyKey)
	if subtle.ConstantTimeCompare(want[:], tag) != 1 {
		return false
	}
	chachaXOR(&key, &nonce, 1, dst, src)
	return true
}
