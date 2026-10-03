package secmemcrypto

// scrypt_inplace.go is scrypt (RFC 7914 §6) for the PKCS#8 PBES2 parser in
// pbes2.go: this module's in-place PBKDF2 either side of the memory-hard
// step of internal/scrypt, all of it in one region the caller owns.
// x/crypto/scrypt.Key allocates V — 128·r·N bytes, 16 MiB at the cost
// openssl pkcs8 -scrypt writes — and its X and Y blocks on the heap, runs
// both PBKDF2 calls through heap HMAC states, returns a heap slice and
// clears none of it. Here V, X, Y, the Salsa20/8 chaining block, B and
// PBKDF2's working state are sub-slices of a region the parser takes from a
// locked scratch buffer for the call.

import (
	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/secmem-crypto/internal/scrypt"
)

// scryptRegionSize is the working region scryptCompute needs for a salt of
// saltLen bytes and the cost parameters n, r and p: internal/scrypt's
// working memory (V, X, Y and the chaining block), B — p blocks of 128·r
// bytes — and PBKDF2's region, sized for the larger of its two salts: the
// caller's, and B. That is 128·r·(n + 2·p + 2) bytes plus a fixed part of
// under 2 KiB; the caller has bounded the parameters (readScryptParams), so
// nothing here overflows.
func scryptRegionSize(saltLen, n, r, p int) int {
	b := p * scrypt.BlockSize(r)
	return scrypt.WorkSize(n, r) + b + pbkdf2RegionSize(hashSHA256, max(saltLen, b))
}

// scryptCompute derives len(dst) bytes into dst with scrypt over password
// and salt at cost n, r, p. region must be at least
// scryptRegionSize(len(salt), n, r, p) bytes and start 4-byte aligned (the
// start of a SecureBuffer's mapping is), and is wiped before return. n must
// be a power of two greater than 1 and r and p at least 1: internal/scrypt
// panics otherwise, and the parser has refused such a file by then.
//
// The three steps are RFC 7914 §6's: B = PBKDF2-HMAC-SHA256(P, S, 1,
// p·128·r); each of B's p blocks through scryptROMix, in sequence; DK =
// PBKDF2-HMAC-SHA256(P, B, 1, dkLen). The second PBKDF2's salt is B, which
// is why its region is sized from B's length and not from a file's salt.
func scryptCompute(dst, region, password, salt []byte, n, r, p int) {
	workLen, bLen := scrypt.WorkSize(n, r), p*scrypt.BlockSize(r)
	work := region[:workLen]
	b := region[workLen : workLen+bLen]
	kdf := region[workLen+bLen:]
	pbkdf2Compute(hashSHA256, b, kdf[:pbkdf2RegionSize(hashSHA256, len(salt))], password, salt, 1)
	scrypt.Mix(b, n, r, work)
	pbkdf2Compute(hashSHA256, dst, kdf[:pbkdf2RegionSize(hashSHA256, bLen)], password, b, 1)
	// PBKDF2 wiped its own region each time; V, X, Y, the chaining block
	// and B are what is left.
	secmem.SecureWipe(region[:workLen+bLen])
}
