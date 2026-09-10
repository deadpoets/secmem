// modreduce.go computes x mod m for the CRT exponents an OpenSSH RSA file
// omits, without math/big. math/big's division scratch is a sync.Pool-backed
// stack (nat.go, stackPool) that is returned unwiped: limbs derived from d,
// p and q would sit in a pooled object that stays reachable — and so is not
// erased even by runtime/secret — until the pool's victim cache drops it.
// The arithmetic here is a shift-and-subtract reduction over fixed-size
// stack arrays inside the caller's Scrub window, with every array wiped
// before return. It is slow by big-integer standards (one conditional
// subtraction per bit of x) and that is fine: it runs once per parsed key,
// and a 2048-bit d against a 1024-bit p-1 is about forty thousand limb
// operations.
package secmemcrypto

import (
	"math/bits"
	"unsafe"

	"github.com/deadpoets/secmem"
)

// modReduceLimbs is the working width in 64-bit limbs: enough for a modulus
// of rsaMaxPrimeBits plus one limb, so that 2r (r < m) never overflows.
const modReduceLimbs = rsaMaxPrimeBits/64 + 1

// reduceMod writes x mod m into dst as a big-endian magnitude the width of
// m (leading zeros included) and reports whether it did. x and m are
// big-endian magnitudes; m must be non-zero and at most rsaMaxPrimeBits
// wide, x at most rsaMaxModulusBits, and len(dst) must equal len(m).
// Anything else returns false with dst untouched.
//
// The loop count depends only on the lengths of x and m, which the key's
// size already reveals; no branch depends on a value. The working arrays
// live on the stack and are wiped before return.
func reduceMod(dst, x, m []byte) bool {
	if len(m) == 0 || len(m)*8 > rsaMaxPrimeBits || len(x)*8 > rsaMaxModulusBits || len(dst) != len(m) {
		return false
	}
	var mw, r, t [modReduceLimbs]uint64
	defer func() {
		secmem.SecureWipe(limbBytes(&mw))
		secmem.SecureWipe(limbBytes(&r))
		secmem.SecureWipe(limbBytes(&t))
	}()
	if !setLimbsBE(&mw, m) {
		return false
	}
	// Work on nl limbs: one more than m needs, since r < 2m. The length
	// check above bounds nl by modReduceLimbs.
	nl := (len(m)+7)/8 + 1
	mws, rs, ts := mw[:nl], r[:nl], t[:nl]
	nonzero := uint64(0)
	for _, w := range mws {
		nonzero |= w
	}
	if nonzero == 0 {
		return false
	}

	for _, b := range x {
		for bit := 7; bit >= 0; bit-- {
			// r = 2r + bit
			carry := uint64(b>>uint(bit)) & 1
			for i := range rs {
				rs[i], carry = rs[i]<<1|carry, rs[i]>>63
			}
			// t = r - m; keep t iff it did not borrow (r >= m).
			var borrow uint64
			for i := range ts {
				ts[i], borrow = bits.Sub64(rs[i], mws[i], borrow)
			}
			mask := borrow - 1 // all ones when borrow == 0
			for i := range rs {
				rs[i] = ts[i]&mask | rs[i]&^mask
			}
		}
	}
	limbsToBE(dst, &r)
	return true
}

// setLimbsBE loads a big-endian magnitude into little-endian limbs. It
// reports false when b does not fit.
func setLimbsBE(w *[modReduceLimbs]uint64, b []byte) bool {
	if (len(b)+7)/8 > len(w) {
		return false
	}
	for i := range w {
		w[i] = 0
	}
	for i := 0; i < len(b); i++ {
		byteIdx := len(b) - 1 - i
		w[i/8] |= uint64(b[byteIdx]) << (8 * uint(i%8))
	}
	return true
}

// limbsToBE writes the low len(dst) bytes of w big-endian into dst.
func limbsToBE(dst []byte, w *[modReduceLimbs]uint64) {
	for i := range dst {
		byteIdx := len(dst) - 1 - i
		dst[byteIdx] = byte(w[i/8] >> (8 * uint(i%8))) //nolint:gosec // G115: the low byte is the point
	}
}

// decrementBE writes p-1 into dst (same length as p) for a big-endian p >= 1
// and reports whether it did; false for p == 0 or a length mismatch.
func decrementBE(dst, p []byte) bool {
	if len(dst) != len(p) {
		return false
	}
	borrow := uint16(1)
	for i := len(p) - 1; i >= 0; i-- {
		v := uint16(p[i]) - borrow
		dst[i] = byte(v) //nolint:gosec // G115: the low byte is the point; the borrow is read from bit 15
		borrow = v >> 15 // 1 iff the subtraction wrapped
	}
	return borrow == 0
}

// limbBytes aliases a limb array as a byte slice so it can be wiped with
// the cache-flushing wipe; no foreign memory is dereferenced.
func limbBytes(w *[modReduceLimbs]uint64) []byte {
	//nolint:gosec // G103: audited — a view over the caller's own array.
	return unsafe.Slice((*byte)(unsafe.Pointer(w)), len(w)*8)
}
