package secmemcrypto

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

// TestReduceMod_MatchesMathBig is the differential proof for the
// shift-and-subtract reduction pkcs1DER uses instead of math/big: random
// operands across the size range the parser accepts, plus the edges — x
// below, equal to and one above m, x zero, m one, m a power of two, and
// m at the maximum width — all compared against big.Int.Mod.
func TestReduceMod_MatchesMathBig(t *testing.T) {
	t.Parallel()
	check := func(name string, x, m *big.Int) {
		t.Helper()
		xb, mb := x.Bytes(), m.Bytes()
		dst := make([]byte, len(mb))
		if !reduceMod(dst, xb, mb) {
			t.Fatalf("%s: reduceMod refused len(x)=%d len(m)=%d", name, len(xb), len(mb))
		}
		want := new(big.Int).Mod(x, m).FillBytes(make([]byte, len(mb)))
		if !bytes.Equal(dst, want) {
			t.Fatalf("%s: reduceMod = %x, want %x", name, dst, want)
		}
	}
	randInt := func(bits int) *big.Int {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	one := big.NewInt(1)

	for _, mBits := range []int{1, 7, 8, 9, 63, 64, 65, 127, 128, 129, 1024, 1536, 2048, rsaMaxPrimeBits} {
		for _, xBits := range []int{0, 1, 8, 64, 65, 500, 1024, 2048, 4096, rsaMaxModulusBits} {
			for i := range 4 {
				m := randInt(mBits)
				if m.Sign() == 0 {
					m.SetInt64(1)
				}
				x := randInt(xBits)
				check(big.NewInt(int64(i)).String()+"/random", x, m)
				check("x<m", new(big.Int).Sub(m, one), m)
				check("x==m", m, m)
				check("x==m+1", new(big.Int).Add(m, one), m)
				check("x==2m-1", new(big.Int).Sub(new(big.Int).Lsh(m, 1), one), m)
			}
		}
	}
	// Structured moduli.
	for _, mBits := range []int{8, 64, 1024, rsaMaxPrimeBits} {
		pow2 := new(big.Int).Lsh(one, uint(mBits-1))
		allOnes := new(big.Int).Sub(new(big.Int).Lsh(one, uint(mBits)), one)
		x := randInt(2 * mBits)
		check("power-of-two", x, pow2)
		check("all-ones", x, allOnes)
		check("m=1", x, one)
		check("x=0", new(big.Int), allOnes)
	}
}

// TestReduceMod_Refuses pins the fail-closed inputs: a zero modulus, an
// oversized operand, and a mismatched destination width.
func TestReduceMod_Refuses(t *testing.T) {
	t.Parallel()
	dst := make([]byte, 2)
	if reduceMod(dst, []byte{1}, []byte{0, 0}) {
		t.Error("zero modulus accepted")
	}
	if reduceMod(dst, []byte{1}, nil) {
		t.Error("empty modulus accepted")
	}
	if reduceMod(make([]byte, 1), []byte{1}, []byte{0, 3}) {
		t.Error("mismatched dst width accepted")
	}
	if reduceMod(make([]byte, rsaMaxPrimeBits/8+1), []byte{1}, make([]byte, rsaMaxPrimeBits/8+1)) {
		t.Error("oversized modulus accepted")
	}
	if reduceMod(dst, make([]byte, rsaMaxModulusBits/8+1), []byte{0, 3}) {
		t.Error("oversized x accepted")
	}
}

// TestDecrementBE pins p-1 on the shapes that matter: a borrow chain across
// bytes, a power of two, one, and zero (which has no predecessor).
func TestDecrementBE(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		p, want []byte
		ok      bool
	}{
		{[]byte{0x01, 0x00}, []byte{0x00, 0xff}, true},
		{[]byte{0x80, 0x00, 0x00}, []byte{0x7f, 0xff, 0xff}, true},
		{[]byte{0x01}, []byte{0x00}, true},
		{[]byte{0x00}, []byte{0xff}, false},
		{[]byte{0x00, 0x00}, []byte{0xff, 0xff}, false},
	} {
		dst := make([]byte, len(tc.p))
		if got := decrementBE(dst, tc.p); got != tc.ok || !bytes.Equal(dst, tc.want) {
			t.Errorf("decrementBE(%x) = %x, %v; want %x, %v", tc.p, dst, got, tc.want, tc.ok)
		}
	}
	if decrementBE(make([]byte, 1), []byte{1, 2}) {
		t.Error("length mismatch accepted")
	}
}
