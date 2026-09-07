package argon2

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// TestSumTo_MatchesNew pins that every length 1..64 through sumTo — the
// x/crypto one-shots for 32/48/64 and the forked portable finalisation for
// the rest — equals x/crypto's blake2b.New(n) digest of the same input,
// for inputs on both sides of the 128-byte block boundary (H0's input is
// 72 bytes, H' inputs are 76 or 1028).
func TestSumTo_MatchesNew(t *testing.T) {
	for _, in := range [][]byte{
		[]byte("short"),
		bytes.Repeat([]byte{0x5a}, 72),
		bytes.Repeat([]byte{0x5a}, 128),
		bytes.Repeat([]byte{0x5a}, 129),
		bytes.Repeat([]byte{0x5a}, 1028),
	} {
		for n := 1; n <= 64; n++ {
			got := make([]byte, n)
			sumTo(got, in)
			h, _ := blake2b.New(n, nil)
			h.Write(in)
			if want := h.Sum(nil); !bytes.Equal(got, want) {
				t.Errorf("len(in)=%d n=%d: sumTo %x, New %x", len(in), n, got, want)
			}
		}
	}
}
