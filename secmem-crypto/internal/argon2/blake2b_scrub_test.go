package argon2

import (
	"bytes"
	"reflect"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// blake2bDigestMirror is x/crypto/blake2b's unexported digest struct,
// field for field, at v0.56.0. scrubDigest's guarantee rests on that
// layout and on Write's retain-the-last-block behaviour; this file is the
// tripwire that turns a change in either into a red run instead of a
// silent regression, the same discipline rsa_wipe_tripwire_test.go applies
// to the stdlib reflection helpers.
type blake2bDigestMirror struct {
	h      [8]uint64
	c      [2]uint64
	size   int
	block  [blake2b.BlockSize]byte
	offset int
	key    [blake2b.BlockSize]byte
	keyLen int
}

func mirrorDigest(t *testing.T, h interface{}) *blake2bDigestMirror {
	t.Helper()
	v := reflect.ValueOf(h)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		t.Fatalf("blake2b.New returned %T, not a pointer to a struct", h)
	}
	actual, mirror := v.Elem().Type(), reflect.TypeOf(blake2bDigestMirror{})
	if actual.NumField() != mirror.NumField() || actual.Size() != mirror.Size() {
		t.Fatalf("x/crypto/blake2b digest layout changed: %d fields / %d bytes, mirror has %d / %d: re-verify scrubDigest",
			actual.NumField(), actual.Size(), mirror.NumField(), mirror.Size())
	}
	for i := 0; i < actual.NumField(); i++ {
		rf, mf := actual.Field(i), mirror.Field(i)
		if rf.Name != mf.Name || rf.Type != mf.Type || rf.Offset != mf.Offset {
			t.Fatalf("x/crypto/blake2b digest field %d is %s %v @%d, mirror has %s %v @%d: re-verify scrubDigest",
				i, rf.Name, rf.Type, rf.Offset, mf.Name, mf.Type, mf.Offset)
		}
	}
	return (*blake2bDigestMirror)(v.UnsafePointer())
}

// TestScrubDigest_Tripwire proves, for output sizes that fall back to
// blake2b.New and for inputs on both sides of the block boundary, that
// (1) the digest really does keep input bytes in its block buffer after
// Sum, the control without which the assertion is vacuous, and (2)
// scrubDigest leaves the block buffer, chaining value and counters with
// nothing input-dependent.
func TestScrubDigest_Tripwire(t *testing.T) {
	inputs := [][]byte{
		bytes.Repeat([]byte{0xA5}, 72),   // H0-sized: fits one block
		bytes.Repeat([]byte{0xA5}, 128),  // exactly one block: retained, not compressed
		bytes.Repeat([]byte{0xA5}, 200),  // one compressed, 72 retained
		bytes.Repeat([]byte{0xA5}, 1028), // H' input for a full block
	}
	for _, size := range []int{1, 20, 31, 33, 40, 63} {
		for _, in := range inputs {
			h, err := blake2b.New(size, nil)
			if err != nil {
				t.Fatal(err)
			}
			d := mirrorDigest(t, h)
			h.Write(in)
			var out [64]byte
			h.Sum(out[:0])

			// Write retains the unconsumed tail of the input (1..128 bytes)
			// in block[:offset]; that tail is what Sum leaves behind.
			if d.offset < 1 || d.offset > blake2b.BlockSize || !bytes.Equal(d.block[:d.offset], in[len(in)-d.offset:]) {
				t.Fatalf("size %d, len %d: control failed: block[:%d] does not hold the input tail after Sum; scrubDigest's premise no longer holds", size, len(in), d.offset)
			}

			scrubDigest(h)

			if !isZero(d.block[:]) {
				t.Errorf("size %d, len %d: block buffer holds residue after scrubDigest: %x", size, len(in), d.block)
			}
			if d.c != [2]uint64{} || d.offset != 0 {
				t.Errorf("size %d, len %d: counters/offset not reset: c=%v offset=%d", size, len(in), d.c, d.offset)
			}
			// The chaining value must be the parameterised IV, i.e. what a
			// fresh digest of the same size has, not anything input-derived.
			fresh, _ := blake2b.New(size, nil)
			if want := mirrorDigest(t, fresh).h; d.h != want {
				t.Errorf("size %d, len %d: chaining value not reset to the IV", size, len(in))
			}
		}
	}
}

// TestSumTo_MatchesNew pins that the one-shot path and the New(n) path
// agree for every size 1..64, so choosing between them can never change
// output.
func TestSumTo_MatchesNew(t *testing.T) {
	in := []byte("H' input of no particular significance")
	for n := 1; n <= 64; n++ {
		got := make([]byte, n)
		sumTo(got, in)
		h, _ := blake2b.New(n, nil)
		h.Write(in)
		if want := h.Sum(nil); !bytes.Equal(got, want) {
			t.Errorf("n=%d: sumTo %x, New %x", n, got, want)
		}
	}
}
