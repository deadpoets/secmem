package scrypt

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	xscrypt "golang.org/x/crypto/scrypt"
)

// unhex decodes the RFC's spaced hex.
func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func words(b []byte) []uint32 {
	w := make([]uint32, len(b)/4)
	for i := range w {
		w[i] = binary.LittleEndian.Uint32(b[4*i:])
	}
	return w
}

func unwords(w []uint32) []byte {
	b := make([]byte, 4*len(w))
	for i, v := range w {
		binary.LittleEndian.PutUint32(b[4*i:], v)
	}
	return b
}

// key is scrypt end to end with the standard library's PBKDF2 around Mix:
// what the fork computes when the caller's two PBKDF2 calls are the
// reference ones. secmem-crypto's own PBKDF2 is tested against the same
// vectors where it lives (scrypt_inplace_test.go).
func key(t testing.TB, password, salt []byte, N, r, p, keyLen int) []byte {
	t.Helper()
	b, err := pbkdf2.Key(sha256.New, string(password), salt, 1, p*BlockSize(r))
	if err != nil {
		t.Fatal(err)
	}
	Mix(b, N, r, make([]byte, WorkSize(N, r)))
	out, err := pbkdf2.Key(sha256.New, string(password), b, 1, keyLen)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The inputs RFC 7914 §8, §9 and §10 share: §9's B[0] ‖ B[1] is §10's B.
const (
	rfcBlock0 = `f7 ce 0b 65 3d 2d 72 a4 10 8c f5 ab e9 12 ff dd
	             77 76 16 db bb 27 a7 0e 82 04 f3 ae 2d 0f 6f ad
	             89 f6 8f 48 11 d1 e8 7b cc 3b d7 40 0a 9f fd 29
	             09 4f 01 84 63 95 74 f3 9a e5 a1 31 52 17 bc d7`
	rfcBlock1 = `89 49 91 44 72 13 bb 22 6c 25 b5 4d a8 63 70 fb
	             cd 98 43 80 37 46 66 bb 8f fc b5 bf 40 c2 54 b0
	             67 d2 7c 51 ce 4a d5 fe d8 29 c9 0b 50 5a 57 1b
	             7f 4d 1c ad 6a 52 3c da 77 0e 67 bc ea af 7e 89`
)

// TestSalsa208Core_RFC7914 is RFC 7914 §8. salsaXOR applies the core to
// tmp XOR in, so a zero tmp makes it the bare core.
func TestSalsa208Core_RFC7914(t *testing.T) {
	in := unhex(t, `7e 87 9a 21 4f 3e c9 86 7c a9 40 e6 41 71 8f 26
	                ba ee 55 5b 8c 61 c1 b5 0d f8 46 11 6d cd 3b 1d
	                ee 24 f3 19 df 9b 3d 85 14 12 1e 4b 5a c5 aa 32
	                76 02 1d 29 09 c7 48 29 ed eb c6 8d b8 b8 c2 5e`)
	want := unhex(t, `a4 1f 85 9c 66 08 cc 99 3b 81 ca cb 02 0c ef 05
	                  04 4b 21 81 a2 fd 33 7d fd 7b 1c 63 96 68 2f 29
	                  b4 39 31 68 e3 c9 e6 bc fe 6b c5 b7 a0 6d 96 ba
	                  e4 24 cc 10 2c 91 74 5c 24 ad 67 3d c7 61 8f 81`)
	var tmp [16]uint32
	out := make([]uint32, 16)
	salsaXOR(&tmp, words(in), out)
	if got := unwords(out); !bytes.Equal(got, want) {
		t.Fatalf("Salsa20/8 core:\n got %x\nwant %x", got, want)
	}
	if got := unwords(tmp[:]); !bytes.Equal(got, want) {
		t.Fatalf("the chaining block does not carry the output:\n got %x\nwant %x", got, want)
	}
}

// TestBlockMix_RFC7914 is RFC 7914 §9, at r = 1.
func TestBlockMix_RFC7914(t *testing.T) {
	in := unhex(t, rfcBlock0+rfcBlock1)
	want := unhex(t, `a4 1f 85 9c 66 08 cc 99 3b 81 ca cb 02 0c ef 05
	                  04 4b 21 81 a2 fd 33 7d fd 7b 1c 63 96 68 2f 29
	                  b4 39 31 68 e3 c9 e6 bc fe 6b c5 b7 a0 6d 96 ba
	                  e4 24 cc 10 2c 91 74 5c 24 ad 67 3d c7 61 8f 81
	                  20 ed c9 75 32 38 81 a8 05 40 f6 4c 16 2d cd 3c
	                  21 07 7c fe 5f 8d 5f e2 b1 a4 16 8f 95 36 78 b7
	                  7d 3b 3d 80 3b 60 e4 ab 92 09 96 e5 9b 4d 53 b6
	                  5d 2a 22 58 77 d5 ed f5 84 2c b9 f1 4e ef e4 25`)
	var tmp [16]uint32
	out := make([]uint32, 32)
	blockMix(&tmp, words(in), out, 1)
	if got := unwords(out); !bytes.Equal(got, want) {
		t.Fatalf("scryptBlockMix:\n got %x\nwant %x", got, want)
	}
}

// TestMix_RFC7914ROMix is RFC 7914 §10: one block through scryptROMix at
// r = 1, N = 16, which is Mix over a single block.
func TestMix_RFC7914ROMix(t *testing.T) {
	b := unhex(t, rfcBlock0+rfcBlock1)
	want := unhex(t, `79 cc c1 93 62 9d eb ca 04 7f 0b 70 60 4b f6 b6
	                  2c e3 dd 4a 96 26 e3 55 fa fc 61 98 e6 ea 2b 46
	                  d5 84 13 67 3b 99 b0 29 d6 65 c3 57 60 1f b4 26
	                  a0 b2 f4 bb a2 00 ee 9f 0a 43 d1 9b 57 1a 9c 71
	                  ef 11 42 e6 5d 5a 26 6f dd ca 83 2c e5 9f aa 7c
	                  ac 0b 9c f1 be 2b ff ca 30 0d 01 ee 38 76 19 c4
	                  ae 12 fd 44 38 f2 03 a0 e4 e1 c4 7e c3 14 86 1f
	                  4e 90 87 cb 33 39 6a 68 73 e8 f9 d2 53 9a 4b 8e`)
	Mix(b, 16, 1, make([]byte, WorkSize(16, 1)))
	if !bytes.Equal(b, want) {
		t.Fatalf("scryptROMix:\n got %x\nwant %x", b, want)
	}
}

// TestKey_RFC7914 is RFC 7914 §12. The fourth vector (N = 1048576, a 1 GiB
// V) is not run: nothing in this module will ever be asked for it.
func TestKey_RFC7914(t *testing.T) {
	for _, v := range []struct {
		password, salt string
		N, r, p        int
		want           string
	}{
		{"", "", 16, 1, 1,
			`77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
			 f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
			 fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
			 e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06`},
		{"password", "NaCl", 1024, 8, 16,
			`fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
			 7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
			 2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
			 c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40`},
		{"pleaseletmein", "SodiumChloride", 16384, 8, 1,
			`70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
			 fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
			 d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
			 e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87`},
	} {
		t.Run(fmt.Sprintf("N=%d,r=%d,p=%d", v.N, v.r, v.p), func(t *testing.T) {
			want := unhex(t, v.want)
			if got := key(t, []byte(v.password), []byte(v.salt), v.N, v.r, v.p, len(want)); !bytes.Equal(got, want) {
				t.Fatalf("scrypt:\n got %x\nwant %x", got, want)
			}
		})
	}
}

// TestMatchesUpstream is the differential against golang.org/x/crypto/scrypt
// over random inputs: every r the block arithmetic treats differently (1,
// where integer reads the only block; 2; and 8, what every writer uses),
// p of 1, 2 and 3 (one, and more than one, pass over B), a spread of N, and
// output lengths either side of one SHA-256 block of PBKDF2 output.
func TestMatchesUpstream(t *testing.T) {
	for _, N := range []int{2, 4, 16, 128, 1024} {
		for _, r := range []int{1, 2, 8} {
			for _, p := range []int{1, 2, 3} {
				for _, keyLen := range []int{16, 31, 32, 33, 64} {
					password, salt := make([]byte, 1+(N+r+p)%40), make([]byte, 8+keyLen%9)
					_, _ = rand.Read(password)
					_, _ = rand.Read(salt)
					want, err := xscrypt.Key(password, salt, N, r, p, keyLen)
					if err != nil {
						t.Fatal(err)
					}
					if got := key(t, password, salt, N, r, p, keyLen); !bytes.Equal(got, want) {
						t.Fatalf("N=%d r=%d p=%d keyLen=%d: differs from x/crypto/scrypt\n got %x\nwant %x", N, r, p, keyLen, got, want)
					}
				}
			}
		}
	}
}

// TestMix_WorkingStateStaysInTheRegion is the fork's reason for existing,
// asserted: everything Mix writes is in b or in work[:WorkSize] — V, X, Y
// and the chaining block that upstream keeps on the stack — so the caller's
// one wipe of the region reaches all of it. Every part must be non-zero
// after a run (the control: a view laid over the wrong offset would leave
// its part untouched), nothing past WorkSize may be written, and Mix must
// allocate nothing.
func TestMix_WorkingStateStaysInTheRegion(t *testing.T) {
	const N, r, p = 64, 2, 3
	size := WorkSize(N, r)
	const guard = 256
	work := make([]byte, size+guard)
	for i := size; i < len(work); i++ {
		work[i] = 0xA5
	}
	b := make([]byte, p*BlockSize(r))
	_, _ = rand.Read(b)
	before := bytes.Clone(b)

	Mix(b, N, r, work)

	if bytes.Equal(b, before) {
		t.Fatal("Mix left b unchanged")
	}
	for i := 0; i < p; i++ {
		if blk := b[i*BlockSize(r) : (i+1)*BlockSize(r)]; bytes.Equal(blk, before[i*BlockSize(r):(i+1)*BlockSize(r)]) {
			t.Fatalf("block %d of b was not mixed", i)
		}
	}
	parts := []struct {
		name     string
		from, to int
	}{
		{"V", 0, 128 * r * N},
		{"X", 128 * r * N, 128*r*N + 128*r},
		{"Y", 128*r*N + 128*r, 128*r*N + 256*r},
		{"the Salsa20/8 chaining block", 128*r*N + 256*r, size},
	}
	for _, part := range parts {
		if bytes.Equal(work[part.from:part.to], make([]byte, part.to-part.from)) {
			t.Errorf("%s (work[%d:%d]) is all zero after Mix: it is not where the caller's wipe will look", part.name, part.from, part.to)
		}
	}
	if parts[len(parts)-1].to-parts[len(parts)-1].from != 64 {
		t.Fatalf("the chaining block is %d bytes, want 64", parts[len(parts)-1].to-parts[len(parts)-1].from)
	}
	// Each of V's N blocks is written: an off-by-one in the view would
	// leave the last one, or the first, untouched.
	for i := 0; i < N; i++ {
		if blk := work[i*128*r : (i+1)*128*r]; bytes.Equal(blk, make([]byte, len(blk))) {
			t.Errorf("V[%d] is all zero after Mix", i)
		}
	}
	for i := size; i < len(work); i++ {
		if work[i] != 0xA5 {
			t.Fatalf("Mix wrote past WorkSize, at work[%d]", i)
		}
	}

	if allocs := testing.AllocsPerRun(10, func() { Mix(b, N, r, work) }); allocs != 0 {
		t.Fatalf("Mix allocates %v objects per run, want 0", allocs)
	}
}

// TestMix_ReusedRegionGivesTheSameAnswer: V is written before it is read
// and the chaining block is loaded before it is used, so a region still
// holding a previous derivation's state — or anything else — changes
// nothing. A caller that reuses a region need not zero it for correctness.
func TestMix_ReusedRegionGivesTheSameAnswer(t *testing.T) {
	const N, r, p = 32, 2, 2
	in := make([]byte, p*BlockSize(r))
	_, _ = rand.Read(in)
	clean := bytes.Clone(in)
	Mix(clean, N, r, make([]byte, WorkSize(N, r)))

	dirty := make([]byte, WorkSize(N, r))
	_, _ = rand.Read(dirty)
	got := bytes.Clone(in)
	Mix(got, N, r, dirty)
	if !bytes.Equal(got, clean) {
		t.Fatal("a region holding old state changed the result")
	}
}

// TestMix_Preconditions: each precondition panics rather than computing
// something that is not scrypt, or writing where it should not.
func TestMix_Preconditions(t *testing.T) {
	good := func() ([]byte, []byte) { return make([]byte, BlockSize(1)), make([]byte, WorkSize(4, 1)) }
	cases := map[string]func(){
		"N zero": func() { b, w := good(); Mix(b, 0, 1, w) },
		"N one":  func() { b, w := good(); Mix(b, 1, 1, w) },
		"N not a power of two": func() {
			b := make([]byte, BlockSize(1))
			Mix(b, 3, 1, make([]byte, WorkSize(4, 1)))
		},
		"N negative":             func() { b, w := good(); Mix(b, -4, 1, w) },
		"r zero":                 func() { b, w := good(); Mix(b, 4, 0, w) },
		"b empty":                func() { _, w := good(); Mix(nil, 4, 1, w) },
		"b not a block multiple": func() { _, w := good(); Mix(make([]byte, BlockSize(1)+1), 4, 1, w) },
		"work too small":         func() { b, w := good(); Mix(b, 4, 1, w[:len(w)-1]) },
		"work misaligned": func() {
			b := make([]byte, BlockSize(1))
			Mix(b, 4, 1, make([]byte, WorkSize(4, 1)+8)[1:])
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("no panic")
				}
			}()
			fn()
		})
	}
	// The control: the good arguments do not panic.
	b, w := good()
	Mix(b, 4, 1, w)
}
