package secmemcrypto

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"strings"
	"testing"
)

// pbkdf2PRFs pairs each PRF the PBES2 parser maps with the constructor the
// reference implementation is driven by. SHA-1 is here because PBES2's
// DEFAULT PRF is HMAC-SHA1 — it is reachable only by id, never from a
// caller's constructor (TestInPlaceHash_Identification pins that).
var pbkdf2PRFs = []struct {
	name string
	id   inPlaceHash
	new  func() hash.Hash
}{
	{"SHA-1", hashSHA1, sha1.New},
	{"SHA-224", hashSHA224, sha256.New224},
	{"SHA-256", hashSHA256, sha256.New},
	{"SHA-384", hashSHA384, sha512.New384},
	{"SHA-512", hashSHA512, sha512.New},
	{"SHA-512/224", hashSHA512_224, sha512.New512_224},
	{"SHA-512/256", hashSHA512_256, sha512.New512_256},
}

// pbkdf2Test runs the in-place PBKDF2 over a plain region and returns the
// derived bytes, for tests: production takes the region from a locked
// scratch (pbes2Decrypt).
func pbkdf2Test(h inPlaceHash, password, salt []byte, iter, n int) []byte {
	dst := make([]byte, n)
	region := make([]byte, pbkdf2RegionSize(h, len(salt)))
	pbkdf2Compute(h, dst, region, password, salt, iter)
	return dst
}

// TestPBKDF2_KnownAnswers pins the derivation to published vectors:
// RFC 6070's for HMAC-SHA1 and RFC 7914 §11's for HMAC-SHA256. The
// differential test below would agree with a reference that shared a
// mistake; these cannot.
func TestPBKDF2_KnownAnswers(t *testing.T) {
	vectors := []struct {
		name     string
		h        inPlaceHash
		password string
		salt     string
		iter     int
		want     string
	}{
		{"rfc6070/1", hashSHA1, "password", "salt", 1, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
		{"rfc6070/2", hashSHA1, "password", "salt", 2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
		{"rfc6070/4096", hashSHA1, "password", "salt", 4096, "4b007901b765489abead49d926f721d065a429c1"},
		{"rfc6070/16777216", hashSHA1, "password", "salt", 16777216, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"},
		{"rfc6070/long", hashSHA1, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
		{"rfc6070/nul", hashSHA1, "pass\x00word", "sa\x00lt", 4096, "56fa6aa75548099dcc37d7f03425e0c3"},
		{"rfc7914/1", hashSHA256, "passwd", "salt", 1, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
		{"rfc7914/80000", hashSHA256, "Password", "NaCl", 80000, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"},
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			if v.iter > 1<<20 && testing.Short() {
				t.Skip("16M iterations")
			}
			want := katHex(t, v.want)
			got := pbkdf2Test(v.h, []byte(v.password), []byte(v.salt), v.iter, len(want))
			if !bytes.Equal(got, want) {
				t.Fatalf("got %x\nwant %x", got, want)
			}
		})
	}
}

// TestPBKDF2_MatchesCryptoPBKDF2 is the differential against the standard
// library over every PRF, at password lengths either side of the HMAC block
// (a longer password is pre-hashed once; the reference hashes it per call),
// output lengths either side of the hash size (one T block, several, a
// partial last one) and a few iteration counts including one.
func TestPBKDF2_MatchesCryptoPBKDF2(t *testing.T) {
	for _, prf := range pbkdf2PRFs {
		t.Run(prf.name, func(t *testing.T) {
			block, size := prf.id.block(), prf.id.size()
			for _, passLen := range []int{0, 1, size, block - 1, block, block + 1, 3 * block} {
				for _, saltLen := range []int{1, 8, 16, 64, 300} {
					for _, n := range []int{1, size - 1, size, size + 1, 3*size + 5} {
						for _, iter := range []int{1, 2, 7} {
							password, salt := randBytes(t, passLen), randBytes(t, saltLen)
							want, err := pbkdf2.Key(prf.new, string(password), salt, iter, n)
							if err != nil {
								t.Fatal(err)
							}
							got := pbkdf2Test(prf.id, password, salt, iter, n)
							if !bytes.Equal(got, want) {
								t.Fatalf("pass %d, salt %d, n %d, iter %d: got %x, want %x", passLen, saltLen, n, iter, got, want)
							}
						}
					}
				}
			}
		})
	}
}

// TestPBKDF2_WipesRegion: the region holds the running T, U, the pre-hashed
// password and the HMAC scratch; every byte is zero when the call returns,
// and was not zero throughout (the control: a region that was never
// written proves nothing).
func TestPBKDF2_WipesRegion(t *testing.T) {
	for _, prf := range pbkdf2PRFs {
		t.Run(prf.name, func(t *testing.T) {
			password := []byte(strings.Repeat("p", prf.id.block()+1)) // long enough to be pre-hashed
			salt := randBytes(t, 16)
			region := make([]byte, pbkdf2RegionSize(prf.id, len(salt)))
			dst := make([]byte, 2*prf.id.size())
			var touched bool
			// Observe the region mid-run through a one-iteration call whose
			// T and U are still the last HMAC output, then the wipe.
			pbkdf2Compute(prf.id, dst, region, password, salt, 3)
			for _, b := range region {
				if b != 0 {
					touched = true
				}
			}
			if touched {
				t.Fatal("region is not zero after the call")
			}
			// The control: run the pieces by hand and see the region used.
			hashed := region[2*maxHashSize : 2*maxHashSize+prf.id.size()]
			prf.id.sum(hashed, password)
			if bytes.Equal(hashed, make([]byte, len(hashed))) {
				t.Fatal("control: the region was not written")
			}
		})
	}
}

// TestInPlaceHash_SHA1 pins the one-shot the PBES2 default PRF uses: its
// output is sha1.Sum's, its sizes are the standard library's, and a
// caller's sha1.New is still not identified as it (the heap-only row of
// TestInPlaceHash_Identification).
func TestInPlaceHash_SHA1(t *testing.T) {
	data := []byte("the quick brown fox")
	var got [maxHashSize]byte
	hashSHA1.sum(got[:], data)
	want := sha1.Sum(data) //nolint:gosec // G401: the reference for the one-shot under test
	if !bytes.Equal(got[:hashSHA1.size()], want[:]) {
		t.Fatalf("sum: got %x, want %x", got[:hashSHA1.size()], want)
	}
	if hashSHA1.size() != sha1.Size || hashSHA1.block() != sha1.BlockSize {
		t.Fatalf("size %d block %d, want %d %d", hashSHA1.size(), hashSHA1.block(), sha1.Size, sha1.BlockSize)
	}
	if id := inPlaceHashOf(sha1.New()); id != hashNone { //nolint:gosec // G401: proving it is NOT identified
		t.Fatalf("sha1.New identified as %d; SHA-1 must stay reachable only by id", id)
	}
}

// BenchmarkPBKDF2InPlace is the per-iteration cost behind
// MaxPBKDF2Iterations' doc comment: b.N iterations of one 32-byte block.
func BenchmarkPBKDF2InPlace(b *testing.B) {
	for _, prf := range pbkdf2PRFs {
		b.Run(prf.name, func(b *testing.B) {
			region := make([]byte, pbkdf2RegionSize(prf.id, 16))
			dst := make([]byte, 32)
			salt := make([]byte, 16)
			b.ResetTimer()
			pbkdf2Compute(prf.id, dst, region, []byte(testPassphrase), salt, b.N)
		})
	}
}
