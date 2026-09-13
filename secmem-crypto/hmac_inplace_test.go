package secmemcrypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"errors"
	"hash"
	"io"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"github.com/deadpoets/secmem"
)

type namedHash struct {
	name string
	new  func() hash.Hash
	id   inPlaceHash
}

var inPlaceHashes = []namedHash{
	{"SHA-224", sha256.New224, hashSHA224},
	{"SHA-256", sha256.New, hashSHA256},
	{"SHA-384", sha512.New384, hashSHA384},
	{"SHA-512", sha512.New, hashSHA512},
	{"SHA-512/224", sha512.New512_224, hashSHA512_224},
	{"SHA-512/256", sha512.New512_256, hashSHA512_256},
	{"SHA3-224", func() hash.Hash { return sha3.New224() }, hashSHA3_224},
	{"SHA3-256", func() hash.Hash { return sha3.New256() }, hashSHA3_256},
	{"SHA3-384", func() hash.Hash { return sha3.New384() }, hashSHA3_384},
	{"SHA3-512", func() hash.Hash { return sha3.New512() }, hashSHA3_512},
}

// wrappedSHA256 has SHA-256's behaviour but not its dynamic type, so it must
// not be taken for a one-shot.
type wrappedSHA256 struct{ hash.Hash }

func blake2b256() hash.Hash {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

var heapOnlyHashes = []namedHash{
	{"SHA-1", sha1.New, hashNone},
	{"MD5", md5.New, hashNone},
	{"BLAKE2b-256", blake2b256, hashNone},
	{"wrapped SHA-256", func() hash.Hash { return wrappedSHA256{sha256.New()} }, hashNone},
}

func TestInPlaceHash_Identification(t *testing.T) {
	for _, h := range slices.Concat(inPlaceHashes, heapOnlyHashes) {
		for range 2 { // the second lookup is served from the cache
			if got := inPlaceHashOf(h.new()); got != h.id {
				t.Errorf("%s: identified as %d, want %d", h.name, got, h.id)
			}
		}
		if h.id != hashNone {
			if got, want := h.id.size(), h.new().Size(); got != want {
				t.Errorf("%s: size %d, hash says %d", h.name, got, want)
			}
			if got, want := h.id.block(), h.new().BlockSize(); got != want {
				t.Errorf("%s: block %d, hash says %d", h.name, got, want)
			}
		}
	}
	if inPlaceHashOf(nil) != hashNone {
		t.Error("nil hash identified as a one-shot")
	}
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func readOut(t *testing.T, b *secmem.SecureBuffer) []byte {
	t.Helper()
	var out []byte
	if err := b.WithBytesErr(func(p []byte) error {
		out = append([]byte(nil), p...) //nolint:secmem-lint // test oracle: the derived bytes are compared with the reference implementation's
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// Lengths either side of every boundary the in-place code has: the hash's
// block (a longer key is hashed first) and the stack region (a longer
// message moves to a locked buffer).
func boundaryLengths(block int) []int {
	return []int{0, 1, block - 1, block, block + 1, 2*block + 3,
		hmacStackRegion - block - 1, hmacStackRegion - block, hmacStackRegion - block + 1, 3000}
}

func TestHMACInto_InPlaceMatchesCryptoHMAC(t *testing.T) {
	for _, h := range inPlaceHashes {
		t.Run(h.name, func(t *testing.T) {
			block, size := h.id.block(), h.id.size()
			for _, keyLen := range []int{0, 1, size, block - 1, block, block + 1, 3 * block} {
				for _, infoLen := range boundaryLengths(block) {
					if infoLen < 0 {
						continue
					}
					key, info := randBytes(t, keyLen), randBytes(t, infoLen)
					out, err := secmem.NewEmptyBuffer(size)
					if err != nil {
						t.Skipf("NewEmptyBuffer: %v", err)
					}
					if err := HMACInto(h.new, key, info, out); err != nil {
						t.Fatalf("key %d, info %d: %v", keyLen, infoLen, err)
					}
					m := hmac.New(h.new, key)
					m.Write(info)
					if got, want := readOut(t, out), m.Sum(nil); !bytes.Equal(got, want) {
						t.Fatalf("key %d, info %d: got %x, crypto/hmac %x", keyLen, infoLen, got, want)
					}
					_ = out.Destroy()
				}
			}
		})
	}
}

func TestHKDFInto_InPlaceMatchesXCrypto(t *testing.T) {
	for _, h := range inPlaceHashes {
		t.Run(h.name, func(t *testing.T) {
			block, size := h.id.block(), h.id.size()
			cases := 0
			for _, secretLen := range boundaryLengths(block) {
				for _, saltLen := range []int{0, size, block + 1} {
					for _, infoLen := range []int{0, 17, hmacStackRegion} {
						for _, outLen := range []int{1, size - 1, size, size + 1, 3*size + 5} {
							if secretLen < 0 || (cases%7 != 0 && outLen != size) {
								cases++
								continue // a thinned grid: every length boundary is still crossed
							}
							cases++
							secret, salt, info := randBytes(t, secretLen), randBytes(t, saltLen), randBytes(t, infoLen)
							out, err := secmem.NewEmptyBuffer(outLen)
							if err != nil {
								t.Skipf("NewEmptyBuffer: %v", err)
							}
							if err := HKDFInto(h.new, secret, salt, info, out); err != nil {
								t.Fatalf("secret %d salt %d info %d out %d: %v", secretLen, saltLen, infoLen, outLen, err)
							}
							want := make([]byte, outLen)
							if _, err := io.ReadFull(hkdf.New(h.new, secret, salt, info), want); err != nil {
								t.Fatal(err)
							}
							if got := readOut(t, out); !bytes.Equal(got, want) {
								t.Fatalf("secret %d salt %d info %d out %d: got %x, x/crypto %x", secretLen, saltLen, infoLen, outLen, got, want)
							}
							_ = out.Destroy()
						}
					}
				}
			}
			// The RFC's maximum output, 255 blocks, once per hash.
			secret := randBytes(t, 32)
			out, err := secmem.NewEmptyBuffer(255 * size)
			if err != nil {
				t.Skipf("NewEmptyBuffer: %v", err)
			}
			defer out.Destroy()
			if err := HKDFInto(h.new, secret, nil, []byte("max"), out); err != nil {
				t.Fatal(err)
			}
			want := make([]byte, 255*size)
			if _, err := io.ReadFull(hkdf.New(h.new, secret, nil, []byte("max")), want); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(readOut(t, out), want) {
				t.Fatal("255-block output differs from x/crypto")
			}
		})
	}
}

// The heap path, for a hash with no one-shot, is gated like RSA and ECDSA:
// refused under a refusing policy with a remedy that names the hashes that
// run in place, admitted with AllowHeapTransients, and then still correct.
// The in-place hashes are never refused.
func TestHMACHKDF_HeapHashGate(t *testing.T) {
	withPolicy(t, false, func() {
		for _, h := range heapOnlyHashes {
			out, err := secmem.NewEmptyBuffer(h.new().Size())
			if err != nil {
				t.Skipf("NewEmptyBuffer: %v", err)
			}
			key, info := randBytes(t, 32), []byte("info")
			err = HMACInto(h.new, key, info, out)
			if !errors.Is(err, ErrHeapTransients) || !strings.Contains(err.Error(), "SHA-2 or SHA-3") {
				t.Errorf("HMACInto(%s) under a refusing policy: %v, want ErrHeapTransients naming SHA-2 or SHA-3", h.name, err)
			}
			if err := HKDFInto(h.new, key, nil, info, out); !errors.Is(err, ErrHeapTransients) {
				t.Errorf("HKDFInto(%s) under a refusing policy: %v, want ErrHeapTransients", h.name, err)
			}
			if err := HMACInto(h.new, key, info, out, AllowHeapTransients()); err != nil {
				t.Errorf("HMACInto(%s) with AllowHeapTransients: %v", h.name, err)
			}
			m := hmac.New(h.new, key)
			m.Write(info)
			if got := readOut(t, out); !bytes.Equal(got, m.Sum(nil)) {
				t.Errorf("HMACInto(%s) heap path: wrong output", h.name)
			}
			if err := HKDFInto(h.new, key, nil, info, out, AllowHeapTransients()); err != nil {
				t.Errorf("HKDFInto(%s) with AllowHeapTransients: %v", h.name, err)
			}
			_ = out.Destroy()
		}
		for _, h := range inPlaceHashes {
			out, err := secmem.NewEmptyBuffer(h.id.size())
			if err != nil {
				t.Skipf("NewEmptyBuffer: %v", err)
			}
			if err := HMACInto(h.new, []byte("k"), []byte("i"), out); err != nil {
				t.Errorf("HMACInto(%s) under a refusing policy: %v, want success (in place)", h.name, err)
			}
			if err := HKDFInto(h.new, []byte("k"), nil, []byte("i"), out); err != nil {
				t.Errorf("HKDFInto(%s) under a refusing policy: %v, want success (in place)", h.name, err)
			}
			_ = out.Destroy()
		}
	})
}

func TestHMACHKDF_NilHashConstructorResult(t *testing.T) {
	out, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()
	nilHash := func() hash.Hash { return nil }
	if err := HMACInto(nilHash, []byte("k"), nil, out); err == nil {
		t.Error("HMACInto accepted a constructor that returns nil")
	}
	if err := HKDFInto(nilHash, []byte("k"), nil, nil, out); err == nil {
		t.Error("HKDFInto accepted a constructor that returns nil")
	}
}
