package bcryptpbkdf

import (
	"bytes"
	"crypto/rand"
	"testing"
	"unsafe"

	//nolint:staticcheck // SA1019: the differential test against the deprecated upstream package is the point.
	//lint:ignore SA1019 the differential test against the deprecated upstream package is the point
	"golang.org/x/crypto/blowfish"
)

// TestBlowfish_MatchesUpstream is the differential proof for the forked
// cipher: for random key/salt pairs of bcrypt's shapes (64-byte key, 64-byte
// or empty salt), initSaltedCipher followed by ExpandKey must give a
// schedule that encrypts exactly like upstream's NewSaltedCipher plus
// ExpandKey. The public package makes this a direct comparison; bcrypt_pbkdf
// itself is internal to x/crypto and is compared end to end in
// secmem-crypto instead.
func TestBlowfish_MatchesUpstream(t *testing.T) {
	var ours Cipher
	for i := 0; i < 32; i++ {
		key := make([]byte, 64)
		salt := make([]byte, 64)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(salt); err != nil {
			t.Fatal(err)
		}
		if i%4 == 0 {
			// The empty-salt degradation is upstream's NewCipher, which
			// keeps Blowfish's 56-byte key limit; bcrypt never takes it.
			salt, key = nil, key[:56]
		}
		theirs, err := blowfish.NewSaltedCipher(key, salt)
		if err != nil {
			t.Fatal(err)
		}
		initSaltedCipher(&ours, key, salt) // ours was left dirty by the previous round
		for r := 0; r < 3; r++ {
			blowfish.ExpandKey(key, theirs)
			ExpandKey(key, &ours)
		}
		var in, a, b [8]byte
		if _, err := rand.Read(in[:]); err != nil {
			t.Fatal(err)
		}
		theirs.Encrypt(a[:], in[:])
		ours.Encrypt(b[:], in[:])
		if a != b {
			t.Fatalf("round %d: fork encrypts %x, upstream %x", i, b, a)
		}
	}
}

// TestCipher_LayoutMatchesUpstream pins that the forked Cipher is the same
// size as upstream's, so Workspace's Size (and the SecureBuffer sized from
// it) does not silently drift from what the schedule needs.
func TestCipher_LayoutMatchesUpstream(t *testing.T) {
	if a, b := unsafe.Sizeof(Cipher{}), unsafe.Sizeof(blowfish.Cipher{}); a != b {
		t.Fatalf("forked Cipher is %d bytes, upstream's %d", a, b)
	}
	if got := Size; got != int(unsafe.Sizeof(Cipher{}))+64+64+32+32+saltReserve {
		t.Fatalf("Size = %d does not account for every Workspace field", got)
	}
}

func TestInitCipher_RestoresTables(t *testing.T) {
	var c Cipher
	initSaltedCipher(&c, []byte("dirty"), []byte("salt"))
	initCipher(&c)
	if !bytes.Equal(u32Bytes(c.p[:]), u32Bytes(p[:])) || !bytes.Equal(u32Bytes(c.s3[:]), u32Bytes(s3[:])) {
		t.Fatal("initCipher did not restore the π tables")
	}
}

func u32Bytes(w []uint32) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&w[0])), 4*len(w))
}

func uintptrOf(b []byte) uintptr { return uintptr(unsafe.Pointer(&b[0])) }
