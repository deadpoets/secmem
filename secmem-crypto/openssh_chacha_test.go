package secmemcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/chacha20"

	//lint:ignore SA1019 as in openssh_chacha.go: the successor is internal.
	"golang.org/x/crypto/poly1305" //nolint:staticcheck // see openssh_chacha.go
)

// TestChaChaBlock_RFC8439Vector pins the core to the published vector
// (RFC 8439 §2.3.2), which is the IETF split of the same function: its
// 32-bit counter and 96-bit nonce are this implementation's 64-bit counter
// and 64-bit nonce with the first nonce word carrying the counter's high
// half. Here the high half is zero, so the words line up directly.
func TestChaChaBlock_RFC8439Vector(t *testing.T) {
	t.Parallel()
	var key [chachaKeyLen]byte
	for i := range key {
		key[i] = byte(i)
	}
	// RFC 8439's nonce is 00:00:00:09 00:00:00:4a 00:00:00:00; the first
	// word is the counter's high half in this variant.
	var nonce [8]byte
	binary.LittleEndian.PutUint32(nonce[0:], 0x4a000000)
	counter := uint64(1) | uint64(0x09000000)<<32

	var got [chachaBlockSize]byte
	chachaBlock(&got, &key, &nonce, counter)

	want, err := hex.DecodeString(
		"10f1e7e4d13b5915500fdd1fa32071c4" +
			"c7d1f4c733c068030422aa9ac3d46c4e" +
			"d2826446079faa0914c2d705d98b02a2" +
			"b5129cd1de164eb9cbd083e8a2503c4e")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], want) {
		t.Errorf("block =\n%x\nwant\n%x", got[:], want)
	}
}

// TestChaChaXOR_MatchesXCrypto is the differential: for random keys, nonces,
// counters and lengths, the keystream must equal x/crypto/chacha20's. The
// two are related by the counter split described above, so this also pins
// that mapping.
func TestChaChaXOR_MatchesXCrypto(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 63, 64, 65, 127, 128, 200, 1024} {
		for range 8 {
			var key [chachaKeyLen]byte
			var nonce [8]byte
			chachaRand(t, key[:])
			chachaRand(t, nonce[:])
			var hi [4]byte
			chachaRand(t, hi[:])
			counter := uint64(binary.LittleEndian.Uint32(hi[:]))<<32 | 7

			src := make([]byte, n)
			chachaRand(t, src)
			got := make([]byte, n)
			chachaXOR(&key, &nonce, counter, got, src)

			// x/crypto takes the IETF split: a 32-bit counter and a nonce
			// whose first word is the counter's high half.
			ietfNonce := append(hi[:], nonce[:]...)
			c, err := chacha20.NewUnauthenticatedCipher(key[:], ietfNonce)
			if err != nil {
				t.Fatal(err)
			}
			c.SetCounter(uint32(counter))
			want := make([]byte, n)
			c.XORKeyStream(want, src)

			if !bytes.Equal(got, want) {
				t.Fatalf("len %d: keystream differs from x/crypto/chacha20", n)
			}
		}
	}
}

// TestChaCha_NoHeap: the core, the keystream and the Poly1305 key are stack
// locals wiped before return, so none of the three allocates. A regression
// here means a secret reached the heap where nothing wipes it.
func TestChaCha_NoHeap(t *testing.T) {
	var key [chachaKeyLen]byte
	var nonce [8]byte
	var out [chachaBlockSize]byte
	src := make([]byte, 256)
	dst := make([]byte, 256)
	keyMaterial := make([]byte, chachaOpenSSHKeyLen)
	tag := make([]byte, chachaTagLen)

	for _, tc := range []struct {
		name string
		fn   func()
	}{
		{"chachaBlock", func() { chachaBlock(&out, &key, &nonce, 1) }},
		{"chachaXOR", func() { chachaXOR(&key, &nonce, 1, dst, src) }},
		{"opensshChaChaOpen", func() { _ = opensshChaChaOpen(dst, src, tag, keyMaterial) }},
	} {
		if got := testing.AllocsPerRun(50, tc.fn); got != 0 {
			t.Errorf("%s: %v allocs/op, want 0", tc.name, got)
		}
	}
}

// TestOpensshChaChaOpen_RejectsWrongTag: the authenticator is checked before
// anything is decrypted, and a tag that does not match leaves dst untouched.
func TestOpensshChaChaOpen_RejectsWrongTag(t *testing.T) {
	t.Parallel()
	keyMaterial := make([]byte, chachaOpenSSHKeyLen)
	chachaRand(t, keyMaterial)
	ct := make([]byte, 64)
	chachaRand(t, ct)

	// The tag this construction would produce, obtained by asking for it.
	dst := make([]byte, len(ct))
	good := chachaTagFor(t, keyMaterial, ct)
	if !opensshChaChaOpen(dst, ct, good, keyMaterial) {
		t.Fatal("the tag this construction produces did not verify")
	}

	bad := bytes.Clone(good)
	bad[0] ^= 1
	untouched := make([]byte, len(ct))
	if opensshChaChaOpen(untouched, ct, bad, keyMaterial) {
		t.Error("a corrupted tag verified")
	}
	if !bytes.Equal(untouched, make([]byte, len(ct))) {
		t.Error("a failed verification still wrote plaintext")
	}
}

// chachaTagFor returns the authenticator opensshChaChaOpen expects for ct,
// computed the way the construction defines it: Poly1305 under the first 32
// bytes of the keystream at counter 0.
func chachaTagFor(t *testing.T, keyMaterial, ct []byte) []byte {
	t.Helper()
	var key [chachaKeyLen]byte
	var nonce [8]byte
	var block [chachaBlockSize]byte
	copy(key[:], keyMaterial[:chachaKeyLen])
	chachaBlock(&block, &key, &nonce, 0)
	var polyKey [chachaKeyLen]byte
	copy(polyKey[:], block[:chachaKeyLen])
	var tag [chachaTagLen]byte
	poly1305.Sum(&tag, ct, &polyKey)
	return tag[:]
}

func chachaRand(t *testing.T, b []byte) {
	t.Helper()
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
}
