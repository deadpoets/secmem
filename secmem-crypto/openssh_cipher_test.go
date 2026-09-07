package secmemcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

// The hand-written CTR and CBC loops are differential-tested against
// crypto/cipher, which is what x/crypto/ssh and OpenSSH-compatible tooling
// use, over every length shape that matters: empty, partial block, exact
// blocks, and a counter that carries across the whole 128-bit width.

func TestCTRXOR_MatchesCryptoCipher(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	iv := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 15, 16, 17, 32, 48, 100, 1024} {
		if _, err := rand.Read(iv); err != nil {
			t.Fatal(err)
		}
		src := make([]byte, n)
		if _, err := rand.Read(src); err != nil {
			t.Fatal(err)
		}
		want := make([]byte, n)
		cipher.NewCTR(blk, iv).XORKeyStream(want, src)

		got := make([]byte, n)
		scratch := make([]byte, cipherScratch)
		ctrXOR(blk, iv, got, src, scratch)
		if !bytes.Equal(got, want) {
			t.Fatalf("len %d: ctrXOR differs from cipher.NewCTR", n)
		}
		if !bytes.Equal(scratch, make([]byte, cipherScratch)) {
			t.Fatalf("len %d: ctrXOR left keystream in its scratch", n)
		}
		// In place, as the marshal path uses it.
		inPlace := append([]byte(nil), src...)
		ctrXOR(blk, iv, inPlace, inPlace, scratch)
		if !bytes.Equal(inPlace, want) {
			t.Fatalf("len %d: in-place ctrXOR differs from cipher.NewCTR", n)
		}
	}
}

// TestCTRXOR_CounterCarry pins the big-endian increment across every byte:
// an all-0xff IV must wrap to zero and continue.
func TestCTRXOR_CounterCarry(t *testing.T) {
	t.Parallel()
	blk, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	iv := bytes.Repeat([]byte{0xff}, 16)
	src := make([]byte, 64)
	want := make([]byte, 64)
	cipher.NewCTR(blk, iv).XORKeyStream(want, src)
	got := make([]byte, 64)
	ctrXOR(blk, iv, got, src, make([]byte, cipherScratch))
	if !bytes.Equal(got, want) {
		t.Fatal("ctrXOR counter carry differs from cipher.NewCTR")
	}
}

func TestCBCDecrypt_MatchesCryptoCipher(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	iv := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{16, 32, 48, 1024} {
		if _, err := rand.Read(iv); err != nil {
			t.Fatal(err)
		}
		src := make([]byte, n)
		if _, err := rand.Read(src); err != nil {
			t.Fatal(err)
		}
		want := make([]byte, n)
		cipher.NewCBCDecrypter(blk, iv).CryptBlocks(want, src)
		got := make([]byte, n)
		scratch := make([]byte, cipherScratch)
		cbcDecrypt(blk, iv, got, src, scratch)
		if !bytes.Equal(got, want) {
			t.Fatalf("len %d: cbcDecrypt differs from cipher.NewCBCDecrypter", n)
		}
		if !bytes.Equal(scratch, make([]byte, cipherScratch)) {
			t.Fatalf("len %d: cbcDecrypt left the chaining block in its scratch", n)
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("cbcDecrypt accepted a non-block-multiple input")
			}
		}()
		cbcDecrypt(blk, iv, make([]byte, 17), make([]byte, 17), make([]byte, cipherScratch))
	}()
}
