package secmemcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/deadpoets/secmem"
)

// FuzzSignEd25519Direct_MatchesStdlib differentially fuzzes the hand-rolled
// RFC 8032 implementation against crypto/ed25519 — a perfect, cheap oracle
// for the one function in this module that reimplements standard crypto.
func FuzzSignEd25519Direct_MatchesStdlib(f *testing.F) {
	f.Add([]byte("9d61b19deffd5a60ba844af492ec2cc4"), []byte(""))
	f.Add([]byte("4ccd089b28ff96da9db6c346ec114e0f"), []byte{0x72})
	f.Add(bytes.Repeat([]byte{0x00}, 32), bytes.Repeat([]byte{0xff}, 1024))
	f.Fuzz(func(t *testing.T, seed, msg []byte) {
		if len(seed) != ed25519.SeedSize {
			if _, err := signEd25519Direct(seed, msg); err == nil {
				t.Fatal("bad-length seed accepted")
			}
			return
		}
		ourSig, err := signEd25519Direct(seed, msg)
		if err != nil {
			t.Fatalf("signEd25519Direct: %v", err)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		if stdSig := ed25519.Sign(priv, msg); !bytes.Equal(ourSig, stdSig) {
			t.Errorf("signature differs from stdlib\n  ours:   %x\n  stdlib: %x", ourSig, stdSig)
		}
		if !ed25519.Verify(priv.Public().(ed25519.PublicKey), msg, ourSig) {
			t.Error("stdlib Verify rejected our signature")
		}
		pub, err := deriveEd25519PublicKey(seed)
		if err != nil {
			t.Fatalf("deriveEd25519PublicKey: %v", err)
		}
		if !pub.Equal(priv.Public().(ed25519.PublicKey)) {
			t.Error("derived public key differs from stdlib")
		}
	})
}

// FuzzHKDFInto asserts the wrapper never panics and, when it succeeds,
// matches a direct x/crypto/hkdf derivation for the same parameters.
func FuzzHKDFInto(f *testing.F) {
	f.Add([]byte("key"), []byte("salt"), []byte("info"), uint16(32))
	f.Add([]byte{}, []byte(nil), []byte(nil), uint16(1))
	f.Add([]byte("k"), []byte(nil), []byte(nil), uint16(9000))
	f.Fuzz(func(t *testing.T, secret, salt, info []byte, outLen uint16) {
		size := int(outLen)
		if size == 0 {
			return // NewEmptyBuffer(0) is its own core concern, not HKDF's
		}
		out, err := secmem.NewEmptyBuffer(size)
		if err != nil {
			t.Skipf("NewEmptyBuffer(%d): %v", size, err)
		}
		defer out.Destroy()

		err = HKDFSHA256Into(secret, salt, info, out)
		if size > 255*sha256.Size {
			if err == nil {
				t.Fatalf("output %d over the RFC limit accepted", size)
			}
			return
		}
		if err != nil {
			t.Fatalf("HKDFSHA256Into: %v", err)
		}
		want := make([]byte, size)
		if _, err := io.ReadFull(hkdf.New(sha256.New, secret, salt, info), want); err != nil {
			t.Fatalf("direct hkdf read: %v", err)
		}
		var got []byte
		_ = out.WithBytesErr(func(p []byte) error { got = append([]byte(nil), p...); return nil })
		if !bytes.Equal(got, want) {
			t.Error("HKDFSHA256Into differs from direct x/crypto/hkdf derivation")
		}
	})
}

// FuzzArgon2Params asserts the cost-parameter validation holds the no-panic
// contract for arbitrary parameters — the exact class of input that
// panicked before the validation existed. Memory and time are clamped small
// so the fuzzer explores parameters, not CPU time.
func FuzzArgon2Params(f *testing.F) {
	f.Add(uint32(0), uint32(64), uint8(0), []byte("p"), []byte("s"))
	f.Add(uint32(1), uint32(0), uint8(1), []byte("p"), []byte("s"))
	f.Add(uint32(2), uint32(64), uint8(2), []byte(""), []byte(""))
	f.Fuzz(func(t *testing.T, time, memory uint32, threads uint8, password, salt []byte) {
		time %= 3
		memory %= 1024
		threads %= 3

		out, err := secmem.NewEmptyBuffer(16)
		if err != nil {
			t.Skipf("NewEmptyBuffer: %v", err)
		}
		defer out.Destroy()

		// Must never panic; must error exactly when a cost param is < 1.
		err = Argon2IDKeyInto(password, salt, time, memory, threads, out)
		if (time < 1 || threads < 1) && err == nil {
			t.Errorf("zero cost param accepted: time=%d threads=%d", time, threads)
		}
		if time >= 1 && threads >= 1 && err != nil {
			t.Errorf("valid params rejected: time=%d memory=%d threads=%d: %v", time, memory, threads, err)
		}
	})
}
