//go:build !race

// Allocation counts are only meaningful without the race detector's
// instrumentation; the non-race CI jobs execute this file.

package secmemcrypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/deadpoets/secmem"
)

// These tests pin the classification of each entry point in the README's
// "What each signer actually buys you" table. A "contained" entry point
// puts no secret on the heap: for the ones that allocate nothing at all
// that is AllocsPerRun == 0, and for Ed25519 signing it is exactly one
// allocation, the public signature. A "transient" entry point copies the
// secret through the heap by construction — the count here only records
// that it does; what is wiped and what is not is pinned by the live-wipe
// and tripwire tests (livewipe_test.go, rsawipe_test.go, mlkemwipe_test.go)
// and the docs name the remainder. A count that moves in either direction
// means the table needs re-reading, not the assertion loosening.

func TestClassification_Contained_SealFrom(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	pt, err := secmem.NewBuffer(make([]byte, 1024))
	if err != nil {
		t.Skipf("NewBuffer: %v", err)
	}
	defer pt.Destroy()
	dst := make([]byte, 0, 1024+gcm.Overhead())
	if _, err := SealFrom(dst, gcm, nonce, pt, nil); err != nil {
		t.Fatal(err)
	}
	got := testing.AllocsPerRun(200, func() {
		_, _ = SealFrom(dst[:0], gcm, nonce, pt, nil)
	})
	if got > 0 {
		t.Errorf("SealFrom: %.1f allocs/op, want 0 — the plaintext must be read from the buffer in place", got)
	}
}

// TestClassification_Contained_Ed25519Sign pins Sign at one allocation —
// the 64-byte signature — for a message up to ed25519NonceStackBytes: the
// SHA-512 digests, the edwards25519 scalars and points, and the nonce
// pre-image are all stack locals inside the Scrub window. A longer message
// adds exactly one more, the heap nonce pre-image, which is wiped.
func TestClassification_Contained_Ed25519Sign(t *testing.T) {
	s, err := GenerateEd25519Signer()
	if err != nil {
		t.Skipf("GenerateEd25519Signer: %v", err)
	}
	defer s.Destroy()
	for _, tc := range []struct {
		name string
		msg  []byte
		want float64
	}{
		{"short", []byte("hello"), 1},
		{"at the stack limit", make([]byte, ed25519NonceStackBytes), 1},
		{"over the stack limit", make([]byte, ed25519NonceStackBytes+1), 2},
	} {
		if _, err := s.Sign(nil, tc.msg, nil); err != nil {
			t.Fatal(err)
		}
		got := testing.AllocsPerRun(100, func() {
			_, _ = s.Sign(nil, tc.msg, nil)
		})
		if got != tc.want {
			t.Errorf("Ed25519Signer.Sign(%s): %.1f allocs/op, want %.0f — a new heap copy of secret material has appeared, or one disappeared; re-audit ed25519direct.go", tc.name, got, tc.want)
		}
	}
}

// TestClassification_Transient records that the standard-library-backed
// entry points copy the secret through the heap: each allocates, and the
// README classifies them accordingly. The assertion is deliberately weak
// (> 0); the strong claims about these paths are the wipe tests named at
// the top of this file.
func TestClassification_Transient(t *testing.T) {
	digest := sha256.Sum256([]byte("classify me"))
	ec, err := GenerateECDSASigner(elliptic.P256())
	if err != nil {
		t.Skipf("GenerateECDSASigner: %v", err)
	}
	defer ec.Destroy()
	rs := testRSASigner(t)
	x, err := GenerateX25519Key()
	if err != nil {
		t.Skipf("GenerateX25519Key: %v", err)
	}
	defer x.Destroy()
	peer, err := x.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	mk, err := GenerateMLKEM768Key()
	if err != nil {
		t.Skipf("GenerateMLKEM768Key: %v", err)
	}
	defer mk.Destroy()
	ek, err := mk.EncapsulationKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	ct, ss, err := Encapsulate(ek)
	if err != nil {
		t.Fatal(err)
	}
	ss.Destroy()
	out, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()
	secret := []byte("0123456789abcdef0123456789abcdef")

	for _, tc := range []struct {
		name string
		op   func()
	}{
		{"ECDSASigner.Sign", func() { _, _ = ec.Sign(rand.Reader, digest[:], crypto.SHA256) }},
		{"RSASigner.Sign", func() { _, _ = rs.Sign(rand.Reader, digest[:], crypto.SHA256) }},
		{"X25519Key.PublicKey", func() { _, _ = x.PublicKey() }},
		{"X25519Key.SharedSecret", func() { s, _ := x.SharedSecret(peer); s.Destroy() }},
		{"MLKEM768Key.Decapsulate", func() { s, _ := mk.Decapsulate(ct); s.Destroy() }},
		{"HKDFSHA256Into", func() { _ = HKDFSHA256Into(secret, nil, []byte("info"), out) }},
		{"HMACSHA256Into", func() { _ = HMACSHA256Into(secret, []byte("info"), out) }},
	} {
		tc.op()
		if got := testing.AllocsPerRun(5, tc.op); got == 0 {
			t.Errorf("%s: 0 allocs/op — it no longer copies through the heap; promote it in the README table", tc.name)
		}
	}
}

// TestClassification_EncapsulationKeyBytesDoesNotExpand pins the cache:
// the public key costs one allocation (the returned copy) and no seed
// expansion — TestMLKEM768Key_WipesLiveExpansion pins the second half.
func TestClassification_EncapsulationKeyBytesDoesNotExpand(t *testing.T) {
	mk, err := GenerateMLKEM768Key()
	if err != nil {
		t.Skipf("GenerateMLKEM768Key: %v", err)
	}
	defer mk.Destroy()
	if got := testing.AllocsPerRun(50, func() { _, _ = mk.EncapsulationKeyBytes() }); got != 1 {
		t.Errorf("EncapsulationKeyBytes: %.1f allocs/op, want 1 (the returned copy)", got)
	}
}
