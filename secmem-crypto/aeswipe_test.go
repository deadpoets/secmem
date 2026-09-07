package secmemcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"strings"
	"testing"
)

// These tests pin wipeAESBlock to the current toolchain, the way
// rsa_wipe_tripwire_test.go pins the ECDH scalar wipe: the helper reaches
// crypto/aes's unexported round-key arrays by name via reflection, which no
// compiler check protects, so a stdlib refactor must turn into a red run on
// the first CI pass of a new Go version — not into a wipe that quietly
// stopped wiping under two exported functions that still succeed.

// TestWipeAESBlock_Tripwire proves, on this toolchain, that (1) both
// reflected fields resolve to non-empty uint32 arrays holding a non-zero
// schedule, (2) the wipe reports success, and (3) the cipher no longer
// computes AES afterwards — an oracle independent of the reflection path,
// so a field that still exists but is no longer the schedule the cipher
// uses is caught too.
func TestWipeAESBlock_Tripwire(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	var in, want, got [16]byte
	if _, err := rand.Read(in[:]); err != nil {
		t.Fatal(err)
	}
	ref.Encrypt(want[:], in[:])

	var views [][]byte
	for _, field := range aesRoundKeyFields {
		keys, err := aesRoundKeys(blk, field)
		if err != nil {
			t.Fatalf("crypto/aes round keys %q no longer resolve on this toolchain — update aesRoundKeyFields: %v", field, err)
		}
		if len(keys) != 60*4 {
			t.Fatalf("field %q is %d bytes, want 240 ([60]uint32)", field, len(keys))
		}
		if bytes.Equal(keys, make([]byte, len(keys))) {
			t.Fatalf("field %q is all zero on a freshly keyed cipher: not the schedule", field)
		}
		views = append(views, keys)
	}

	if err := wipeAESBlock(blk); err != nil {
		t.Fatalf("wipeAESBlock: %v", err)
	}
	for i, keys := range views {
		if !bytes.Equal(keys, make([]byte, len(keys))) {
			t.Fatalf("field %q still holds the schedule after the wipe", aesRoundKeyFields[i])
		}
	}
	blk.Encrypt(got[:], in[:])
	if got == want {
		t.Fatal("the cipher still computes AES after the wipe: the reflected fields are not the schedule it uses")
	}
	blk.Decrypt(got[:], want[:])
	if got == in {
		t.Fatal("the cipher still decrypts after the wipe: the dec schedule was not reached")
	}

	if err := wipeAESBlock(nil); err != nil {
		t.Errorf("wipeAESBlock(nil) = %v, want nil", err)
	}
}

type fakeBlock struct{}

func (fakeBlock) BlockSize() int          { return 16 }
func (fakeBlock) Encrypt(dst, src []byte) { copy(dst, src) }
func (fakeBlock) Decrypt(dst, src []byte) { copy(dst, src) }

// TestAESRoundKeys_ReportsUnresolvableField pins the fail-loud half: a
// missing field, a field of the wrong shape, and a Block of an unexpected
// concrete type must each be reported as NOT wiped, never returned as if
// wiped.
func TestAESRoundKeys_ReportsUnresolvableField(t *testing.T) {
	t.Parallel()
	blk, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		block cipher.Block
		field string
	}{
		{"missing field", blk, "noSuchField"},
		{"wrong shape", blk, "rounds"}, // an int, not [N]uint32
		{"not a pointer to a struct", fakeBlock{}, "enc"},
	} {
		keys, err := aesRoundKeys(tc.block, tc.field)
		if err == nil {
			t.Errorf("%s: reported success with %d bytes", tc.name, len(keys))
			continue
		}
		if !strings.Contains(err.Error(), "NOT wiped") {
			t.Errorf("%s: error does not say the keys were not wiped: %v", tc.name, err)
		}
	}
	if err := wipeAESBlock(fakeBlock{}); err == nil {
		t.Error("wipeAESBlock on a foreign Block type reported success")
	}
}
