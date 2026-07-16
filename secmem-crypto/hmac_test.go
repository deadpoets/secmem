package secmemcrypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/deadpoets/secmem"
)

// TestHMACInto_RFC4231TestCase2 is a published known-answer test, not a
// self-consistency check: RFC 4231 §4.3, key="Jefe", data="what do ya want
// for nothing?" — independently verified against crypto/hmac+crypto/sha256
// directly before being hardcoded here.
func TestHMACInto_RFC4231TestCase2(t *testing.T) {
	t.Parallel()
	const wantHex = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("decode want: %v", err)
	}

	out, err := secmem.NewEmptyBuffer(sha256.Size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()

	if err := HMACSHA256Into([]byte("Jefe"), []byte("what do ya want for nothing?"), out); err != nil {
		t.Fatalf("HMACSHA256Into: %v", err)
	}

	err = out.WithBytesErr(func(got []byte) error {
		if !bytes.Equal(got, want) { //nolint:secmem-lint // test compares MAC output against a published KAT, not a secret
			t.Errorf("HMAC-SHA256 = %x, want %x (RFC 4231 test case 2)", got, want) //nolint:secmem-lint // diagnostic on failure only; not a secret in this KAT
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithBytesErr: %v", err)
	}
}

// TestHMACInto_DiffersFromHKDF is the concrete proof behind the doc comment's
// warning: HMACInto(secret, info) and HKDFSHA256Into(secret, nil, info) look
// similar but are NOT the same computation, because HKDF's Extract step uses
// secret as HMAC's *message* (with a zero key), not as the key. If this ever
// produced identical output, the doc comment's warning would be wrong.
func TestHMACInto_DiffersFromHKDF(t *testing.T) {
	t.Parallel()
	secret := []byte("a-shared-root-secret")
	info := []byte("checkpoint-signing-subkey")

	hmacOut, err := secmem.NewEmptyBuffer(sha256.Size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer hmacOut.Destroy()
	if err := HMACSHA256Into(secret, info, hmacOut); err != nil {
		t.Fatalf("HMACSHA256Into: %v", err)
	}

	hkdfOut, err := secmem.NewEmptyBuffer(sha256.Size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer hkdfOut.Destroy()
	if err := HKDFSHA256Into(secret, nil, info, hkdfOut); err != nil {
		t.Fatalf("HKDFSHA256Into: %v", err)
	}

	var a, b []byte
	_ = hmacOut.WithBytesErr(func(x []byte) error { a = append([]byte(nil), x...); return nil }) //nolint:secmem-lint // test compares two derivations for inequality
	_ = hkdfOut.WithBytesErr(func(x []byte) error { b = append([]byte(nil), x...); return nil }) //nolint:secmem-lint // test compares two derivations for inequality
	if bytes.Equal(a, b) {
		t.Fatal("HMACInto and HKDFSHA256Into produced identical output — they must NOT be interchangeable")
	}

	// Positive confirmation, not just "they differ": HMACInto really is a raw
	// keyed HMAC, independently computed via crypto/hmac directly.
	mac := hmac.New(sha256.New, secret)
	mac.Write(info)
	want := mac.Sum(nil)
	if !bytes.Equal(a, want) { //nolint:secmem-lint // test compares MAC output against an independent computation, not a secret
		t.Errorf("HMACInto output does not match an independent crypto/hmac computation")
	}
}

// TestHMACInto_WrongOutputSize proves a mismatched buffer size errors rather
// than silently truncating or padding the digest.
func TestHMACInto_WrongOutputSize(t *testing.T) {
	t.Parallel()
	out, err := secmem.NewEmptyBuffer(sha256.Size - 1) // one byte short
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()

	if err := HMACSHA256Into([]byte("key"), []byte("info"), out); err == nil {
		t.Error("expected an error for a wrong-size output buffer, got nil")
	}
}

// TestHMACInto_NilChecks mirrors this file's existing nil-handling coverage
// for the other *Into functions.
func TestHMACInto_NilChecks(t *testing.T) {
	t.Parallel()
	out, err := secmem.NewEmptyBuffer(sha256.Size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()

	if err := HMACInto(nil, []byte("key"), []byte("info"), out); err == nil {
		t.Error("expected an error for a nil hash function, got nil")
	}
	if err := HMACSHA256Into([]byte("key"), []byte("info"), nil); err == nil {
		t.Error("expected an error for a nil output buffer, got nil")
	}
}

// TestHMACInto_DestroyedOutput mirrors HKDFInto/Argon2IDKeyInto's existing
// destroyed-buffer coverage.
func TestHMACInto_DestroyedOutput(t *testing.T) {
	t.Parallel()
	out, err := secmem.NewEmptyBuffer(sha256.Size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	if err := out.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if err := HMACSHA256Into([]byte("key"), []byte("info"), out); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("error = %v, want wrap of ErrDestroyed", err)
	}
}

// TestHMACInto_HashAgile proves the full-params function isn't hardcoded to
// SHA-256 internally — a different hash produces its own correctly-sized,
// independently-verifiable output.
func TestHMACInto_HashAgile(t *testing.T) {
	t.Parallel()
	out, err := secmem.NewEmptyBuffer(sha512.Size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()

	secret, info := []byte("key"), []byte("info")
	if err := HMACInto(sha512.New, secret, info, out); err != nil {
		t.Fatalf("HMACInto with sha512.New: %v", err)
	}

	mac := hmac.New(sha512.New, secret)
	mac.Write(info)
	want := mac.Sum(nil)

	err = out.WithBytesErr(func(got []byte) error {
		if !bytes.Equal(got, want) { //nolint:secmem-lint // test compares MAC output against an independent computation, not a secret
			t.Error("SHA-512 HMACInto output does not match an independent crypto/hmac computation")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithBytesErr: %v", err)
	}
}
