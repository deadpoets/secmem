package secmemcrypto

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/deadpoets/secmem"
)

// readBuf copies a SecureBuffer's contents out for test assertions only.
func readBuf(t *testing.T, b *secmem.SecureBuffer) []byte {
	t.Helper()
	var out []byte
	if err := b.WithBytesErr(func(p []byte) error {
		out = append([]byte(nil), p...) //nolint:secmem-lint // test helper reads contents out for comparison
		return nil
	}); err != nil {
		t.Fatalf("WithBytesErr: %v", err)
	}
	return out
}

func deriveHKDF(t *testing.T, secret, salt, info []byte, size int) []byte {
	t.Helper()
	out, err := secmem.NewEmptyBuffer(size)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()
	if err := HKDFSHA256Into(secret, salt, info, out); err != nil {
		t.Fatalf("HKDFSHA256Into: %v", err)
	}
	return readBuf(t, out)
}

// RFC 5869 Appendix A test vectors (SHA-256) — verified against the
// published RFC text. TC1 and TC2 exercise the salted extract step and
// info binding the previous salt-less API could not express; TC3 covers
// the zero-salt/zero-info degenerate corner.

func TestHKDFSHA256Into_RFC5869TestCase1(t *testing.T) {
	t.Parallel()
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := mustDecodeHex(t, "000102030405060708090a0b0c")
	info := mustDecodeHex(t, "f0f1f2f3f4f5f6f7f8f9")
	wantOKM := mustDecodeHex(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	got := deriveHKDF(t, ikm, salt, info, len(wantOKM))
	if !bytes.Equal(got, wantOKM) {
		t.Errorf("OKM mismatch\n  got:  %x\n  want: %x", got, wantOKM)
	}
}

func TestHKDFSHA256Into_RFC5869TestCase2(t *testing.T) {
	t.Parallel()
	ikm := mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
	salt := mustDecodeHex(t, "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	info := mustDecodeHex(t, "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	wantOKM := mustDecodeHex(t, "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")

	got := deriveHKDF(t, ikm, salt, info, len(wantOKM))
	if !bytes.Equal(got, wantOKM) {
		t.Errorf("OKM mismatch\n  got:  %x\n  want: %x", got, wantOKM)
	}
}

func TestHKDFSHA256Into_RFC5869TestCase3(t *testing.T) {
	t.Parallel()
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	wantOKM := mustDecodeHex(t, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")

	// nil salt and nil info equal the RFC's zero-length values: HMAC
	// zero-pads short keys to the block size either way.
	got := deriveHKDF(t, ikm, nil, nil, len(wantOKM))
	if !bytes.Equal(got, wantOKM) {
		t.Errorf("OKM mismatch\n  got:  %x\n  want: %x", got, wantOKM)
	}
}

func TestHKDFInto_HashAgility(t *testing.T) {
	t.Parallel()
	secret := []byte("master key material")
	salt := []byte("per-tenant salt")
	info := []byte("sub-key: signing")

	out256, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out256.Destroy()
	out512, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out512.Destroy()

	if err := HKDFInto(sha256.New, secret, salt, info, out256); err != nil {
		t.Fatalf("HKDFInto(sha256): %v", err)
	}
	if err := HKDFInto(sha512.New, secret, salt, info, out512); err != nil {
		t.Fatalf("HKDFInto(sha512): %v", err)
	}

	got256, got512 := readBuf(t, out256), readBuf(t, out512)
	if bytes.Equal(got256, got512) {
		t.Error("SHA-256 and SHA-512 HKDF produced identical output")
	}

	// Cross-check the SHA-512 path against a direct x/crypto/hkdf read —
	// there is no official RFC 5869 SHA-512 vector, so the property check
	// is against the engine this wrapper builds on.
	want := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha512.New, secret, salt, info), want); err != nil {
		t.Fatalf("direct hkdf read: %v", err)
	}
	if !bytes.Equal(got512, want) {
		t.Error("HKDFInto(sha512) does not match a direct x/crypto/hkdf derivation")
	}
}

func TestHKDFSHA256Into_ConvenienceMatchesFullForm(t *testing.T) {
	t.Parallel()
	secret, salt, info := []byte("s"), []byte("salt"), []byte("info")

	a, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer a.Destroy()
	b, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer b.Destroy()

	if err := HKDFSHA256Into(secret, salt, info, a); err != nil {
		t.Fatalf("HKDFSHA256Into: %v", err)
	}
	if err := HKDFInto(sha256.New, secret, salt, info, b); err != nil {
		t.Fatalf("HKDFInto: %v", err)
	}
	if !bytes.Equal(readBuf(t, a), readBuf(t, b)) {
		t.Error("HKDFSHA256Into differs from HKDFInto(sha256.New, ...)")
	}
}

func TestHKDFInto_DifferentInfoDiffers(t *testing.T) {
	t.Parallel()
	masterKey := []byte("master key material")
	a := deriveHKDF(t, masterKey, nil, []byte("info-a"), 32)
	b := deriveHKDF(t, masterKey, nil, []byte("info-b"), 32)
	if bytes.Equal(a, b) {
		t.Error("different HKDF info values produced identical output")
	}
}

func TestHKDFInto_DifferentSaltDiffers(t *testing.T) {
	t.Parallel()
	masterKey := []byte("master key material")
	a := deriveHKDF(t, masterKey, []byte("salt-a"), nil, 32)
	b := deriveHKDF(t, masterKey, []byte("salt-b"), nil, 32)
	if bytes.Equal(a, b) {
		t.Error("different HKDF salts produced identical output")
	}
}

// TestHKDFInto_EmptyIKMPin pins that an empty secret is accepted (HKDF is
// defined for it) — a deliberate behavior pin for the security review
// record, not an endorsement of empty input keying material.
func TestHKDFInto_EmptyIKMPin(t *testing.T) {
	t.Parallel()
	out, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()
	if err := HKDFSHA256Into(nil, []byte("salt"), nil, out); err != nil {
		t.Fatalf("HKDFSHA256Into with empty IKM: %v", err)
	}
	want := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, nil, []byte("salt"), nil), want); err != nil {
		t.Fatalf("direct hkdf read: %v", err)
	}
	if !bytes.Equal(readBuf(t, out), want) {
		t.Error("empty-IKM output does not match direct x/crypto/hkdf derivation")
	}
}

// TestHKDFInto_OutputCeiling pins both sides of the RFC 5869 255×HashLen
// boundary (8160 bytes for SHA-256): the maximum succeeds, one byte more
// is rejected up front with the buffer left untouched (all zeros).
func TestHKDFInto_OutputCeiling(t *testing.T) {
	t.Parallel()
	const maxOut = 255 * sha256.Size // 8160

	ok, err := secmem.NewEmptyBuffer(maxOut)
	if err != nil {
		t.Fatalf("NewEmptyBuffer(%d): %v", maxOut, err)
	}
	defer ok.Destroy()
	if err := HKDFSHA256Into([]byte("k"), nil, nil, ok); err != nil {
		t.Errorf("HKDFSHA256Into at the exact 255*HashLen limit failed: %v", err)
	}

	over, err := secmem.NewEmptyBuffer(maxOut + 1)
	if err != nil {
		t.Fatalf("NewEmptyBuffer(%d): %v", maxOut+1, err)
	}
	defer over.Destroy()
	if err := HKDFSHA256Into([]byte("k"), nil, nil, over); err == nil {
		t.Fatal("expected error for output exceeding 255*HashLen, got nil")
	}
	if got := readBuf(t, over); !bytes.Equal(got, make([]byte, maxOut+1)) {
		t.Error("failed derivation left non-zero bytes in the output buffer")
	}
}

func TestHKDFInto_NilHashAndBadBuffers(t *testing.T) {
	t.Parallel()
	out, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()

	if err := HKDFInto(nil, []byte("k"), nil, nil, out); err == nil {
		t.Error("expected error for nil hash function")
	}
	if err := HKDFSHA256Into([]byte("k"), nil, nil, nil); err == nil {
		t.Error("expected error for nil output buffer")
	}
}

func TestHKDFInto_DestroyedAndSealedOut(t *testing.T) {
	t.Parallel()
	destroyed, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	_ = destroyed.Destroy()
	err = HKDFSHA256Into([]byte("k"), nil, nil, destroyed)
	if !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("destroyed out: error = %v, want wrap of secmem.ErrDestroyed", err)
	}

	sealed, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer sealed.Destroy()
	if err := sealed.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	err = HKDFSHA256Into([]byte("k"), nil, nil, sealed)
	if !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("sealed out: error = %v, want wrap of secmem.ErrSealed", err)
	}
}

// TestArgon2IDKeyInto_KnownVector checks against x/crypto/argon2's Argon2id
// known-answer test (generated with the PHC reference implementation's CLI,
// per that file's own provenance note) — the vector actually reachable
// through the public IDKey API this package wraps. RFC 9106's headline
// vector sets secret-key and associated-data parameters that
// golang.org/x/crypto/argon2 does not expose, so it cannot be reproduced
// through this (or any mainstream Go) Argon2 API.
func TestArgon2IDKeyInto_KnownVector(t *testing.T) {
	t.Parallel()
	wantHash := mustDecodeHex(t, "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb")

	out, err := secmem.NewEmptyBuffer(len(wantHash))
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()

	if err := Argon2IDKeyInto([]byte("password"), []byte("somesalt"), 1, 64, 1, out); err != nil {
		t.Fatalf("Argon2IDKeyInto: %v", err)
	}
	if got := readBuf(t, out); !bytes.Equal(got, wantHash) {
		t.Errorf("hash mismatch\n  got:  %x\n  want: %x", got, wantHash)
	}
}

// TestArgon2IDKeyInto_ZeroCostParams_ErrorNotPanic holds the library's
// no-panic contract on the newly exposed cost-parameter surface: x/crypto
// panics on time<1 and threads<1; this wrapper must catch both first.
func TestArgon2IDKeyInto_ZeroCostParams_ErrorNotPanic(t *testing.T) {
	t.Parallel()
	out, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()

	if err := Argon2IDKeyInto([]byte("p"), []byte("s"), 0, 64, 1, out); err == nil {
		t.Error("expected error for time=0, got nil")
	}
	if err := Argon2IDKeyInto([]byte("p"), []byte("s"), 1, 64, 0, out); err == nil {
		t.Error("expected error for threads=0, got nil")
	}
	// memory=0 is raised to the algorithm minimum by x/crypto itself — it
	// must derive successfully, not error or panic.
	if err := Argon2IDKeyInto([]byte("p"), []byte("s"), 1, 0, 1, out); err != nil {
		t.Errorf("memory=0 should clamp and succeed, got: %v", err)
	}
}

func TestArgon2IDKeyInto_DifferentSaltDiffers(t *testing.T) {
	t.Parallel()
	password := []byte("correct horse battery staple")

	a, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer a.Destroy()
	b, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer b.Destroy()

	if err := Argon2IDKeyInto(password, []byte("salt-a-16-bytes!"), 1, 64, 1, a); err != nil {
		t.Fatalf("Argon2IDKeyInto a: %v", err)
	}
	if err := Argon2IDKeyInto(password, []byte("salt-b-16-bytes!"), 1, 64, 1, b); err != nil {
		t.Fatalf("Argon2IDKeyInto b: %v", err)
	}
	if bytes.Equal(readBuf(t, a), readBuf(t, b)) {
		t.Error("different Argon2id salts produced identical output")
	}
}

func TestArgon2IDKeyInto_NilAndBadBuffers(t *testing.T) {
	t.Parallel()
	if err := Argon2IDKeyInto([]byte("p"), []byte("s"), 1, 64, 1, nil); err == nil {
		t.Error("expected error for nil output buffer")
	}

	destroyed, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	_ = destroyed.Destroy()
	err = Argon2IDKeyInto([]byte("p"), []byte("s"), 1, 64, 1, destroyed)
	if !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("destroyed out: error = %v, want wrap of secmem.ErrDestroyed", err)
	}

	sealed, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer sealed.Destroy()
	if err := sealed.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	err = Argon2IDKeyInto([]byte("p"), []byte("s"), 1, 64, 1, sealed)
	if !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("sealed out: error = %v, want wrap of secmem.ErrSealed", err)
	}
}

func TestArgon2DeriveInto_UsesPackageDefaults(t *testing.T) {
	t.Parallel()
	out, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer out.Destroy()

	if err := Argon2DeriveInto([]byte("password"), []byte("some 16 byte sal"), out); err != nil {
		t.Fatalf("Argon2DeriveInto: %v", err)
	}

	want, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer want.Destroy()
	if err := Argon2IDKeyInto([]byte("password"), []byte("some 16 byte sal"), Argon2Time, Argon2Memory, Argon2Threads, want); err != nil {
		t.Fatalf("Argon2IDKeyInto: %v", err)
	}

	if !bytes.Equal(readBuf(t, out), readBuf(t, want)) {
		t.Error("Argon2DeriveInto did not match Argon2IDKeyInto called with the package's own default constants")
	}
}
