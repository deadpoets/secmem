package secmemcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/deadpoets/secmem"
)

// aesGCMViews returns byte views of every region the layout wipes inside
// aead, aliasing its storage: the tripwire's path to the arrays.
func aesGCMViews(t *testing.T, l *aesGCMLayout, aead cipher.AEAD) map[string][]byte {
	t.Helper()
	if reflect.TypeOf(aead) != l.typ {
		t.Fatalf("aead is %T, layout is for %v", aead, l.typ)
	}
	base := reflect.ValueOf(aead).UnsafePointer()
	m := map[string][]byte{}
	for _, r := range l.regions {
		m[r.name] = unsafe.Slice((*byte)(unsafe.Add(base, r.off)), r.size)
	}
	return m
}

func mustKeyBuffer(t *testing.T, key []byte) *secmem.SecureBuffer {
	t.Helper()
	b, err := secmem.NewBuffer(bytes.Clone(key))
	if err != nil {
		t.Skipf("NewBuffer: %v", err)
	}
	t.Cleanup(func() { _ = b.Destroy() })
	return b
}

func allZeroBytes(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

// TestWithAESGCM_MatchesStandardLibrary: for every key size, what the lent
// AEAD seals opens with a plain crypto/cipher GCM and the other way round,
// byte for byte, and a tampered ciphertext is refused.
func TestWithAESGCM_MatchesStandardLibrary(t *testing.T) {
	for _, size := range []int{16, 24, 32} {
		key, nonce := randBytes(t, size), randBytes(t, 12)
		pt, ad := randBytes(t, 1000), randBytes(t, 33)
		blk, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := cipher.NewGCM(blk)
		if err != nil {
			t.Fatal(err)
		}
		want := ref.Seal(nil, nonce, pt, ad)

		err = WithAESGCM(mustKeyBuffer(t, key), func(a cipher.AEAD) error {
			if a.NonceSize() != 12 || a.Overhead() != 16 {
				t.Errorf("AES-%d: nonce %d overhead %d, want 12 and 16", size*8, a.NonceSize(), a.Overhead())
			}
			if got := a.Seal(nil, nonce, pt, ad); !bytes.Equal(got, want) {
				t.Errorf("AES-%d: Seal differs from crypto/cipher", size*8)
			}
			if got, err := a.Open(nil, nonce, want, ad); err != nil || !bytes.Equal(got, pt) {
				t.Errorf("AES-%d: Open of a crypto/cipher ciphertext: %v", size*8, err)
			}
			bad := bytes.Clone(want)
			bad[0] ^= 1
			if _, err := a.Open(nil, nonce, bad, ad); err == nil {
				t.Errorf("AES-%d: tampered ciphertext opened", size*8)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("AES-%d: %v", size*8, err)
		}
	}
}

// TestWithAESGCM_WithSealFromOpenInto: the lent AEAD satisfies OpenInto's
// in-place check, so key and plaintext both stay in locked memory.
func TestWithAESGCM_WithSealFromOpenInto(t *testing.T) {
	plain := randBytes(t, 64)
	pt := mustKeyBuffer(t, plain)
	back, err := secmem.NewEmptyBuffer(64)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	defer back.Destroy()
	nonce := randBytes(t, 12)
	if err := WithAESGCM(mustKeyBuffer(t, randBytes(t, 32)), func(a cipher.AEAD) error {
		ct, err := SealFrom(nil, a, nonce, pt, nil)
		if err != nil {
			return err
		}
		return OpenInto(back, a, nonce, ct, nil)
	}); err != nil {
		t.Fatal(err)
	}
	if ok, err := back.ConstantTimeEqual(plain); err != nil || !ok {
		t.Fatalf("round trip through SealFrom/OpenInto: equal=%v err=%v", ok, err)
	}
}

// TestWithAESGCM_WipesEverySchedule is the tripwire for the reflection wipe:
// on this toolchain the GCM layout resolves to both round-key arrays of the
// Block copy (and, on amd64 and arm64, the GHASH table); inside the callback
// the Block's arrays and the Block copy's hold the expanded key; after the
// callback returns normally, with an error, or by panicking, every region is
// zero and the GCM object no longer computes AES-GCM under the key — an
// oracle independent of the reflection that did the wipe.
func TestWithAESGCM_WipesEverySchedule(t *testing.T) {
	layout, err := aesGCMLayoutReady()
	if err != nil {
		t.Fatalf("layout does not resolve on %s: %v", runtime.Version(), err)
	}
	names := map[string]bool{}
	for _, r := range layout.regions {
		names[r.name] = true
	}
	if !names["cipher.enc"] || !names["cipher.dec"] {
		t.Fatalf("layout regions %v lack the Block copy's round keys", layout.regions)
	}
	if (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") && !names["productTable"] {
		t.Fatalf("layout regions %v lack the GHASH table this architecture's GCM carries", layout.regions)
	}

	key, nonce, pt := randBytes(t, 32), randBytes(t, 12), randBytes(t, 40)
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatal(err)
	}
	want := ref.Seal(nil, nonce, pt, nil)
	sentinel := errors.New("callback failed")

	for _, exit := range []string{"return", "error", "panic"} {
		t.Run(exit, func(t *testing.T) {
			var gotBlk cipher.Block
			var gotAEAD cipher.AEAD
			withAESGCMProbe = func(b cipher.Block, a cipher.AEAD) { gotBlk, gotAEAD = b, a }
			defer func() { withAESGCMProbe = nil }()

			inside := map[string]bool{}
			var err error
			panicked := func() (p any) {
				defer func() { p = recover() }()
				err = WithAESGCM(mustKeyBuffer(t, key), func(cipher.AEAD) error {
					for name, v := range aesGCMViews(t, layout, gotAEAD) {
						inside["gcm."+name] = !allZeroBytes(v)
					}
					for _, f := range aesRoundKeyFields {
						v, verr := aesRoundKeys(gotBlk, f)
						if verr != nil {
							t.Fatal(verr)
						}
						inside["block."+f] = !allZeroBytes(v)
					}
					switch exit {
					case "error":
						return sentinel
					case "panic":
						panic("callback panicked")
					}
					return nil
				})
				return nil
			}()
			switch exit {
			case "return":
				if err != nil || panicked != nil {
					t.Fatalf("err %v, panic %v", err, panicked)
				}
			case "error":
				if !errors.Is(err, sentinel) {
					t.Errorf("callback error not propagated: %v", err)
				}
			case "panic":
				if panicked == nil {
					t.Error("the callback's panic did not propagate")
				}
			}
			for _, name := range []string{"gcm.cipher.enc", "gcm.cipher.dec", "block.enc", "block.dec"} {
				if !inside[name] {
					t.Errorf("%s was zero inside the callback: the test would observe nothing", name)
				}
			}
			for name, v := range aesGCMViews(t, layout, gotAEAD) {
				if !allZeroBytes(v) {
					t.Errorf("gcm.%s not zero after the callback", name)
				}
			}
			for _, f := range aesRoundKeyFields {
				v, verr := aesRoundKeys(gotBlk, f)
				if verr != nil {
					t.Fatal(verr)
				}
				if !allZeroBytes(v) {
					t.Errorf("block.%s not zero after the callback", f)
				}
			}
			if got := gotAEAD.Seal(nil, nonce, pt, nil); bytes.Equal(got, want) {
				t.Error("the wiped GCM object still computes AES-GCM under the key")
			}
		})
	}
}

// TestWithAESGCM_RetainedAEADPanics: an AEAD kept past the callback refuses
// both directions with ErrAEADOutOfScope instead of running on a wiped
// schedule.
func TestWithAESGCM_RetainedAEADPanics(t *testing.T) {
	var kept cipher.AEAD
	if err := WithAESGCM(mustKeyBuffer(t, randBytes(t, 32)), func(a cipher.AEAD) error { kept = a; return nil }); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(){
		"Seal": func() { kept.Seal(nil, make([]byte, 12), []byte("x"), nil) },
		"Open": func() { _, _ = kept.Open(nil, make([]byte, 12), make([]byte, 17), nil) },
	} {
		func() {
			defer func() {
				if r := recover(); r != ErrAEADOutOfScope { //nolint:errorlint // the panic value itself is the sentinel
					t.Errorf("%s after the callback: recovered %v, want ErrAEADOutOfScope", name, r)
				}
			}()
			f()
		}()
	}
	if kept.NonceSize() != 12 || kept.Overhead() != 16 {
		t.Error("NonceSize/Overhead changed after the callback")
	}
}

func TestWithAESGCM_BadInputs(t *testing.T) {
	ok := func(cipher.AEAD) error { return nil }
	if err := WithAESGCM(nil, ok); err == nil {
		t.Error("nil key accepted")
	}
	if err := WithAESGCM(mustKeyBuffer(t, randBytes(t, 32)), nil); err == nil {
		t.Error("nil callback accepted")
	}
	called := false
	err := WithAESGCM(mustKeyBuffer(t, randBytes(t, 20)), func(cipher.AEAD) error { called = true; return nil })
	if err == nil || !strings.Contains(err.Error(), "20 bytes") {
		t.Errorf("20-byte key: %v, want a size error", err)
	}
	if called {
		t.Error("callback ran for a bad key size")
	}
}

// TestResolveAESGCMLayout_RefusesUnexpectedShapes: a layout the wipe cannot
// trust is an error, never a partial layout.
func TestResolveAESGCMLayout_RefusesUnexpectedShapes(t *testing.T) {
	// Fake layouts: only their reflected shape is used, never their fields.
	type noCipher struct{ x int } //nolint:unused // reflected shape only
	type badRounds struct {
		cipher struct{ enc, dec []uint32 } //nolint:unused // reflected shape only
	}
	type badTable struct {
		cipher       struct{ enc, dec [60]uint32 } //nolint:unused // reflected shape only
		productTable []byte                        //nolint:unused // reflected shape only
	}
	type portable struct {
		cipher struct{ enc, dec [60]uint32 } //nolint:unused // reflected shape only
	}
	for name, typ := range map[string]reflect.Type{
		"not a pointer":     reflect.TypeOf(noCipher{}),
		"no cipher":         reflect.TypeOf(&noCipher{}),
		"round keys slices": reflect.TypeOf(&badRounds{}),
		"table a slice":     reflect.TypeOf(&badTable{}),
	} {
		if l, err := resolveAESGCMLayout(typ); err == nil {
			t.Errorf("%s: resolved to %+v, want an error", name, l)
		}
	}
	if l, err := resolveAESGCMLayout(reflect.TypeOf(&portable{})); err != nil || len(l.regions) != 2 {
		t.Errorf("a GCM without a GHASH table (the portable build): %+v, %v; want the two round-key arrays", l, err)
	}
}
