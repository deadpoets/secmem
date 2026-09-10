package secmemcrypto

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"reflect"
	"strings"
	"testing"
)

// These tests pin wipeRSAFIPSKey to the current toolchain, the way
// aeswipe_test.go and mlkemwipe_test.go pin the other reflection wipes:
// the helper reaches crypto/rsa's unexported FIPS-form key and the bigmod
// types inside it by name, which no compiler check protects, so a stdlib
// refactor must turn into a red run on the first CI pass of a new Go
// version — not into a Sign that still succeeds over a copy of d, p and q
// that quietly stopped being wiped.

// rsaFIPSViews returns the byte views over the FIPS-form key's secret
// storage for a key that must have one.
func rsaFIPSViews(t *testing.T, key *rsa.PrivateKey) [][]byte {
	t.Helper()
	fips, err := rsaFIPSKey(key)
	if err != nil {
		t.Fatalf("rsa.PrecomputedValues.%s no longer resolves on this toolchain — update rsawipe.go: %v", rsaFIPSField, err)
	}
	if !fips.IsValid() {
		t.Fatal("the parsed key carries no FIPS-form key: crypto/x509 no longer precomputes on parse, so Sign's copy is not the one being wiped")
	}
	views, err := rsaFIPSSecretViews(fips)
	if err != nil {
		t.Fatalf("the FIPS-form key's fields no longer resolve on this toolchain — update rsaFIPSSecretFields: %v", err)
	}
	return views
}

// TestWipeRSAFIPSKey_Tripwire proves, on this toolchain, that (1) the
// reflected fields resolve to the ten secret slices and words a two-prime
// key holds (d; p, q with their limbs, R² and m0inv; dP, dQ; qInv), all
// non-zero on a freshly parsed key, (2) the wipe reports success, and (3)
// crypto/rsa's own consistency check — Validate compares the exported
// big.Ints against the FIPS-form key — fails afterwards: an oracle
// independent of the reflection path, so a field that still exists but is
// no longer what the key uses is caught too.
func TestWipeRSAFIPSKey_Tripwire(t *testing.T) {
	t.Parallel()
	key := stdlibRSAKey(t)
	if err := key.Validate(); err != nil {
		t.Fatalf("fresh key does not validate: %v", err)
	}
	views := rsaFIPSViews(t, key)
	if len(views) != 10 {
		t.Fatalf("resolved %d secret views, want 10 (d, p×3, q×3, dP, dQ, qInv)", len(views))
	}
	total := 0
	for i, v := range views {
		if len(v) == 0 || bytes.Equal(v, make([]byte, len(v))) {
			t.Fatalf("view %d is empty or all zero on a freshly parsed key: not the secret", i)
		}
		total += len(v)
	}
	// d and qInv are N-sized Nats, dP/dQ half that, p and q half each plus
	// R² of the same width and one word: well over 4×256 bytes for 2048 bits.
	if total < 4*256 {
		t.Fatalf("secret views total %d bytes, implausibly small for a 2048-bit key", total)
	}

	if err := wipeRSAFIPSKey(key); err != nil {
		t.Fatalf("wipeRSAFIPSKey: %v", err)
	}
	for i, v := range views {
		if !bytes.Equal(v, make([]byte, len(v))) {
			t.Fatalf("view %d still holds the secret after the wipe", i)
		}
	}
	if err := key.Validate(); err == nil {
		t.Fatal("crypto/rsa still finds the FIPS-form key consistent with the big.Ints after the wipe: the reflected fields are not the key it uses")
	}
	if key.N.Sign() == 0 {
		t.Fatal("the wipe touched the public modulus")
	}

	if err := wipeRSAFIPSKey(nil); err != nil {
		t.Errorf("wipeRSAFIPSKey(nil) = %v, want nil", err)
	}
	if err := wipeRSAFIPSKey(&rsa.PrivateKey{}); err != nil {
		t.Errorf("wipeRSAFIPSKey on a key without a FIPS form = %v, want nil", err)
	}
}

// TestWipeRSAFIPSKey_GeneratedAndMultiPrime covers the two other shapes a
// key reaches the wipe in: straight from rsa.GenerateKey (GenerateRSASigner's
// path, which must also carry the FIPS-form copy) and a deprecated
// multi-prime key, whose FIPS form has no CRT fields — nil pointers the
// wipe must accept, not report.
func TestWipeRSAFIPSKey_GeneratedAndMultiPrime(t *testing.T) {
	t.Parallel()
	gen, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	views := rsaFIPSViews(t, gen)
	if err := wipeRSAFIPSKey(gen); err != nil {
		t.Fatalf("generated key: %v", err)
	}
	for i, v := range views {
		if !bytes.Equal(v, make([]byte, len(v))) {
			t.Fatalf("generated key: view %d not zero after the wipe", i)
		}
	}

	//nolint:staticcheck // SA1019: the deprecated multi-prime path is the point
	//lint:ignore SA1019 the deprecated multi-prime path is the point
	multi, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 1024)
	if err != nil {
		t.Skipf("GenerateMultiPrimeKey: %v", err)
	}
	multi.Precompute()
	fips, err := rsaFIPSKey(multi)
	if err != nil {
		t.Fatal(err)
	}
	if !fips.IsValid() {
		t.Skip("multi-prime key carries no FIPS-form key on this toolchain")
	}
	mviews, err := rsaFIPSSecretViews(fips)
	if err != nil {
		t.Fatalf("multi-prime key: %v", err)
	}
	if len(mviews) != 1 {
		t.Fatalf("multi-prime key resolved %d views, want 1 (d only; no CRT fields)", len(mviews))
	}
	if err := wipeRSAFIPSKey(multi); err != nil {
		t.Fatalf("multi-prime key: %v", err)
	}
	if !bytes.Equal(mviews[0], make([]byte, len(mviews[0]))) {
		t.Fatal("multi-prime key: d not zero after the wipe")
	}
}

// TestRSAFIPSSecretViews_ReportsUnresolvableLayout pins the fail-loud half:
// a struct that lacks the fields, or has them in the wrong shape, must be
// reported as NOT wiped with no views returned, never partially wiped.
func TestRSAFIPSSecretViews_ReportsUnresolvableLayout(t *testing.T) {
	t.Parallel()
	// The fake types are read only by reflection (FieldByName), which
	// neither linter can see, hence the explicit zero-value keys.
	type fakeNat struct{ limbs []uint32 } // wrong limb type
	type fakeModulus struct{ nat *fakeNat }
	type fakeKey struct {
		d    *fakeNat
		p, q *fakeModulus
		dP   []byte
		dQ   string // wrong shape
		qInv *fakeNat
	}
	for name, v := range map[string]any{
		"missing fields": &struct{ x int }{x: 0},
		"wrong shapes":   &fakeKey{d: &fakeNat{limbs: []uint32{1}}, p: &fakeModulus{nat: nil}, q: nil, dP: nil, dQ: "", qInv: nil},
	} {
		views, err := rsaFIPSSecretViews(reflect.ValueOf(v).Elem())
		if err == nil {
			t.Errorf("%s: reported success with %d views", name, len(views))
			continue
		}
		if !strings.Contains(err.Error(), "NOT wiped") || len(views) != 0 {
			t.Errorf("%s: error does not say the key was not wiped, or views were returned: %v", name, err)
		}
	}
}

// TestRSASigner_SignWipesLiveFIPSKey wraps the package's wipe var to alias
// the FIPS-form key's storage at the moment Sign wipes it, and asserts
// those exact slices are zero once Sign has returned — the counterpart of
// TestRSASigner_SignWipesLiveTransient for the copy that test could not
// see. Must not call t.Parallel(): it swaps a package var.
func TestRSASigner_SignWipesLiveFIPSKey(t *testing.T) {
	signer, err := NewRSASigner(cloneRSADER(t))
	if err != nil {
		t.Fatalf("NewRSASigner: %v", err)
	}
	defer signer.Destroy()

	var aliased [][]byte
	orig := wipeRSAPrivateKey
	wipeRSAPrivateKey = func(key *rsa.PrivateKey) error {
		if fips, err := rsaFIPSKey(key); err == nil && fips.IsValid() {
			if views, err := rsaFIPSSecretViews(fips); err == nil {
				aliased = views
			}
		}
		return orig(key)
	}
	defer func() { wipeRSAPrivateKey = orig }()

	digest := sha256.Sum256([]byte("wipe me"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(aliased) != 10 {
		t.Fatalf("aliased %d FIPS-form views at wipe time, want 10", len(aliased))
	}
	for i, v := range aliased {
		if !bytes.Equal(v, make([]byte, len(v))) {
			t.Errorf("FIPS-form view %d is not zero after Sign returned", i)
		}
	}
	pub, _ := signer.Public().(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature produced before the wipe does not verify: %v", err)
	}
}

// TestRSASigner_WipeFailureIsAnError pins the fail-closed contract: when the
// FIPS-form key cannot be located, Sign and the constructors return the
// error rather than reporting success over a live heap copy of the key.
func TestRSASigner_WipeFailureIsAnError(t *testing.T) {
	signer, err := NewRSASigner(cloneRSADER(t))
	if err != nil {
		t.Fatalf("NewRSASigner: %v", err)
	}
	defer signer.Destroy()

	orig := wipeRSAPrivateKey
	wipeRSAPrivateKey = func(key *rsa.PrivateKey) error {
		_ = orig(key)
		return errWipeSimulated
	}
	defer func() { wipeRSAPrivateKey = orig }()

	digest := sha256.Sum256([]byte("wipe me"))
	if sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatalf("Sign reported success (%d-byte signature) although the wipe failed", len(sig))
	} else if !strings.Contains(err.Error(), errWipeSimulated.Error()) {
		t.Fatalf("Sign error does not carry the wipe failure: %v", err)
	}
	der := cloneRSADER(t)
	defer der.Destroy() // ownership is not transferred on failure
	if s, err := NewRSASigner(der); err == nil {
		s.Destroy()
		t.Fatal("NewRSASigner reported success although the wipe failed")
	}
}
