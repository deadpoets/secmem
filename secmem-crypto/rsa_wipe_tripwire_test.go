package secmemcrypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/deadpoets/secmem"
)

// These tests pin wipeECDHPrivateKey to the current toolchain. The helper
// reaches crypto/ecdh's unexported scalar field by name via reflection,
// which no compiler check protects: a stdlib rename or retype would make the
// lookup fail with every other test still green. The tripwire below turns
// that into a red run on the first CI pass of a new Go version — the same
// discipline livewipe_test.go and wipehelpers_block3_test.go apply to the
// ECDSA and RSA wipe helpers, which this one previously lacked.

// ecdhTestKeys returns one parsed key per crypto/ecdh curve family whose
// scalar storage could plausibly diverge (X25519 vs. a NIST curve).
func ecdhTestKeys(t *testing.T) map[string]*ecdh.PrivateKey {
	t.Helper()
	keys := map[string]*ecdh.PrivateKey{}
	for name, curve := range map[string]ecdh.Curve{"X25519": ecdh.X25519(), "P256": ecdh.P256()} {
		k, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("%s GenerateKey: %v", name, err)
		}
		keys[name] = k
	}
	return keys
}

// TestWipeECDHPrivateKey_Tripwire proves, on this toolchain, that (1) the
// reflected field resolves to a non-empty []byte the length of the scalar,
// (2) the wipe reports success, and (3) the scalar is actually zero
// afterwards as seen through crypto/ecdh's own Bytes() — an oracle
// independent of the reflection path, so a field that still exists but no
// longer holds the scalar is caught too.
func TestWipeECDHPrivateKey_Tripwire(t *testing.T) {
	t.Parallel()
	for name, k := range ecdhTestKeys(t) {
		before := k.Bytes()
		if bytes.Equal(before, make([]byte, len(before))) {
			t.Fatalf("%s: generated scalar is all zero", name)
		}

		scalar, err := ecdhScalar(k, ecdhScalarField)
		if err != nil {
			t.Fatalf("%s: crypto/ecdh.PrivateKey.%s no longer resolves on this toolchain — update ecdhScalarField: %v", name, ecdhScalarField, err)
		}
		if !bytes.Equal(scalar, before) {
			t.Fatalf("%s: reflected field %q holds %x, want the scalar %x", name, ecdhScalarField, scalar, before)
		}

		if err := wipeECDHPrivateKey(k); err != nil {
			t.Fatalf("%s: wipeECDHPrivateKey: %v", name, err)
		}
		if after := k.Bytes(); !bytes.Equal(after, make([]byte, len(after))) {
			t.Fatalf("%s: scalar after wipe = %x, want all zero (the wipe did not reach crypto/ecdh's storage)", name, after)
		}
	}

	if err := wipeECDHPrivateKey(nil); err != nil {
		t.Errorf("wipeECDHPrivateKey(nil) = %v, want nil", err)
	}
}

// TestWipeECDHPrivateKey_ReportsUnresolvableField pins the fail-loud half:
// when the field cannot be found the helper must say so, not return as if it
// had wiped. The original helper silently returned in exactly this case.
func TestWipeECDHPrivateKey_ReportsUnresolvableField(t *testing.T) {
	t.Parallel()
	k := ecdhTestKeys(t)["X25519"]
	if _, err := ecdhScalar(k, "noSuchField"); err == nil {
		t.Fatal("ecdhScalar on a missing field reported success")
	} else if !strings.Contains(err.Error(), "NOT wiped") {
		t.Fatalf("missing-field error does not say the scalar was not wiped: %v", err)
	}
	// A field that exists but is not a []byte (curve is an interface).
	if _, err := ecdhScalar(k, "curve"); err == nil {
		t.Fatal("ecdhScalar on a non-[]byte field reported success")
	}
	if scalar := k.Bytes(); bytes.Equal(scalar, make([]byte, len(scalar))) {
		t.Fatal("a failed lookup must leave the key untouched")
	}
}

// TestNewRSASigner_RejectsECDHKey_WipesLiveTransient wraps the package's
// wipe var to alias the parsed key's scalar at the moment the reject path
// wipes it, and asserts that exact backing array is zero once NewRSASigner
// has returned its error. Must not call t.Parallel(): it swaps a package
// var (see livewipe_test.go).
func TestNewRSASigner_RejectsECDHKey_WipesLiveTransient(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	buf, err := secmem.NewBuffer(der) // copies into secure memory, wipes der
	if err != nil {
		t.Skipf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	var fired bool
	var aliased []byte
	orig := wipeECDHPrivateKey
	wipeECDHPrivateKey = func(k *ecdh.PrivateKey) error {
		fired = true
		if k != nil {
			if s, err := ecdhScalar(k, ecdhScalarField); err == nil {
				aliased = s
			}
		}
		return orig(k)
	}
	defer func() { wipeECDHPrivateKey = orig }()

	_, rerr := NewRSASigner(buf)
	if rerr == nil {
		t.Fatal("NewRSASigner accepted an X25519 key; want rejection")
	}
	if strings.Contains(rerr.Error(), "NOT wiped") {
		t.Fatalf("reject path reported a failed wipe on this toolchain: %v", rerr)
	}
	if !fired {
		t.Fatal("the ECDH reject path did not call wipeECDHPrivateKey")
	}
	if len(aliased) == 0 {
		t.Fatal("wipe hook fired but could not alias the scalar")
	}
	if !bytes.Equal(aliased, make([]byte, len(aliased))) {
		t.Fatalf("parsed ECDH scalar after rejection = %x, want all zero", aliased)
	}
}
