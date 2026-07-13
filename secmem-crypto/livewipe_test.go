package secmemcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"
)

// These tests prove the deferred wipe in Sign fires on the LIVE transient
// key — not just that the wipe helpers zero limbs in isolation (that is
// wipehelpers_block3_test.go). Each wraps the package's wipe var to alias
// the transient's limb backing arrays at the moment Sign wipes them, runs a
// real Sign, and asserts afterward that those exact arrays are zero. If a
// future change drops the `defer wipe...` from Sign, the hook never fires
// and the test fails.
//
// They must NOT call t.Parallel(): they swap a package var, which is only
// safe while the package's parallel tests are paused (Go runs all
// non-parallel tests to completion before releasing parallel ones).

func TestECDSASigner_SignWipesLiveTransient(t *testing.T) {
	signer, err := GenerateECDSASigner(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSASigner: %v", err)
	}
	defer signer.Destroy()

	var fired bool
	var dLimbs []big.Word
	orig := wipeECDSAPrivateKey
	wipeECDSAPrivateKey = func(priv *ecdsa.PrivateKey) {
		fired = true
		if priv != nil {
			// Only the deprecated priv.D field read needs suppressing; the
			// *big.Int Bits() below is an ordinary method on the aliased value.
			//nolint:staticcheck // SA1019: reading the raw D field to alias its limbs is the point
			//lint:ignore SA1019 reading the raw D field to alias its limbs is the point
			if d := priv.D; d != nil {
				dLimbs = d.Bits()
			}
		}
		orig(priv) // the real wipe zeroes the array dLimbs aliases
	}
	defer func() { wipeECDSAPrivateKey = orig }()

	digest := sha256.Sum256([]byte("wipe me"))
	if _, err := signer.Sign(nil, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !fired {
		t.Fatal("Sign did not wipe its transient key — the deferred wipe is missing")
	}
	if dLimbs == nil {
		t.Fatal("wipe hook fired but captured no limbs")
	}
	assertLimbsZero(t, "ECDSA transient D after Sign", dLimbs)
}

func TestRSASigner_SignWipesLiveTransient(t *testing.T) {
	signer, err := NewRSASigner(cloneRSADER(t))
	if err != nil {
		t.Fatalf("NewRSASigner: %v", err)
	}
	defer signer.Destroy()

	var fired bool
	var dLimbs, pLimbs, qLimbs []big.Word
	orig := wipeRSAPrivateKey
	wipeRSAPrivateKey = func(key *rsa.PrivateKey) {
		fired = true
		if key != nil {
			if key.D != nil {
				dLimbs = key.D.Bits()
			}
			if len(key.Primes) >= 2 {
				pLimbs = key.Primes[0].Bits()
				qLimbs = key.Primes[1].Bits()
			}
		}
		orig(key)
	}
	defer func() { wipeRSAPrivateKey = orig }()

	digest := sha256.Sum256([]byte("wipe me"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !fired {
		t.Fatal("Sign did not wipe its transient key — the deferred wipe is missing")
	}
	if dLimbs == nil || pLimbs == nil || qLimbs == nil {
		t.Fatal("wipe hook fired but did not capture D and both primes")
	}
	assertLimbsZero(t, "RSA transient D after Sign", dLimbs)
	assertLimbsZero(t, "RSA transient P after Sign", pLimbs)
	assertLimbsZero(t, "RSA transient Q after Sign", qLimbs)
}
