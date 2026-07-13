package secmemcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"
	"testing"
)

// These tests pin the zeroing the block-3 honesty caveats claim ("zeroes
// the transient's D limbs", "zeroes every exported big.Int limb") — the
// block-1 WipeScalar standard applied to the big.Int wipe helpers. The
// limb slices are captured via Bits() BEFORE the wipe: a future refactor
// to x.SetInt64(0)/x.Set(zero) would abandon the old backing array unwiped
// (the exact trap wipeBigInt's comment warns about) and these captured
// aliases would catch it.

func assertLimbsZero(t *testing.T, name string, limbs []big.Word) {
	t.Helper()
	for i, w := range limbs {
		if w != 0 {
			t.Errorf("%s: limb %d = %#x after wipe, want 0", name, i, w)
			return
		}
	}
}

func TestWipeBigInt(t *testing.T) {
	t.Parallel()
	x := new(big.Int).SetBytes([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05})
	limbs := x.Bits() // aliases the backing array
	if len(limbs) == 0 {
		t.Fatal("test value has no limbs")
	}
	wipeBigInt(x)
	assertLimbsZero(t, "wipeBigInt", limbs)

	wipeBigInt(nil) // must not panic
}

func TestWipeECDSAPrivateKey(t *testing.T) {
	t.Parallel()
	buf := scalarBufFromHex(t, elliptic.P256(),
		"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
	defer buf.Destroy()

	var priv *ecdsa.PrivateKey
	if err := buf.WithBytesErr(func(scalar []byte) error {
		var perr error
		priv, perr = ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
		return perr
	}); err != nil {
		t.Fatalf("ParseRawPrivateKey: %v", err)
	}

	//nolint:staticcheck // SA1019: capturing the raw limbs to verify the wipe reached them is the point
	//lint:ignore SA1019 capturing the raw limbs to verify the wipe reached them is the point
	limbs := priv.D.Bits()
	if len(limbs) == 0 {
		t.Fatal("parsed key has no D limbs")
	}
	wipeECDSAPrivateKey(priv)
	assertLimbsZero(t, "wipeECDSAPrivateKey(D)", limbs)

	wipeECDSAPrivateKey(nil) // must not panic
}

func TestWipeRSAPrivateKey(t *testing.T) {
	t.Parallel()
	key := stdlibRSAKey(t) // fresh materialization owned by this test

	nBefore := new(big.Int).Set(key.N)
	captured := map[string][]big.Word{
		"D":    key.D.Bits(),
		"P":    key.Primes[0].Bits(),
		"Q":    key.Primes[1].Bits(),
		"Dp":   key.Precomputed.Dp.Bits(),
		"Dq":   key.Precomputed.Dq.Bits(),
		"Qinv": key.Precomputed.Qinv.Bits(),
	}
	for name, limbs := range captured {
		if len(limbs) == 0 {
			t.Fatalf("field %s has no limbs — fixture not precomputed as expected", name)
		}
	}

	wipeRSAPrivateKey(key)
	for name, limbs := range captured {
		assertLimbsZero(t, "wipeRSAPrivateKey("+name+")", limbs)
	}
	if key.N.Cmp(nBefore) != 0 {
		t.Error("wipe touched the public modulus N")
	}

	wipeRSAPrivateKey(nil) // must not panic

	// A key with no precomputed values must not panic either.
	bare := &rsa.PrivateKey{}
	wipeRSAPrivateKey(bare)
}

// TestWipeRSAPrivateKey_CRTValues exercises the multi-prime CRT loop, which
// two-prime keys never populate (stdlib leaves CRTValues empty for them).
// No real multi-prime key is needed — a literal with known limbs suffices.
func TestWipeRSAPrivateKey_CRTValues(t *testing.T) {
	t.Parallel()
	mk := func() *big.Int { return new(big.Int).SetBytes([]byte{0xAA, 0xBB, 0xCC, 0xDD}) }
	key := &rsa.PrivateKey{}
	//nolint:staticcheck // SA1019: constructing deprecated CRTValues is the point — testing the multi-prime wipe path
	//lint:ignore SA1019 constructing deprecated CRTValues is the point — testing the multi-prime wipe path
	key.Precomputed.CRTValues = []rsa.CRTValue{{Exp: mk(), Coeff: mk(), R: mk()}}
	//nolint:staticcheck // SA1019: as above
	//lint:ignore SA1019 as above
	crt := key.Precomputed.CRTValues
	exp, coeff, r := crt[0].Exp.Bits(), crt[0].Coeff.Bits(), crt[0].R.Bits()

	wipeRSAPrivateKey(key)
	assertLimbsZero(t, "CRTValues.Exp", exp)
	assertLimbsZero(t, "CRTValues.Coeff", coeff)
	assertLimbsZero(t, "CRTValues.R", r)
}
