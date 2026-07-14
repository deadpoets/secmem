package secmemcrypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"strconv"
	"sync"
	"testing"

	"github.com/deadpoets/secmem"
)

// scalarBufFromHex normalizes a hex scalar to the curve's fixed encoding
// size and places it in a fresh SecureBuffer.
func scalarBufFromHex(tb testing.TB, curve elliptic.Curve, hexStr string) *secmem.SecureBuffer {
	tb.Helper()
	d, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		tb.Fatalf("bad hex scalar %q", hexStr)
	}
	raw := make([]byte, scalarSize(curve))
	d.FillBytes(raw)
	buf, err := secmem.NewBuffer(raw)
	if err != nil {
		tb.Fatalf("NewBuffer: %v", err)
	}
	return buf
}

// TestECDSASigner_RFC6979 pins deterministic signatures (nil random) to the
// RFC 6979 test vectors, appendices A.2.5-A.2.7, SHA-256 rows. The P-256
// pair and the P-384 "sample" row were checked against the RFC text
// directly; the remaining rows match Go's own crypto/ecdsa test suite,
// which cites the same appendix.
func TestECDSASigner_RFC6979(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		curve elliptic.Curve
		key   string
		msg   string
		r, s  string
	}{
		{"P-256/sample", elliptic.P256(),
			"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
			"sample",
			"EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
			"F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"},
		{"P-256/test", elliptic.P256(),
			"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
			"test",
			"F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
			"019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"},
		{"P-384/sample", elliptic.P384(),
			"6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
			"sample",
			"21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD",
			"F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0"},
		{"P-384/test", elliptic.P384(),
			"6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
			"test",
			"6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB51D451559F918EEDAF2293BE5B475CC8F0188636B",
			"2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D51AB373F9845C0514EEFB14024787265"},
		{"P-521/sample", elliptic.P521(),
			"0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
			"sample",
			"1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7",
			"04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC"},
		{"P-521/test", elliptic.P521(),
			"0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
			"test",
			"00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D8071042EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656AA8",
			"0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694E86"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewECDSASigner(tc.curve, scalarBufFromHex(t, tc.curve, tc.key))
			if err != nil {
				t.Fatalf("NewECDSASigner: %v", err)
			}
			defer s.Destroy()

			digest := sha256.Sum256([]byte(tc.msg))
			sig, err := s.Sign(nil, digest[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			var parsed struct{ R, S *big.Int }
			if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
				t.Fatalf("signature is not ASN.1 SEQUENCE{r, s}: %v", err)
			}
			wantR, _ := new(big.Int).SetString(tc.r, 16)
			wantS, _ := new(big.Int).SetString(tc.s, 16)
			if parsed.R.Cmp(wantR) != 0 || parsed.S.Cmp(wantS) != 0 {
				t.Errorf("signature mismatch:\n got r=%X s=%X\nwant r=%X s=%X",
					parsed.R, parsed.S, wantR, wantS)
			}
			if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), digest[:], sig) {
				t.Error("stdlib VerifyASN1 rejects the signature")
			}
		})
	}
}

func TestECDSASigner_SignVerifyAllCurves(t *testing.T) {
	t.Parallel()
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			s, err := GenerateECDSASigner(curve)
			if err != nil {
				t.Fatalf("GenerateECDSASigner: %v", err)
			}
			defer s.Destroy()

			pub, ok := s.Public().(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("Public() = %T, want *ecdsa.PublicKey", s.Public())
			}
			if pub.Curve != curve {
				t.Errorf("public key curve = %v, want %v", pub.Curve.Params().Name, curve.Params().Name)
			}

			digest := sha256.Sum256([]byte("randomized signing"))
			sig1, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			sig2, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !ecdsa.VerifyASN1(pub, digest[:], sig1) || !ecdsa.VerifyASN1(pub, digest[:], sig2) {
				t.Error("stdlib VerifyASN1 rejects a signature")
			}
			if bytes.Equal(sig1, sig2) {
				t.Error("two randomized signatures are identical")
			}
		})
	}
}

// TestECDSASigner_DifferentialVsStdlib exports a generated scalar into a
// plain stdlib key and requires deterministic signatures from both paths to
// be byte-identical on every supported curve.
func TestECDSASigner_DifferentialVsStdlib(t *testing.T) {
	t.Parallel()
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			ours, err := GenerateECDSASigner(curve)
			if err != nil {
				t.Fatalf("GenerateECDSASigner: %v", err)
			}
			defer ours.Destroy()

			var std *ecdsa.PrivateKey
			if err := ours.WithScalar(func(scalar []byte) error {
				var perr error
				std, perr = ecdsa.ParseRawPrivateKey(curve, scalar)
				return perr
			}); err != nil {
				t.Fatalf("stdlib rejected our generated scalar: %v", err)
			}

			for _, msg := range []string{"a", "differential", "longer message for the third digest"} {
				digest := sha256.Sum256([]byte(msg))
				sigOurs, err := ours.Sign(nil, digest[:], crypto.SHA256)
				if err != nil {
					t.Fatalf("our Sign: %v", err)
				}
				sigStd, err := std.Sign(nil, digest[:], crypto.SHA256)
				if err != nil {
					t.Fatalf("stdlib Sign: %v", err)
				}
				if !bytes.Equal(sigOurs, sigStd) {
					t.Errorf("msg %q: signatures diverge:\n ours:   %x\n stdlib: %x", msg, sigOurs, sigStd)
				}
			}
		})
	}
}

func TestNewECDSASigner_BadInputs(t *testing.T) {
	t.Parallel()

	if _, err := NewECDSASigner(nil, nil); !errors.Is(err, ErrUnsupportedCurve) {
		t.Errorf("nil curve: error = %v, want ErrUnsupportedCurve", err)
	}
	// A *CurveParams is a valid elliptic.Curve but not one of the four
	// canonical instances ParseRawPrivateKey switches on.
	if _, err := NewECDSASigner(elliptic.P256().Params(), nil); !errors.Is(err, ErrUnsupportedCurve) {
		t.Errorf("non-canonical curve: error = %v, want ErrUnsupportedCurve", err)
	}
	if _, err := GenerateECDSASigner(elliptic.P256().Params()); !errors.Is(err, ErrUnsupportedCurve) {
		t.Errorf("GenerateECDSASigner(non-canonical): error = %v, want ErrUnsupportedCurve", err)
	}

	if _, err := NewECDSASigner(elliptic.P256(), nil); err == nil {
		t.Error("expected error for nil buffer")
	}

	destroyed, _ := secmem.NewEmptyBuffer(32)
	_ = destroyed.Destroy()
	if _, err := NewECDSASigner(elliptic.P256(), destroyed); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("destroyed buffer: error = %v, want wrap of ErrDestroyed", err)
	}

	short, _ := secmem.NewEmptyBuffer(16)
	defer short.Destroy()
	if _, err := NewECDSASigner(elliptic.P256(), short); !errors.Is(err, ErrBadScalarLength) {
		t.Errorf("wrong-size scalar: error = %v, want wrap of ErrBadScalarLength", err)
	}
	if short.IsDestroyed() {
		t.Error("ownership transferred on failure")
	}

	// Out-of-range scalars: zero, and the group order itself.
	zero, _ := secmem.NewEmptyBuffer(32)
	defer zero.Destroy()
	if _, err := NewECDSASigner(elliptic.P256(), zero); err == nil {
		t.Error("expected error for the zero scalar")
	}
	if zero.IsDestroyed() {
		t.Error("ownership transferred on failure")
	}

	order := scalarBufFromHex(t, elliptic.P256(), elliptic.P256().Params().N.Text(16))
	defer order.Destroy()
	if _, err := NewECDSASigner(elliptic.P256(), order); err == nil {
		t.Error("expected error for scalar == group order")
	}
}

func TestECDSASigner_DeterministicNeedsOpts(t *testing.T) {
	t.Parallel()
	s, err := GenerateECDSASigner(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSASigner: %v", err)
	}
	defer s.Destroy()
	digest := sha256.Sum256([]byte("x"))
	if _, err := s.Sign(nil, digest[:], nil); err == nil {
		t.Error("Sign(nil random, nil opts) should error, not panic downstream")
	}
	// crypto.Hash(0) is a non-nil opts that names no hash — stdlib's
	// deterministic path would panic on it; the guard must error instead.
	if _, err := s.Sign(nil, digest[:], crypto.Hash(0)); err == nil {
		t.Error("Sign(nil random, crypto.Hash(0)) should error, not panic downstream")
	}
}

// TestECDSASigner_ConcurrentSign exercises the production access pattern:
// crypto/tls drives crypto.Signer from concurrent handshake goroutines.
// Run under -race (the suite always is, per the Makefile/CI).
func TestECDSASigner_ConcurrentSign(t *testing.T) {
	t.Parallel()
	signer, err := GenerateECDSASigner(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSASigner: %v", err)
	}
	defer signer.Destroy()
	pub := signer.Public().(*ecdsa.PublicKey)

	const goroutines = 8
	const perGoroutine = 25
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*perGoroutine)

	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perGoroutine {
				digest := sha256.Sum256([]byte("concurrent " + strconv.Itoa(g) + "/" + strconv.Itoa(i)))
				sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
				if err != nil {
					errs <- err
					return
				}
				if !ecdsa.VerifyASN1(pub, digest[:], sig) {
					errs <- errors.New("concurrent signature failed verification")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestECDSASigner_SignDuringDestroy races Sign against Destroy: every Sign
// must return either a verifiable signature or a clean error — never a
// panic, never a corrupt signature. The transient parse + wipe inside the
// borrow closure is exactly the path that must stay safe under teardown.
func TestECDSASigner_SignDuringDestroy(t *testing.T) {
	t.Parallel()
	for round := range 5 {
		signer, err := GenerateECDSASigner(elliptic.P256())
		if err != nil {
			t.Fatalf("GenerateECDSASigner: %v", err)
		}
		pub := signer.Public().(*ecdsa.PublicKey)

		const goroutines = 4
		var wg sync.WaitGroup
		bad := make(chan string, goroutines*10)

		for g := range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range 10 {
					digest := sha256.Sum256([]byte("race " + strconv.Itoa(round) + "/" + strconv.Itoa(g) + "/" + strconv.Itoa(i)))
					sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
					if err != nil {
						continue // clean error during/after Destroy is the contract
					}
					if !ecdsa.VerifyASN1(pub, digest[:], sig) {
						bad <- "Sign returned a corrupt signature during Destroy race"
						return
					}
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = signer.Destroy()
		}()
		wg.Wait()
		close(bad)
		for msg := range bad {
			t.Error(msg)
		}
	}
}

func TestECDSASigner_PublicAndEqual(t *testing.T) {
	t.Parallel()
	s, err := GenerateECDSASigner(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSASigner: %v", err)
	}
	defer s.Destroy()

	pub := s.Public().(*ecdsa.PublicKey)
	if !s.Equal(pub) {
		t.Error("signer does not Equal its own public key")
	}

	// Mutating the returned copy must not corrupt the signer's copy.
	//nolint:staticcheck // SA1019: see above
	//lint:ignore SA1019 mutating the deprecated raw field is the point — proving the returned key is a defensive copy
	pub.X.SetInt64(42)
	if !s.Equal(s.Public()) {
		t.Error("mutating a returned public key corrupted the cached one")
	}

	other, err := GenerateECDSASigner(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSASigner: %v", err)
	}
	defer other.Destroy()
	if s.Equal(other.Public()) {
		t.Error("distinct keys compare equal")
	}
	if s.Equal(42) {
		t.Error("Equal(non-key type) = true")
	}
}

func TestECDSASigner_WithScalarRoundTrip(t *testing.T) {
	t.Parallel()
	s, err := GenerateECDSASigner(elliptic.P384())
	if err != nil {
		t.Fatalf("GenerateECDSASigner: %v", err)
	}
	defer s.Destroy()

	persisted := make([]byte, scalarSize(elliptic.P384()))
	if err := s.WithScalar(func(scalar []byte) error {
		copy(persisted, scalar) //nolint:secmem-lint // test persists the scalar to verify reload
		return nil
	}); err != nil {
		t.Fatalf("WithScalar: %v", err)
	}

	buf, err := secmem.NewBuffer(persisted)
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	restored, err := NewECDSASigner(elliptic.P384(), buf)
	if err != nil {
		t.Fatalf("NewECDSASigner(restored): %v", err)
	}
	defer restored.Destroy()

	if !s.Equal(restored.Public()) {
		t.Error("restored key has a different public key")
	}
	digest := sha256.Sum256([]byte("round trip"))
	sig1, err := s.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig2, err := restored.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("restored Sign: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Error("restored key signs differently")
	}
}

func TestECDSASigner_NilAndDestroyed(t *testing.T) {
	t.Parallel()
	var s *ECDSASigner
	if _, err := s.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("nil.Sign error = %v", err)
	}
	if err := s.WithScalar(func([]byte) error { return nil }); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("nil.WithScalar error = %v", err)
	}
	if s.Public() != nil {
		t.Error("nil.Public() != nil")
	}
	if s.Equal(42) {
		t.Error("nil.Equal = true")
	}
	if err := s.Destroy(); err != nil {
		t.Errorf("nil.Destroy() = %v", err)
	}

	live, err := GenerateECDSASigner(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSASigner: %v", err)
	}
	pub := live.Public()
	_ = live.Destroy()
	digest := sha256.Sum256([]byte("y"))
	if _, err := live.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("Sign after Destroy: error = %v, want wrap of ErrDestroyed", err)
	}
	if live.Public() == nil || !live.Equal(pub) {
		t.Error("cached public key should survive Destroy")
	}
	if err := live.Destroy(); err != nil {
		t.Errorf("double Destroy not idempotent: %v", err)
	}
}
