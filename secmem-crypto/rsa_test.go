package secmemcrypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/deadpoets/secmem"
)

var (
	rsaFixtureOnce sync.Once
	rsaFixture     *RSASigner
	rsaFixtureErr  error
)

// testRSASigner returns a shared 2048-bit fixture — RSA key generation is
// too slow to repeat per test. Sign takes a read lock per borrow, so
// concurrent read-only use is safe; tests that Destroy or Seal must work on
// a clone (see cloneRSADER).
func testRSASigner(tb testing.TB) *RSASigner {
	tb.Helper()
	rsaFixtureOnce.Do(func() { rsaFixture, rsaFixtureErr = GenerateRSASigner(2048) })
	if rsaFixtureErr != nil {
		tb.Fatalf("GenerateRSASigner(2048): %v", rsaFixtureErr)
	}
	return rsaFixture
}

// cloneRSADER copies the fixture's PKCS#1 DER into a fresh SecureBuffer for
// tests that need a signer they may destroy or seal.
func cloneRSADER(tb testing.TB) *secmem.SecureBuffer {
	tb.Helper()
	s := testRSASigner(tb)
	var buf *secmem.SecureBuffer
	if err := s.WithDER(func(der []byte) error {
		cp := make([]byte, len(der))
		copy(cp, der)
		var berr error
		buf, berr = secmem.NewBuffer(cp) // NewBuffer wipes cp
		return berr
	}); err != nil {
		tb.Fatalf("WithDER: %v", err)
	}
	return buf
}

// stdlibRSAKey materializes the fixture as a plain heap key for
// differential comparison. Test-only egress of a test-only key.
func stdlibRSAKey(tb testing.TB) *rsa.PrivateKey {
	tb.Helper()
	s := testRSASigner(tb)
	var key *rsa.PrivateKey
	if err := s.WithDER(func(der []byte) error {
		k, perr := x509.ParsePKCS1PrivateKey(der)
		key = k
		return perr
	}); err != nil {
		tb.Fatalf("materialize stdlib key: %v", err)
	}
	return key
}

// TestRSASigner_PKCS1v15 verifies signatures with stdlib and — since
// PKCS#1 v1.5 signing is deterministic — requires byte-identical output
// from RSASigner and a plain stdlib key holding the same material.
func TestRSASigner_PKCS1v15(t *testing.T) {
	t.Parallel()
	s := testRSASigner(t)
	std := stdlibRSAKey(t)
	pub := s.Public().(*rsa.PublicKey)

	for _, msg := range []string{"a", "pkcs1v15 differential", "third message"} {
		digest := sha256.Sum256([]byte(msg))
		sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			t.Errorf("msg %q: stdlib rejects the signature: %v", msg, err)
		}
		sigStd, err := std.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("stdlib Sign: %v", err)
		}
		if !bytes.Equal(sig, sigStd) {
			t.Errorf("msg %q: signatures diverge from stdlib", msg)
		}
	}
}

func TestRSASigner_PSS(t *testing.T) {
	t.Parallel()
	s := testRSASigner(t)
	pub := s.Public().(*rsa.PublicKey)

	digest := sha256.Sum256([]byte("pss message"))
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	sig, err := s.Sign(rand.Reader, digest[:], opts)
	if err != nil {
		t.Fatalf("Sign(PSS): %v", err)
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, opts); err != nil {
		t.Errorf("stdlib rejects the PSS signature: %v", err)
	}
}

// TestRSASigner_PKCS8 round-trips the fixture key through PKCS#8: the
// signer must auto-detect the encoding, sign identically to the PKCS#1
// original, and hand back the exact PKCS#8 bytes through WithDER.
func TestRSASigner_PKCS8(t *testing.T) {
	t.Parallel()
	std := stdlibRSAKey(t)
	p8, err := x509.MarshalPKCS8PrivateKey(std)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	p8Copy := make([]byte, len(p8))
	copy(p8Copy, p8)

	buf, err := secmem.NewBuffer(p8)
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	s, err := NewRSASigner(buf)
	if err != nil {
		t.Fatalf("NewRSASigner(PKCS#8): %v", err)
	}
	defer s.Destroy()

	digest := sha256.Sum256([]byte("pkcs8"))
	sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sigStd, err := std.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("stdlib Sign: %v", err)
	}
	if !bytes.Equal(sig, sigStd) {
		t.Error("PKCS#8-constructed signer signs differently")
	}

	if err := s.WithDER(func(der []byte) error {
		if !bytes.Equal(der, p8Copy) {
			t.Error("WithDER did not return the PKCS#8 bytes as given")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithDER: %v", err)
	}
}

func TestNewRSASigner_BadInputs(t *testing.T) {
	t.Parallel()

	if _, err := NewRSASigner(nil); err == nil {
		t.Error("expected error for nil buffer")
	}

	destroyed, _ := secmem.NewEmptyBuffer(64)
	_ = destroyed.Destroy()
	if _, err := NewRSASigner(destroyed); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("destroyed buffer: error = %v, want wrap of ErrDestroyed", err)
	}

	garbage, _ := secmem.NewBuffer([]byte("not DER at all, not even close"))
	defer garbage.Destroy()
	_, err := NewRSASigner(garbage)
	if err == nil {
		t.Fatal("expected error for garbage DER")
	}
	if !strings.Contains(err.Error(), "PKCS#1") || !strings.Contains(err.Error(), "PKCS#8") {
		t.Errorf("garbage-DER error should mention both encodings tried, got: %v", err)
	}
	if garbage.IsDestroyed() {
		t.Error("ownership transferred on failure")
	}
}

// TestNewRSASigner_RejectsNonRSA feeds PKCS#8 blobs holding ECDSA and
// Ed25519 keys and expects errors that say what was found and where to go
// instead.
func TestNewRSASigner_RejectsNonRSA(t *testing.T) {
	t.Parallel()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey(EC): %v", err)
	}
	ecBuf, _ := secmem.NewBuffer(ecDER)
	defer ecBuf.Destroy()
	if _, err := NewRSASigner(ecBuf); err == nil || !strings.Contains(err.Error(), "ECDSA") {
		t.Errorf("PKCS#8 ECDSA key: error = %v, want mention of ECDSA", err)
	}

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	edDER, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey(Ed25519): %v", err)
	}
	edBuf, _ := secmem.NewBuffer(edDER)
	defer edBuf.Destroy()
	if _, err := NewRSASigner(edBuf); err == nil || !strings.Contains(err.Error(), "Ed25519") {
		t.Errorf("PKCS#8 Ed25519 key: error = %v, want mention of Ed25519", err)
	}
}

func TestRSASigner_NilOpts(t *testing.T) {
	t.Parallel()
	s := testRSASigner(t)
	digest := sha256.Sum256([]byte("x"))
	if _, err := s.Sign(rand.Reader, digest[:], nil); err == nil {
		t.Error("Sign(nil opts) should error, not panic downstream")
	}
	// A typed nil passes an interface nil-check but would nil-deref inside
	// crypto/rsa; the guard must catch it too.
	var pss *rsa.PSSOptions
	if _, err := s.Sign(rand.Reader, digest[:], pss); err == nil {
		t.Error("Sign(typed-nil *rsa.PSSOptions) should error, not panic downstream")
	}
}

// TestRSASigner_ConcurrentSign drives the shared fixture from concurrent
// goroutines — the crypto/tls handshake pattern. Run under -race.
func TestRSASigner_ConcurrentSign(t *testing.T) {
	t.Parallel()
	s := testRSASigner(t)
	pub := s.Public().(*rsa.PublicKey)

	const goroutines = 4
	const perGoroutine = 5 // RSA signs are ~ms each; keep the suite fast
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*perGoroutine)

	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perGoroutine {
				digest := sha256.Sum256([]byte("concurrent " + strconv.Itoa(g) + "/" + strconv.Itoa(i)))
				sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
				if err != nil {
					errs <- err
					return
				}
				if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
					errs <- err
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

// TestRSASigner_SignDuringDestroy races Sign against Destroy on a cloned
// signer (never the shared fixture): every Sign must return either a
// verifiable signature or a clean error — never a panic, never a corrupt
// signature.
func TestRSASigner_SignDuringDestroy(t *testing.T) {
	t.Parallel()
	for round := range 3 {
		signer, err := NewRSASigner(cloneRSADER(t))
		if err != nil {
			t.Fatalf("NewRSASigner: %v", err)
		}
		pub := signer.Public().(*rsa.PublicKey)

		const goroutines = 4
		var wg sync.WaitGroup
		bad := make(chan string, goroutines*3)

		for g := range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range 3 {
					digest := sha256.Sum256([]byte("race " + strconv.Itoa(round) + "/" + strconv.Itoa(g) + "/" + strconv.Itoa(i)))
					sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
					if err != nil {
						continue // clean error during/after Destroy is the contract
					}
					if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
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

func TestRSASigner_PublicAndEqual(t *testing.T) {
	t.Parallel()
	s := testRSASigner(t)

	pub := s.Public().(*rsa.PublicKey)
	if !s.Equal(pub) {
		t.Error("signer does not Equal its own public key")
	}

	// Mutating the returned copy must not corrupt the cached key.
	pub.N.SetInt64(42)
	if !s.Equal(s.Public()) {
		t.Error("mutating a returned public key corrupted the cached one")
	}
	if s.Equal(42) {
		t.Error("Equal(non-key type) = true")
	}
}

func TestRSASigner_NilAndDestroyed(t *testing.T) {
	t.Parallel()
	var s *RSASigner
	if _, err := s.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("nil.Sign error = %v", err)
	}
	if err := s.WithDER(func([]byte) error { return nil }); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("nil.WithDER error = %v", err)
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

	live, err := NewRSASigner(cloneRSADER(t))
	if err != nil {
		t.Fatalf("NewRSASigner: %v", err)
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

func TestGenerateRSASigner_RejectsTinyKeys(t *testing.T) {
	t.Parallel()
	// stdlib refuses to generate keys below 1024 bits; make sure the error
	// surfaces instead of being swallowed.
	if _, err := GenerateRSASigner(512); err == nil {
		t.Error("expected error for a 512-bit key")
	}
}
