package secmemcrypto

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strconv"
	"sync"
	"testing"

	"github.com/deadpoets/secmem"
)

// Compile-time interface conformance — the whole point of the type.
var (
	_ crypto.Signer        = (*Ed25519Signer)(nil)
	_ crypto.MessageSigner = (*Ed25519Signer)(nil)
)

func TestNewEd25519Signer_RoundTrip(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	buf, err := secmem.NewBuffer(priv.Seed())
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	signer, err := NewEd25519Signer(buf)
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	defer signer.Destroy()

	if !pub.Equal(signer.Public()) {
		t.Errorf("public key mismatch: got %x, want %x", signer.Public(), pub)
	}

	msg := []byte("secmem-crypto round trip")
	sig, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("stdlib Verify rejected Ed25519Signer's signature")
	}
	if want := ed25519.Sign(priv, msg); !bytes.Equal(sig, want) {
		t.Errorf("signature differs from stdlib\n  ours:   %x\n  stdlib: %x", sig, want)
	}
}

func TestGenerateEd25519Signer(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	defer signer.Destroy()

	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("Public() did not return a valid ed25519.PublicKey: %v", signer.Public())
	}

	msg := []byte("generated signer")
	sig, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("stdlib Verify rejected a freshly generated Ed25519Signer's signature")
	}
}

func TestGenerateEd25519Signer_ProducesDistinctKeys(t *testing.T) {
	t.Parallel()
	a, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer (a): %v", err)
	}
	defer a.Destroy()
	b, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer (b): %v", err)
	}
	defer b.Destroy()

	if a.Equal(b.Public()) {
		t.Error("two independently generated signers produced the same public key")
	}
}

func TestNewEd25519Signer_NilBuffer(t *testing.T) {
	t.Parallel()
	if _, err := NewEd25519Signer(nil); err == nil {
		t.Fatal("expected error for nil buffer")
	}
}

func TestNewEd25519Signer_WrongLengthSeed_OwnershipNotTransferred(t *testing.T) {
	t.Parallel()
	buf, err := secmem.NewEmptyBuffer(16) // not 32 bytes
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer buf.Destroy() // caller still owns buf; must not double-free

	_, err = NewEd25519Signer(buf)
	if err == nil {
		t.Fatal("expected error for wrong-length seed buffer")
	}
	if !errors.Is(err, ErrBadSeedLength) {
		t.Errorf("error does not unwrap to ErrBadSeedLength: %v", err)
	}
	if buf.IsDestroyed() {
		t.Error("NewEd25519Signer destroyed the buffer on a failed construction — ownership should not transfer on failure")
	}
}

func TestNewEd25519Signer_DestroyedBuffer(t *testing.T) {
	t.Parallel()
	buf, err := secmem.NewEmptyBuffer(ed25519.SeedSize)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	_ = buf.Destroy()

	_, err = NewEd25519Signer(buf)
	if err == nil {
		t.Fatal("expected error for destroyed buffer")
	}
	if !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("error does not unwrap to secmem.ErrDestroyed (got %v) — a destroyed buffer is not a length problem", err)
	}
}

func TestNewEd25519Signer_SealedBuffer_OwnershipNotTransferred(t *testing.T) {
	t.Parallel()
	buf, err := secmem.NewEmptyBuffer(ed25519.SeedSize)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer buf.Destroy()
	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	_, err = NewEd25519Signer(buf)
	if err == nil {
		t.Fatal("expected error for sealed buffer")
	}
	if !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("error does not unwrap to secmem.ErrSealed: %v", err)
	}
	if buf.IsDestroyed() {
		t.Error("ownership transferred on failure — sealed buffer was destroyed")
	}
	// The buffer must still be fully usable after unsealing.
	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if _, err := NewEd25519Signer(buf); err != nil {
		t.Errorf("construction after Unseal failed: %v", err)
	}
}

func TestEd25519Signer_Sign_AfterDestroy(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	if err := signer.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	_, err = signer.Sign(nil, []byte("msg"), crypto.Hash(0))
	if err == nil {
		t.Fatal("expected error signing after Destroy")
	}
	if !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("error does not unwrap to secmem.ErrDestroyed: %v", err)
	}
}

func TestEd25519Signer_DoubleDestroy_Idempotent(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	if err := signer.Destroy(); err != nil {
		t.Fatalf("first Destroy: %v", err)
	}
	if err := signer.Destroy(); err != nil {
		t.Errorf("second Destroy not idempotent: %v", err)
	}
}

func TestEd25519Signer_Public_And_Equal_SurviveDestroy(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	pub := signer.Public()
	if err := signer.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	// The cached public key is not secret — Public/Equal must remain safe
	// and correct after the seed buffer is gone.
	if !signer.Equal(pub) {
		t.Error("Equal against the signer's own public key failed after Destroy")
	}
}

func TestEd25519Signer_Public_ReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	defer signer.Destroy()

	original := signer.Public().(ed25519.PublicKey)
	keep := append(ed25519.PublicKey(nil), original...)

	// Mutating the returned slice must not corrupt the Ed25519Signer's cached key —
	// stdlib ed25519.PrivateKey.Public() copies for the same reason.
	original[0] ^= 0xFF

	again := signer.Public().(ed25519.PublicKey)
	if !bytes.Equal(again, keep) {
		t.Error("mutating Public()'s returned slice corrupted the Ed25519Signer's cached public key")
	}
	if !signer.Equal(keep) {
		t.Error("Equal against the true public key failed after a caller mutated a returned copy")
	}
}

func TestEd25519Signer_Sign_RejectsEd25519ph(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	defer signer.Destroy()

	// A bare crypto.SHA512 and an ed25519.Options with SHA-512 both request
	// Ed25519ph; both must be refused.
	if _, err := signer.Sign(nil, []byte("msg"), crypto.SHA512); err == nil {
		t.Fatal("expected error for crypto.SHA512 opts (Ed25519ph), got nil")
	}
	if _, err := signer.Sign(nil, []byte("msg"), &ed25519.Options{Hash: crypto.SHA512}); err == nil {
		t.Fatal("expected error for ed25519.Options{Hash: SHA512} (Ed25519ph), got nil")
	}
}

func TestEd25519Signer_Sign_RejectsEd25519ctx(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	defer signer.Destroy()

	// ed25519.Options with a non-empty Context requests Ed25519ctx — a
	// DIFFERENT domain separation than pure Ed25519. Silently signing pure
	// here would be a cross-protocol signature-confusion bug; it must error.
	_, err = signer.Sign(nil, []byte("msg"), &ed25519.Options{Context: "proto-v1"})
	if err == nil {
		t.Fatal("expected error for ed25519.Options{Context: ...} (Ed25519ctx), got nil — this would silently drop domain separation")
	}
}

func TestEd25519Signer_Sign_AcceptsPureEd25519Options(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	defer signer.Destroy()
	pub := signer.Public().(ed25519.PublicKey)

	msg := []byte("pure ed25519 via Options")
	for _, opts := range []crypto.SignerOpts{
		crypto.Hash(0),
		&ed25519.Options{}, // zero Options = pure Ed25519
		nil,
	} {
		sig, err := signer.Sign(nil, msg, opts)
		if err != nil {
			t.Fatalf("Sign with %v: %v", opts, err)
		}
		if !ed25519.Verify(pub, msg, sig) {
			t.Errorf("Verify failed for opts %v", opts)
		}
	}
}

func TestEd25519Signer_SignMessage_MatchesSign(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	defer signer.Destroy()

	msg := []byte("message signer parity")
	viaSign, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	viaSignMessage, err := signer.SignMessage(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if !bytes.Equal(viaSign, viaSignMessage) {
		t.Error("SignMessage and Sign disagree for identical input — the crypto.MessageSigner contract requires them equal")
	}
}

func TestEd25519Signer_Sign_SealedSeed_ErrorsAndRecovers(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	buf, err := secmem.NewBuffer(priv.Seed())
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	signer, err := NewEd25519Signer(buf)
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	defer signer.Destroy()

	// The caller retained the buffer pointer; sealing through it is the
	// documented dormant-key pattern.
	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, err = signer.Sign(nil, []byte("msg"), crypto.Hash(0))
	if err == nil {
		t.Fatal("expected error signing with a sealed seed buffer")
	}
	if !errors.Is(err, secmem.ErrSealed) {
		t.Errorf("error does not unwrap to secmem.ErrSealed: %v", err)
	}

	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if _, err := signer.Sign(nil, []byte("msg"), crypto.Hash(0)); err != nil {
		t.Errorf("Sign after Unseal failed: %v", err)
	}
}

func TestEd25519Signer_WithSeed_RoundTrip(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	defer signer.Destroy()

	// Persist the seed (simulated), then reconstruct a signer from the
	// persisted copy — the generate-then-store flow WithSeed exists for.
	persisted := make([]byte, ed25519.SeedSize)
	if err := signer.WithSeed(func(seed []byte) error {
		copy(persisted, seed)
		return nil
	}); err != nil {
		t.Fatalf("WithSeed: %v", err)
	}

	buf, err := secmem.NewBuffer(persisted) // NewBuffer wipes `persisted` after copying
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	restored, err := NewEd25519Signer(buf)
	if err != nil {
		t.Fatalf("NewEd25519Signer (restored): %v", err)
	}
	defer restored.Destroy()

	if !restored.Equal(signer.Public()) {
		t.Error("signer restored from a WithSeed-persisted seed has a different public key")
	}
}

func TestEd25519Signer_WithSeed_AfterDestroy(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	_ = signer.Destroy()

	err = signer.WithSeed(func([]byte) error { return nil })
	if err == nil {
		t.Fatal("expected error from WithSeed after Destroy")
	}
	if !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("error does not unwrap to secmem.ErrDestroyed: %v", err)
	}
}

func TestEd25519Signer_Equal_DifferentKeys(t *testing.T) {
	t.Parallel()
	a, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	defer a.Destroy()

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if a.Equal(otherPub) {
		t.Error("Equal reported true for an unrelated public key")
	}
}

// TestEd25519Signer_Equal_NonKeyTypeComparesFalse pins the documented behavior:
// Equal wants a public key, and any other type — including an *Ed25519Signer with
// the IDENTICAL key — compares false without error (stdlib Equal convention).
func TestEd25519Signer_Equal_NonKeyTypeComparesFalse(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	defer signer.Destroy()

	if signer.Equal(signer) {
		t.Error("Equal(*Ed25519Signer) returned true — the documented contract is public keys only")
	}
	if !signer.Equal(signer.Public()) {
		t.Error("Equal(signer.Public()) returned false for the signer's own key")
	}
}

// TestEd25519Signer_NilReceiver_NeverPanics holds the adapter to the core module's
// bar: every method is safe on a nil receiver — errors, not panics.
func TestEd25519Signer_NilReceiver_NeverPanics(t *testing.T) {
	t.Parallel()
	var s *Ed25519Signer

	if got := s.Public(); got != nil {
		t.Errorf("nil.Public() = %v, want nil", got)
	}
	if s.Equal(nil) {
		t.Error("nil.Equal(nil) = true, want false")
	}
	if _, err := s.Sign(nil, []byte("msg"), crypto.Hash(0)); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("nil.Sign error = %v, want wrap of secmem.ErrDestroyed", err)
	}
	if _, err := s.SignMessage(nil, []byte("msg"), crypto.Hash(0)); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("nil.SignMessage error = %v, want wrap of secmem.ErrDestroyed", err)
	}
	if err := s.WithSeed(func([]byte) error { return nil }); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("nil.WithSeed error = %v, want wrap of secmem.ErrDestroyed", err)
	}
	if err := s.Destroy(); err != nil {
		t.Errorf("nil.Destroy() = %v, want nil", err)
	}
}

// TestEd25519Signer_ZeroValue_NeverPanics pins the same guarantee for var s Ed25519Signer.
func TestEd25519Signer_ZeroValue_NeverPanics(t *testing.T) {
	t.Parallel()
	var s Ed25519Signer

	if got := s.Public(); got != nil {
		t.Errorf("zero.Public() = %v, want nil", got)
	}
	if s.Equal(nil) {
		t.Error("zero.Equal(nil) = true, want false")
	}
	if _, err := s.Sign(nil, []byte("msg"), crypto.Hash(0)); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("zero.Sign error = %v, want wrap of secmem.ErrDestroyed", err)
	}
	if err := s.WithSeed(func([]byte) error { return nil }); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("zero.WithSeed error = %v, want wrap of secmem.ErrDestroyed", err)
	}
	if err := s.Destroy(); err != nil {
		t.Errorf("zero.Destroy() = %v, want nil", err)
	}
}

// TestEd25519Signer_ConcurrentSign exercises the production access pattern:
// crypto/tls drives crypto.Signer from concurrent handshake goroutines.
// Run under -race (the suite always is, per the Makefile/CI).
func TestEd25519Signer_ConcurrentSign(t *testing.T) {
	t.Parallel()
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	defer signer.Destroy()
	pub := signer.Public().(ed25519.PublicKey)

	const goroutines = 8
	const perGoroutine = 25
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*perGoroutine)

	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perGoroutine {
				msg := []byte("concurrent " + strconv.Itoa(g) + "/" + strconv.Itoa(i))
				sig, err := signer.Sign(nil, msg, crypto.Hash(0))
				if err != nil {
					errs <- err
					return
				}
				if !ed25519.Verify(pub, msg, sig) {
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

// TestEd25519Signer_SignDuringDestroy races Sign against Destroy: every Sign must
// return either a verifiable signature or a clean error — never a panic,
// never a corrupt signature.
func TestEd25519Signer_SignDuringDestroy(t *testing.T) {
	t.Parallel()
	for round := range 5 {
		signer, err := GenerateEd25519Signer()
		if err != nil {
			t.Fatalf("GenerateEd25519Signer: %v", err)
		}
		pub := signer.Public().(ed25519.PublicKey)

		const goroutines = 4
		var wg sync.WaitGroup
		bad := make(chan string, goroutines*10)

		for g := range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range 10 {
					msg := []byte("race " + strconv.Itoa(round) + "/" + strconv.Itoa(g) + "/" + strconv.Itoa(i))
					sig, err := signer.Sign(nil, msg, crypto.Hash(0))
					if err != nil {
						continue // clean error during/after Destroy is the contract
					}
					if !ed25519.Verify(pub, msg, sig) {
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
