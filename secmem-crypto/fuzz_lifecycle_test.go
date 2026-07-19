package secmemcrypto

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/deadpoets/secmem"
)

// FuzzSignerLifecycle drives an Ed25519Signer through arbitrary sequences of
// Sign / Seal / Unseal / ReadOnly / ReadWrite / WithSeed / Destroy against a
// model of the key buffer's state. It is the crypto-module analog of secmem's
// FuzzBufferLifecycle, and it exists to LOCK IN a property rather than to fix a
// known bug: the signer reads its seed in place and never writes it, so signing
// while the key buffer is read-only (PROT_READ) must succeed, not fault — and
// signing while sealed must return ErrSealed, not disclose or crash. A future
// in-place signing optimization that wrote scratch into the seed buffer would
// fault under read-only and this fuzzer would catch it.
//
// The fuzzer input is the operation program; the seed and message are fixed so
// a successful signature is checkable against the signer's own public key. The
// buffer transitions (Seal/ReadOnly/…) are driven through the *SecureBuffer the
// caller retains, exactly as the "seal a dormant key" pattern does.
func FuzzSignerLifecycle(f *testing.F) {
	f.Add([]byte{soSign, soSeal, soSign, soUnseal, soSign})          // sign, seal (blocked), unseal, sign
	f.Add([]byte{soReadOnly, soSign, soReadWrite, soSign})           // sign while read-only must WORK, not fault
	f.Add([]byte{soReadOnly, soSeal, soUnseal, soSign})              // read-only key survives a seal cycle, still signs
	f.Add([]byte{soSeal, soReadOnly, soUnseal})                      // read-only refused while sealed
	f.Add([]byte{soWithSeed, soDestroy, soSign, soSeal, soWithSeed}) // every op after destroy refuses

	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	msg := []byte("fuzz-signer-lifecycle-message")

	f.Fuzz(func(t *testing.T, program []byte) {
		seedBuf, err := secmem.NewEmptyBuffer(ed25519.SeedSize)
		if err != nil {
			t.Skipf("NewEmptyBuffer: %v", err)
		}
		if _, err := seedBuf.CopyIn(seed, 0); err != nil {
			_ = seedBuf.Destroy()
			t.Fatalf("CopyIn seed: %v", err)
		}
		signer, err := NewEd25519Signer(seedBuf) // takes ownership of seedBuf
		if err != nil {
			_ = seedBuf.Destroy()
			t.Fatalf("NewEd25519Signer: %v", err)
		}
		defer func() { _ = signer.Destroy() }()

		pub, ok := signer.Public().(ed25519.PublicKey)
		if !ok {
			t.Fatalf("Public() is not ed25519.PublicKey")
		}

		// Model: only the states that change an operation's expected result.
		var destroyed, sealed bool

		for _, opByte := range program {
			switch int(opByte) % soCount {
			case soSign:
				sig, err := signer.Sign(nil, msg, crypto.Hash(0))
				switch {
				case destroyed:
					mustWrap(t, "Sign", err, secmem.ErrDestroyed)
				case sealed:
					mustWrap(t, "Sign", err, secmem.ErrSealed)
				default:
					// The load-bearing case: signing must succeed whether the
					// buffer is writable or read-only, and the result must
					// verify. A write-into-the-seed regression would fault here
					// under a preceding ReadOnly.
					if err != nil {
						t.Fatalf("Sign: unexpected error: %v", err)
					}
					if !ed25519.Verify(pub, msg, sig) {
						t.Fatal("Sign produced a signature that does not verify")
					}
				}

			case soWithSeed:
				err := signer.WithSeed(func(seed []byte) error {
					if len(seed) != ed25519.SeedSize {
						t.Fatalf("WithSeed: seed len %d, want %d", len(seed), ed25519.SeedSize)
					}
					return nil
				})
				switch {
				case destroyed:
					mustWrap(t, "WithSeed", err, secmem.ErrDestroyed)
				case sealed:
					mustWrap(t, "WithSeed", err, secmem.ErrSealed)
				default:
					if err != nil {
						t.Fatalf("WithSeed: unexpected error: %v", err)
					}
				}

			case soSeal:
				err := seedBuf.Seal()
				if destroyed {
					mustWrap(t, "Seal", err, secmem.ErrDestroyed)
				} else {
					if err != nil {
						t.Fatalf("Seal: unexpected error: %v", err)
					}
					sealed = true
				}

			case soUnseal:
				err := seedBuf.Unseal()
				if destroyed {
					mustWrap(t, "Unseal", err, secmem.ErrDestroyed)
				} else {
					if err != nil {
						t.Fatalf("Unseal: unexpected error: %v", err)
					}
					sealed = false
				}

			case soReadOnly:
				err := seedBuf.ReadOnly()
				switch {
				case destroyed:
					mustWrap(t, "ReadOnly", err, secmem.ErrDestroyed)
				case sealed:
					mustWrap(t, "ReadOnly", err, secmem.ErrSealed)
				default:
					if err != nil {
						t.Fatalf("ReadOnly: unexpected error: %v", err)
					}
				}

			case soReadWrite:
				err := seedBuf.ReadWrite()
				switch {
				case destroyed:
					mustWrap(t, "ReadWrite", err, secmem.ErrDestroyed)
				case sealed:
					mustWrap(t, "ReadWrite", err, secmem.ErrSealed)
				default:
					if err != nil {
						t.Fatalf("ReadWrite: unexpected error: %v", err)
					}
				}

			case soDestroy:
				_ = signer.Destroy() // idempotent; destroys the owned seedBuf
				destroyed = true
			}
		}
	})
}

// Opcodes for FuzzSignerLifecycle.
const (
	soSign = iota
	soWithSeed
	soSeal
	soUnseal
	soReadOnly
	soReadWrite
	soDestroy
	soCount // must be last
)

func mustWrap(t *testing.T, op string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: error = %v, want it to wrap %v", op, err, want)
	}
}
