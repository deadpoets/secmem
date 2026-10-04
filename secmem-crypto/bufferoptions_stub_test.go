//go:build !linux && !darwin && !windows

package secmemcrypto

import (
	"bytes"
	"errors"
	"testing"

	"github.com/deadpoets/secmem"
)

// TestBufferOptions_NoSecureMemoryPlatform is the case the option exists
// for. The file is built only for platforms on which the core has no lockable
// memory, so it is compiled by the stub cross-compile rows and run nowhere in
// CI (GOOS=js under node is one that can be run by hand): a test that skipped
// on every audited lane would be a proof that never runs, on the allowlist
// forever. There, every allocating call fails closed without
// the core's opt-in, and with it the buffers a call returns — and the ones
// the resulting key returns later — are the core's insecure fallback.
func TestBufferOptions_NoSecureMemoryPlatform(t *testing.T) {
	if probe, err := secmem.NewEmptyBuffer(1); err == nil {
		probe.Destroy()
		t.Skip("this platform has lockable memory; BufferOptions(WithInsecureFallback()) changes nothing here")
	} else if !errors.Is(err, secmem.ErrNoSecureMemory) {
		t.Skipf("allocation failed for another reason: %v", err)
	}
	insecure := BufferOptions(secmem.WithInsecureFallback())

	if _, err := GenerateEd25519Signer(); !errors.Is(err, secmem.ErrNoSecureMemory) {
		t.Fatalf("GenerateEd25519Signer without the opt-in: %v, want ErrNoSecureMemory", err)
	}
	if _, err := GenerateX25519Key(); !errors.Is(err, secmem.ErrNoSecureMemory) {
		t.Fatalf("GenerateX25519Key without the opt-in: %v, want ErrNoSecureMemory", err)
	}
	if _, err := GenerateDicewarePassphrase(4); !errors.Is(err, secmem.ErrNoSecureMemory) {
		t.Fatalf("GenerateDicewarePassphrase without the opt-in: %v, want ErrNoSecureMemory", err)
	}

	mustInsecure := func(name string, b *secmem.SecureBuffer, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s with the opt-in: %v", name, err)
		}
		defer b.Destroy()
		if !b.Capabilities().Insecure {
			t.Fatalf("%s: the buffer does not report the insecure fallback", name)
		}
	}
	ed, err := GenerateEd25519Signer(insecure)
	if err != nil {
		t.Fatalf("GenerateEd25519Signer with the opt-in: %v", err)
	}
	defer ed.Destroy()
	out, err := ed.MarshalOpenSSHPrivateKeyWithPassphraseParams("c", []byte(testPassphrase), OpenSSHPassphraseParams{Rounds: 1})
	mustInsecure("Marshal on a key built with the opt-in", out, err)

	x, err := GenerateX25519Key(insecure)
	if err != nil {
		t.Fatalf("GenerateX25519Key with the opt-in: %v", err)
	}
	defer x.Destroy()
	ss, err := x.SharedSecret([32]byte{9})
	mustInsecure("SharedSecret on a key built with the opt-in", ss, err)

	p, err := GenerateDicewarePassphrase(4, insecure)
	mustInsecure("GenerateDicewarePassphrase", p, err)

	var pemKey []byte
	plain, err := ed.MarshalOpenSSHPrivateKey("c")
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.WithBytesErr(func(b []byte) error {
		pemKey = bytes.Clone(b) //nolint:secmem-lint // test egress of a throwaway test key, to feed it back to the parser
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	plain.Destroy()
	if _, err := ParsePrivateKey(pemKey); !errors.Is(err, secmem.ErrNoSecureMemory) {
		t.Fatalf("ParsePrivateKey without the opt-in: %v, want ErrNoSecureMemory", err)
	}
	s, err := ParsePrivateKey(pemKey, insecure)
	if err != nil {
		t.Fatalf("ParsePrivateKey with the opt-in: %v", err)
	}
	s.Destroy()
}
