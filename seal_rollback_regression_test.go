package secmem

import (
	"bytes"
	"errors"
	"runtime"
	"testing"
)

// Seal encrypts in place BEFORE it drops the page to PROT_NONE. When that
// protect step fails, the rollback decrypt can fail too, and the buffer is then
// holding ciphertext with no page protection. These tests force that double
// failure — a committed region refusing VirtualProtect and then
// CryptUnprotectMemory is not something any environment does to order — and
// pin what the buffer does afterwards: it must stay closed over the ciphertext,
// Unseal must recover it, and a retried Seal must never encrypt ciphertext a
// second time (one Unseal reverses one layer; the secret would be gone).
//
// They must NOT call t.Parallel(): they swap package-level func vars, which is
// only safe while the package's parallel tests are paused (Go runs all
// non-parallel tests to completion before releasing parallel ones).

var (
	errInjectedProtect = errors.New("injected: VirtualProtect refused")
	errInjectedDecrypt = errors.New("injected: CryptUnprotectMemory refused")
)

// installSealCipher makes sure Seal actually turns the contents into
// ciphertext. On Windows that is the real CryptProtectMemory; elsewhere
// sealEncrypt is a no-op, so a reversible XOR over the whole secret area (data
// and canary slack, the same extent the real cipher covers) stands in. The
// state machine under test is the shipped one either way.
func installSealCipher(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	origEncrypt, origDecrypt := sealEncrypt, sealDecrypt
	xor := func(region secRegion) {
		for i := range region.inner {
			region.inner[i] ^= 0x5A
		}
	}
	sealEncrypt = func(region secRegion) (bool, error) { xor(region); return true, nil }
	sealDecrypt = func(region secRegion) error { xor(region); return nil }
	t.Cleanup(func() { sealEncrypt, sealDecrypt = origEncrypt, origDecrypt })
}

// failSealOnce arms both faults for the next Seal: the PROT_NONE step is
// refused, then the rollback decrypt is refused. Every later call passes
// through, so the recovery paths run against the real thing.
func failSealOnce(t *testing.T) {
	t.Helper()
	origProtect, origDecrypt := sealProtect, sealDecrypt
	protectArmed, decryptArmed := true, true
	sealProtect = func(region secRegion) error {
		if protectArmed {
			protectArmed = false
			return errInjectedProtect
		}
		return origProtect(region)
	}
	sealDecrypt = func(region secRegion) error {
		if decryptArmed {
			decryptArmed = false
			return errInjectedDecrypt
		}
		return origDecrypt(region)
	}
	t.Cleanup(func() { sealProtect, sealDecrypt = origProtect, origDecrypt })
}

// newRollbackFixture returns a buffer holding a known secret that has just been
// through the double failure, plus the expected plaintext.
func newRollbackFixture(t *testing.T) (*SecureBuffer, []byte) {
	t.Helper()
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	want := bytes.Repeat([]byte{0xAB}, 32)
	buf, err := NewBuffer(bytes.Clone(want))
	if err != nil {
		t.Skipf("cannot lock a 32-byte buffer: %v", err)
	}
	t.Cleanup(func() { _ = buf.Destroy() })
	installSealCipher(t)
	failSealOnce(t)

	if err := buf.Seal(); !errors.Is(err, errInjectedProtect) {
		t.Fatalf("Seal with protect and rollback both refused = %v, want the injected protect error", err)
	}
	return buf, want
}

// TestSeal_RollbackDecryptFailure_FailsClosed pins the double-failure outcome:
// the contents are ciphertext, so the buffer must report sealed and every
// accessor must refuse — not hand the ciphertext out as the secret — and
// Unseal's decrypt path must bring the plaintext back once the fault is gone.
func TestSeal_RollbackDecryptFailure_FailsClosed(t *testing.T) {
	buf, want := newRollbackFixture(t)

	if !buf.IsSealed() {
		t.Error("IsSealed() = false after a failed rollback; the contents are ciphertext")
	}
	handedOutCiphertext := false
	err := buf.WithBytes(func(b []byte) { handedOutCiphertext = !bytes.Equal(b, want) })
	if !errors.Is(err, ErrSealed) {
		t.Fatalf("WithBytes after a failed rollback = %v, want ErrSealed (handed out bytes differing from the secret: %v)",
			err, handedOutCiphertext)
	}

	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal after a failed rollback: %v", err)
	}
	if err := buf.WithBytesErr(func(b []byte) error {
		if !bytes.Equal(b, want) {
			t.Errorf("contents after Unseal recovered the rollback = %x, want %x", b, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytesErr after recovery: %v", err)
	}
	if err := buf.Destroy(); err != nil {
		t.Errorf("Destroy after recovery: %v", err)
	}
}

// TestSeal_RetryAfterRollbackFailure_DoesNotDoubleEncrypt pins that a Seal
// retried after the double failure never runs the cipher over ciphertext. A
// second layer is invisible until Unseal, which reverses one layer and then
// serves the remaining one as the secret forever; the canary slack is garbage
// too, so Destroy reports an overflow that never happened.
func TestSeal_RetryAfterRollbackFailure_DoesNotDoubleEncrypt(t *testing.T) {
	buf, want := newRollbackFixture(t)

	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal retried after a failed rollback: %v", err)
	}
	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal after the retried Seal: %v", err)
	}
	if err := buf.WithBytesErr(func(b []byte) error {
		if !bytes.Equal(b, want) {
			t.Errorf("contents after retried Seal + Unseal = %x, want %x (the retry encrypted ciphertext again)", b, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytesErr after retried Seal + Unseal: %v", err)
	}
	if err := buf.Destroy(); err != nil {
		t.Errorf("Destroy after retried Seal + Unseal: %v", err)
	}
}

// TestSeal_RefusesToEncryptCiphertext pins the guard on its own: whatever put
// an unsealed buffer into the cipher-applied state, Seal must not run the
// cipher over it again, and must not leave the accessors open over ciphertext.
func TestSeal_RefusesToEncryptCiphertext(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	buf, err := NewEmptyBuffer(32)
	if err != nil {
		t.Skipf("cannot lock a 32-byte buffer: %v", err)
	}
	t.Cleanup(func() { _ = buf.Destroy() })
	installSealCipher(t)

	encrypted := 0
	origEncrypt := sealEncrypt
	sealEncrypt = func(region secRegion) (bool, error) {
		encrypted++
		return origEncrypt(region)
	}
	t.Cleanup(func() { sealEncrypt = origEncrypt })

	// The contents are plaintext; only the bookkeeping says otherwise. That is
	// the state the failed rollback used to leave behind.
	buf.sealCipher.Store(true)
	if err := buf.Seal(); err == nil {
		t.Error("Seal over contents flagged as ciphertext returned nil, want an error")
	}
	if encrypted != 0 {
		t.Errorf("Seal ran the cipher %d time(s) over contents flagged as ciphertext, want 0", encrypted)
	}
	if !buf.IsSealed() {
		t.Error("IsSealed() = false after Seal refused ciphertext; accessors would hand it out")
	}

	// The flag was a lie for this test's purposes: clear it, and the sealed
	// state it forced, so Destroy does not "decrypt" plaintext into garbage
	// and report a canary violation for it.
	buf.sealCipher.Store(false)
	buf.sealed = false
	if err := buf.Destroy(); err != nil {
		t.Errorf("Destroy: %v", err)
	}
}
