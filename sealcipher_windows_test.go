//go:build windows

// Proof tests for the sealed-state cipher: the sealed contents must actually
// be ciphertext in memory (what a process dump would capture), the
// seal→unseal round trip must restore the secret and the canary bit-exactly,
// and destroying a sealed buffer must neither false-report a canary
// violation nor skip the teardown.

package secmem

import (
	"bytes"
	"errors"
	"testing"
	"unsafe"
)

const sealPlaintext = "sealed-secret-0123456789abcdef" // 30 bytes, sub-page

// TestSealCipher_ContentsAreCiphertextWhileSealed proves the encryption is
// real: after Seal, the bytes physically in the mapping (read via a
// temporary internal re-protect, the same view a kernel-mediated dump gets)
// must NOT contain the plaintext.
func TestSealCipher_ContentsAreCiphertextWhileSealed(t *testing.T) {
	t.Parallel()
	buf, err := NewBuffer([]byte(sealPlaintext))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Internal peek at the raw mapping — the moral equivalent of a memory
	// dump reading through the kernel. Re-protect RW, snapshot, re-seal.
	if err := mprotectSecretMem(buf.region, 3); err != nil {
		t.Fatalf("test re-protect: %v", err)
	}
	snapshot := make([]byte, len(sealPlaintext))
	copy(snapshot, buf.region.inner[:len(sealPlaintext)])
	if err := mprotectSecretMem(buf.region, 0); err != nil {
		t.Fatalf("test re-seal: %v", err)
	}

	if bytes.Contains(snapshot, []byte(sealPlaintext)) {
		t.Fatal("sealed mapping contains the PLAINTEXT — CryptProtectMemory was not applied")
	}
	if bytes.Equal(snapshot, make([]byte, len(snapshot))) {
		t.Fatal("sealed mapping is all zeros — contents were wiped, not encrypted")
	}

	// Round trip: Unseal must restore the exact secret.
	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if err := buf.WithBytes(func(b []byte) {
		if string(b) != sealPlaintext {
			t.Errorf("after unseal: %q, want %q — decryption did not restore the secret", b, sealPlaintext)
		}
	}); err != nil {
		t.Fatalf("WithBytes after unseal: %v", err)
	}
}

// TestSealCipher_SealUnsealCycles verifies repeated seal/unseal cycles are
// stable (the canary slack is encrypted and restored bit-exactly each time,
// so the final Destroy still verifies cleanly).
func TestSealCipher_SealUnsealCycles(t *testing.T) {
	t.Parallel()
	buf, err := NewBuffer([]byte(sealPlaintext))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := buf.Seal(); err != nil {
			t.Fatalf("Seal #%d: %v", i, err)
		}
		if err := buf.Unseal(); err != nil {
			t.Fatalf("Unseal #%d: %v", i, err)
		}
	}
	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy after cycles: %v (canary must survive cipher round trips)", err)
	}
}

// TestSealCipher_DestroySealedBuffer pins the teardown path: destroying a
// buffer while sealed+encrypted must succeed with no false canary violation.
func TestSealCipher_DestroySealedBuffer(t *testing.T) {
	t.Parallel()
	buf, err := NewBuffer([]byte(sealPlaintext))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := buf.Destroy(); err != nil {
		if errors.Is(err, ErrCanaryViolation) {
			t.Fatal("Destroy of a sealed buffer false-reported a canary violation — ciphertext was canary-checked")
		}
		t.Fatalf("Destroy of sealed buffer: %v", err)
	}
	if !buf.IsDestroyed() {
		t.Fatal("sealed buffer not destroyed")
	}
}

// TestSealCipher_RealOverflowStillDetected proves the cipher does not mask
// real violations: an overflow inflicted while UNSEALED is still reported by
// Destroy even after an intermediate seal/unseal cycle.
func TestSealCipher_RealOverflowStillDetected(t *testing.T) {
	buf, err := NewEmptyBuffer(100)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}

	// Overflow into the canary slack (unsealed, plaintext state).
	base := uintptr(unsafe.Pointer(&buf.region.inner[0]))
	probeWrite(base+uintptr(cap(buf.data)), 0x00)

	// Cycle the cipher: encrypts the corrupted slack, decrypts it back —
	// the corruption must survive the round trip and still be detected.
	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if err := buf.Destroy(); !errors.Is(err, ErrCanaryViolation) {
		t.Fatalf("Destroy = %v, want ErrCanaryViolation (cipher round trip must not mask a real overflow)", err)
	}
}
