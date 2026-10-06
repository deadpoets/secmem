package secmem

import (
	"bytes"
	"errors"
	"testing"
)

// TestNewBuffer_RegisteredBeforeFilled_RefusesAfterEmergencyWipe pins the
// construction order the copying constructors now follow — register with the
// janitor, then copy the secret in under the lock — and the guard that order
// requires. They used to copy first and register second, so a WipeAllSecrets
// landing between the two could not see the buffer: for that window the
// plaintext existed only in an unregistered region, with the caller's copy
// already wiped.
//
// The test drives the window directly: a buffer is registered, the emergency
// wipe runs, and only then is the fill attempted. The fill must refuse with
// ErrWiped (writing a live secret into a region the wipe has reported as
// handled is what the wiped flag exists to prevent) and the buffer must be
// destroyed rather than left registered and empty.
func TestNewBuffer_RegisteredBeforeFilled_RefusesAfterEmergencyWipe(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	region, data, info, err := allocSecretMem(32)
	if err != nil {
		t.Fatalf("allocSecretMem: %v", err)
	}
	if err := fillCanary(region.inner[len(data):]); err != nil {
		t.Fatalf("fillCanary: %v", err)
	}
	sb, err := newSecureBuffer(region, data, info, config{})
	if err != nil {
		t.Fatalf("newSecureBuffer: %v", err)
	}
	if _, ok := emergencyJanitor.peekAny(sb.janitorKey); !ok {
		t.Fatal("buffer is not registered after newSecureBuffer")
	}

	// The emergency wipe lands between registration and the fill.
	if err := WipeAllSecrets(); err != nil {
		t.Fatalf("WipeAllSecrets: %v", err)
	}

	secret := bytes.Repeat([]byte{0x5A}, 32)
	err = sb.fillInitial(secret)
	if !errors.Is(err, ErrWiped) {
		t.Fatalf("fillInitial after the emergency wipe returned %v, want ErrWiped", err)
	}
	if !sb.IsDestroyed() {
		t.Fatal("a refused fill must destroy the buffer, not leave it registered")
	}
	if _, ok := emergencyJanitor.peekAny(sb.janitorKey); ok {
		t.Fatal("refused buffer is still registered with the janitor")
	}
	// The caller-facing constructor path over the same helper: a live buffer
	// is filled exactly, and the source is wiped as documented.
	src := bytes.Repeat([]byte{0x33}, 40)
	buf, err := NewBuffer(src)
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()
	filled := false
	if err := buf.WithBytes(func(b []byte) {
		filled = bytes.Equal(b, bytes.Repeat([]byte{0x33}, 40))
	}); err != nil {
		t.Fatal(err)
	}
	if !filled {
		t.Error("buffer contents differ from the 40 × 0x33 the constructor was given")
	}
	if !bytes.Equal(src, make([]byte, 40)) {
		t.Error("source slice was not wiped by NewBuffer")
	}
}

// TestTruncate_ClampsCapacity pins that a borrow after Truncate hands out a
// slice that reaches exactly the live bytes: length and capacity both n, so
// the callback cannot re-slice back over the wiped tail.
func TestTruncate_ClampsCapacity(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	buf, err := NewBuffer(bytes.Repeat([]byte{0x77}, 64))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()
	if err := buf.Truncate(10); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if err := buf.WithBytes(func(b []byte) {
		if len(b) != 10 || cap(b) != 10 {
			t.Errorf("borrowed slice len=%d cap=%d after Truncate(10), want 10/10", len(b), cap(b))
		}
	}); err != nil {
		t.Fatal(err)
	}
	// The tail was wiped and Destroy still verifies the untouched canary.
	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy after Truncate: %v", err)
	}
}
