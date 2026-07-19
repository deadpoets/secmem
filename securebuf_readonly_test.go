package secmem

import (
	"bytes"
	"errors"
	"testing"
)

// TestReadOnly_MutatorsRefuseInsteadOfFaulting is the named regression for a
// bug FuzzBufferLifecycle surfaced: before the fix, a mutating method called
// after ReadOnly() wrote to the PROT_READ page and crashed the process with
// SIGSEGV, instead of returning an error like every other misuse in the
// library.
//
// The contract asserted here: after ReadOnly(), every mutating method —
// CopyIn, SetByteAt, Truncate, and ReadFrom (the one the first fix missed) —
// returns ErrReadOnly, with no fault and no silent write. ReadWrite() restores
// mutability. Reads remain allowed throughout (PROT_READ permits them).
func TestReadOnly_MutatorsRefuseInsteadOfFaulting(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(8)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if _, err := buf.CopyIn([]byte{1, 2, 3, 4}, 0); err != nil {
		t.Fatalf("CopyIn while writable: %v", err)
	}
	if err := buf.ReadOnly(); err != nil {
		t.Fatalf("ReadOnly: %v", err)
	}

	// Every mutator must now refuse with ErrReadOnly rather than fault.
	if _, err := buf.CopyIn([]byte{9}, 0); !errors.Is(err, ErrReadOnly) {
		t.Errorf("CopyIn after ReadOnly = %v, want ErrReadOnly", err)
	}
	if err := buf.SetByteAt(0, 0xFF); !errors.Is(err, ErrReadOnly) {
		t.Errorf("SetByteAt after ReadOnly = %v, want ErrReadOnly", err)
	}
	if err := buf.Truncate(2); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Truncate after ReadOnly = %v, want ErrReadOnly", err)
	}
	if _, err := buf.ReadFrom(bytes.NewReader([]byte("XXXXXXXX"))); !errors.Is(err, ErrReadOnly) {
		t.Errorf("ReadFrom after ReadOnly = %v, want ErrReadOnly", err)
	}

	// Reads still work while read-only.
	if _, err := buf.ByteAt(0); err != nil {
		t.Errorf("ByteAt while read-only should succeed, got %v", err)
	}

	// ReadWrite lifts the restriction.
	if err := buf.ReadWrite(); err != nil {
		t.Fatalf("ReadWrite: %v", err)
	}
	if err := buf.SetByteAt(0, 0xAB); err != nil {
		t.Errorf("SetByteAt after ReadWrite = %v, want nil", err)
	}
}

// TestReadOnly_SurvivesSealUnseal proves the read-only protection is preserved
// across a Seal/Unseal cycle: a buffer set read-only, then sealed and unsealed,
// is still read-only — both the flag and the physical page protection — so a
// post-unseal mutator still refuses rather than faulting.
//
// This also pins the cross-platform contract: the seal cipher writes in place
// (Windows CryptProtectMemory), so Seal must lift PROT_READ for the encrypt and
// Unseal must restore it. Before that fix, ReadOnly→Seal returned an error on
// Windows while succeeding on Linux.
func TestReadOnly_SurvivesSealUnseal(t *testing.T) {
	t.Parallel()

	buf, err := NewEmptyBuffer(8)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.ReadOnly(); err != nil {
		t.Fatalf("ReadOnly: %v", err)
	}
	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal of a read-only buffer: %v", err)
	}
	if err := buf.Unseal(); err != nil {
		t.Fatalf("Unseal: %v", err)
	}

	// Still read-only after the cycle: a mutator refuses (flag intact) ...
	if err := buf.SetByteAt(0, 1); !errors.Is(err, ErrReadOnly) {
		t.Errorf("SetByteAt after seal/unseal of a read-only buffer = %v, want ErrReadOnly", err)
	}
	// ... and a read still works, confirming the page is PROT_READ, not PROT_NONE.
	if _, err := buf.ByteAt(0); err != nil {
		t.Errorf("ByteAt after seal/unseal of a read-only buffer = %v, want nil", err)
	}
}
