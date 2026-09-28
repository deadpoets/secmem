package secmem

import (
	"bytes"
	"errors"
	"testing"
)

// TestEmergencyWipe_WriteAccessNotRestored_DoesNotFlagWiped drives the one
// emergency-path outcome in which nothing is wiped: the janitor cannot restore
// write access, so the wipe would fault, and the region is left as it was. The
// region must then NOT be flagged wiped. The flag means two things to its
// owner — the secret is gone, and (for an arena) the slab was left writable —
// and neither is true here: mutators would refuse a secret that is still
// present, and ArenaSlot.Release, which treats the flag as licence to write
// through a read-only slab, would write to a PROT_READ page and fault.
//
// mprotect on a live private mapping does not fail in practice, so the failure
// is injected through restoreWriteAccess, the seam wipeAndFree exposes for
// exactly this test (as sealProtect does for Seal's rollback).
func TestEmergencyWipe_WriteAccessNotRestored_DoesNotFlagWiped(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	arena, err := NewArena(32, 1)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = arena.Destroy() }()
	slot, err := arena.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	secret := bytes.Repeat([]byte{0x5A}, 32)
	if err := slot.WithBytes(func(b []byte) { copy(b, secret) }); err != nil {
		t.Fatal(err)
	}
	if err := arena.ReadOnly(); err != nil {
		t.Fatalf("ReadOnly: %v", err)
	}

	refused := errors.New("forced: mprotect refused")
	saved := restoreWriteAccess
	restoreWriteAccess = func(secRegion, int) error { return refused }
	wipeErr := WipeAllSecrets()
	restoreWriteAccess = saved

	if !errors.Is(wipeErr, errWipeSkipped) || !errors.Is(wipeErr, refused) {
		t.Fatalf("WipeAllSecrets returned %v, want an error wrapping errWipeSkipped and the mprotect failure", wipeErr)
	}
	if arena.wiped.Load() {
		t.Fatal("a slab that was not wiped is flagged wiped")
	}
	// Honest state: the secret is still there ...
	intact := false
	if err := slot.WithBytes(func(b []byte) { intact = bytes.Equal(b, secret) }); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !intact {
		t.Fatal("slot contents changed although the wipe reported it could not run")
	}
	// ... the slab is still PROT_READ, and Release still refuses rather than
	// writing to it (this line is a SIGSEGV if the flag had been set).
	if err := slot.Release(); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Release on the still-read-only slab returned %v, want ErrReadOnly", err)
	}
	// Recovery is the ordinary one, since the arena is not dead: ReadWrite,
	// Release, and Destroy (whose own wipe now finds write access restorable).
	if err := arena.ReadWrite(); err != nil {
		t.Fatalf("ReadWrite: %v", err)
	}
	if err := slot.Release(); err != nil {
		t.Fatalf("Release after ReadWrite: %v", err)
	}
	if err := arena.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
}
