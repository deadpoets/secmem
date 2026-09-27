package secmem

import (
	"bytes"
	"errors"
	"testing"
)

// TestArena_EmergencyWipeOnReadOnlySlab pins how a read-only slab and the
// emergency wipe compose. The janitor restores write access to wipe and
// deliberately leaves the slab that way (so a slot acquired before the wipe
// can still be released without faulting), but the arena's own readOnly flag
// used to stay set: Release then refused with ErrReadOnly for a protection
// that was no longer in force, and the slot could never be returned. And
// ReadOnly() was still accepted on the dead slab, re-protecting a page the
// janitor had deliberately left writable so that pre-wipe slots could be
// released — which, now that Release no longer defers to the stale flag,
// would have made that release a write to a PROT_READ page.
//
// Now: after WipeAllSecrets, ReadOnly and ReadWrite refuse with ErrWiped like
// every other state change on a dead object, and Release on a slot acquired
// before the wipe succeeds.
func TestArena_EmergencyWipeOnReadOnlySlab(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	arena, err := NewArena(32, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = arena.Destroy() }()
	slot, err := arena.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := slot.WithBytes(func(b []byte) { copy(b, bytes.Repeat([]byte{0x5A}, 32)) }); err != nil {
		t.Fatal(err)
	}
	if err := arena.ReadOnly(); err != nil {
		t.Fatalf("ReadOnly: %v", err)
	}
	// The documented contract while read-only: Release refuses.
	if err := slot.Release(); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Release on a read-only slab returned %v, want ErrReadOnly", err)
	}

	if err := WipeAllSecrets(); err != nil {
		t.Fatalf("WipeAllSecrets: %v", err)
	}

	// Dead slab: re-protecting it in either direction is refused.
	if err := arena.ReadOnly(); !errors.Is(err, ErrWiped) {
		t.Fatalf("ReadOnly after the emergency wipe returned %v, want ErrWiped", err)
	}
	if err := arena.ReadWrite(); !errors.Is(err, ErrWiped) {
		t.Fatalf("ReadWrite after the emergency wipe returned %v, want ErrWiped", err)
	}
	// The slot reads as zeros (still mapped) ...
	zeroed := false
	if err := slot.WithBytes(func(b []byte) {
		zeroed = bytes.Equal(b, make([]byte, 32))
	}); err != nil {
		t.Fatalf("read after the wipe: %v", err)
	}
	if !zeroed {
		t.Error("slot contents survived the emergency wipe")
	}
	// ... and can be released: the slab is writable, whatever readOnly says.
	if err := slot.Release(); err != nil {
		t.Fatalf("Release after the emergency wipe returned %v, want nil", err)
	}
	if slot.IsLive() {
		t.Fatal("slot still live after Release")
	}
	if err := arena.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
}
