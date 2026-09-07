package secmem

import (
	"bytes"
	"errors"
	"testing"
)

// TestArena_ReleaseAfterWipeAllSecretsIsClean pins Release's behaviour on a
// slot that was acquired BEFORE an emergency wipe, in a process that keeps
// running afterwards (a panic-recovery handler is a documented call site).
//
// WipeAllSecrets zeroes the whole slab in place — canary strips included — and
// leaves it mapped. The janitor clears its own canary layout for exactly that
// reason (retainWiped), but Release re-verified the slot's strip itself and so
// saw zeros where the pattern should be: it reported ErrCanaryViolation, a
// documented memory-safety bug report, for an overflow that never happened,
// on every slot released after the wipe. Release is teardown, not reuse: it
// must still wipe the slot (a write through the pre-wipe handle is the one
// gap WipeAllSecrets documents), still return it to the pool, and report
// nothing.
func TestArena_ReleaseAfterWipeAllSecretsIsClean(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	a, err := NewArena(32, 4)
	if err != nil {
		t.Skipf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	untouched, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire untouched: %v", err)
	}
	written, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire written: %v", err)
	}
	if err := untouched.WithBytes(func(b []byte) { copy(b, bytes.Repeat([]byte{0x5A}, len(b))) }); err != nil {
		t.Fatalf("fill untouched: %v", err)
	}

	if err := WipeAllSecrets(); err != nil {
		t.Fatalf("WipeAllSecrets: %v", err)
	}

	// The slot holds zeros and its strip holds zeros. Release must not read
	// the zeroed strip as an overflow.
	if err := untouched.Release(); err != nil {
		if errors.Is(err, ErrCanaryViolation) {
			t.Fatalf("Release after emergency wipe reported a canary violation for an overflow that never happened: %v", err)
		}
		t.Fatalf("Release after emergency wipe = %v, want nil", err)
	}
	if untouched.IsLive() {
		t.Error("IsLive() = true after Release")
	}
	if got := a.LiveCount(); got != 1 {
		t.Errorf("LiveCount() after Release = %d, want 1 (slot must go back to the pool)", got)
	}

	// The documented gap: a handle that predates the wipe still writes. Release
	// is the owner's last chance to zero that, so the wipe must not be skipped
	// along with the canary check.
	if err := written.WithBytes(func(b []byte) { copy(b, bytes.Repeat([]byte{0xC3}, len(b))) }); err != nil {
		t.Fatalf("WithBytes through a pre-wipe handle: %v", err)
	}
	start := written.Index() * a.stride
	end := start + a.slotSize
	if err := written.Release(); err != nil {
		t.Fatalf("Release of a slot written after the wipe = %v, want nil", err)
	}
	a.mu.rLock()
	leftover := bytes.Clone(a.region.inner[start:end])
	a.mu.rUnlock()
	if !bytes.Equal(leftover, make([]byte, len(leftover))) {
		t.Errorf("Release after emergency wipe left the slot unwiped: %x", leftover)
	}
	if got := a.LiveCount(); got != 0 {
		t.Errorf("LiveCount() after both Releases = %d, want 0", got)
	}

	// The arena stays dead — Release returned the slots, but nothing can take
	// them — and its teardown stays clean: the janitor's layout was cleared by
	// the wipe, so Destroy has no stale pattern to fail against either.
	if _, err := a.Acquire(); !errors.Is(err, ErrWiped) {
		t.Errorf("Acquire after Release of a wiped slot = %v, want ErrWiped", err)
	}
	if err := a.Destroy(); err != nil {
		t.Errorf("Destroy after emergency wipe and Release = %v, want nil", err)
	}
}
