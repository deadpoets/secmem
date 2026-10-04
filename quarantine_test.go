//go:build linux || windows

package secmem

import (
	"testing"
	"unsafe"
)

// outerRange returns the bounds of buf's whole reservation, guards included.
func outerRange(buf *SecureBuffer) (lo, hi uintptr) {
	lo = uintptr(unsafe.Pointer(&buf.region.outer[0]))
	return lo, lo + uintptr(len(buf.region.outer))
}

// quarantineHeld returns the reservations the quarantine currently holds.
func quarantineHeld() [][]byte {
	destroyQuarantine.mu.Lock()
	defer destroyQuarantine.mu.Unlock()
	return append([][]byte(nil), destroyQuarantine.held...)
}

// withQuarantineLimits empties the quarantine, applies l for the test and
// restores the previous limits afterwards. Tests that use it are not parallel:
// the quarantine is process-wide.
func withQuarantineLimits(t *testing.T, l QuarantineLimits) {
	t.Helper()
	prev := SetQuarantineLimits(QuarantineLimits{})
	SetQuarantineLimits(l)
	t.Cleanup(func() { SetQuarantineLimits(prev) })
}

// TestQuarantine_DestroyedRangeIsNotReused is the property the quarantine
// exists for. Destroy used to unmap the reservation, and the allocator handed
// the same addresses to the next buffer, so a slice retained from the dead
// buffer silently became a view of a live one. The range must instead stay
// reserved and inaccessible, and no later allocation may land in it.
func TestQuarantine_DestroyedRangeIsNotReused(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	withQuarantineLimits(t, DefaultQuarantineLimits())

	buf, err := NewEmptyBuffer(64)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	lo, hi := outerRange(buf)
	inner := uintptr(unsafe.Pointer(&buf.region.inner[0]))
	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	for _, addr := range []uintptr{lo, inner, hi - 1} {
		if mapped, accessible := addrState(t, addr); !mapped || accessible {
			t.Errorf("address %#x of a destroyed buffer: mapped=%v accessible=%v, want a no-access reservation",
				addr, mapped, accessible)
		}
	}

	// The allocator would reuse a freed range at once; with the range still
	// reserved it cannot.
	for i := 0; i < 16; i++ {
		next, err := NewEmptyBuffer(64)
		if err != nil {
			t.Skipf("NewEmptyBuffer %d: %v", i, err)
		}
		defer func() { _ = next.Destroy() }()
		if nlo, nhi := outerRange(next); nlo < hi && lo < nhi {
			t.Fatalf("allocation %d landed at [%#x,%#x), inside the destroyed buffer's range [%#x,%#x): "+
				"a slice retained from the dead buffer now aliases a live one", i, nlo, nhi, lo, hi)
		}
	}
}

// TestQuarantine_RetainedSliceFaults reads through a slice kept past Destroy,
// after new buffers have been allocated and filled. In a child process: the
// read has to die on a fault at that address, not return another buffer's
// bytes.
func TestQuarantine_RetainedSliceFaults(t *testing.T) {
	if !probeFaulted(t, "retained_after_destroy") {
		t.Fatal("a read through a slice retained past Destroy did not fault: " +
			"the address range was given to a later allocation")
	}
}

// TestQuarantine_FIFOAndLimits pins the bound: the oldest reservation is the
// one released, a region larger than the byte limit is not held, and a zero
// limit turns the quarantine off.
func TestQuarantine_FIFOAndLimits(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	destroyed := func(size int) (lo uintptr) {
		t.Helper()
		b, err := NewEmptyBuffer(size)
		if err != nil {
			t.Skipf("NewEmptyBuffer: %v", err)
		}
		lo, _ = outerRange(b)
		if err := b.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		return lo
	}
	base := func(held [][]byte) (addrs []uintptr) {
		for _, h := range held {
			addrs = append(addrs, uintptr(unsafe.Pointer(&h[0])))
		}
		return addrs
	}

	withQuarantineLimits(t, QuarantineLimits{Regions: 2, Bytes: 1 << 30})
	first, second, third := destroyed(64), destroyed(64), destroyed(64)
	got := base(quarantineHeld())
	if len(got) != 2 || got[0] != second || got[1] != third {
		t.Fatalf("held after three destroys with a limit of 2 = %#x, want the last two [%#x %#x] (first was %#x)",
			got, second, third, first)
	}
	for _, addr := range got {
		if mapped, accessible := addrState(t, addr); !mapped || accessible {
			t.Errorf("held reservation %#x: mapped=%v accessible=%v", addr, mapped, accessible)
		}
	}

	// Bytes: three pages of reservation fit, a larger region does not.
	page := uint64(len(quarantineHeld()[0])) / 3
	withQuarantineLimits(t, QuarantineLimits{Regions: 8, Bytes: 3 * page})
	big := destroyed(int(4 * page))
	if held := base(quarantineHeld()); len(held) != 0 {
		t.Errorf("a region over the byte limit was held: %#x (region at %#x)", held, big)
	}
	small := destroyed(64)
	if held := base(quarantineHeld()); len(held) != 1 || held[0] != small {
		t.Errorf("held = %#x, want only the small region at %#x", held, small)
	}
	destroyed(64) // a second three-page region exceeds the byte limit: the first goes
	if held := base(quarantineHeld()); len(held) != 1 || held[0] == small {
		t.Errorf("held = %#x after the byte limit was exceeded, want one region, not the older one at %#x", held, small)
	}

	withQuarantineLimits(t, QuarantineLimits{})
	destroyed(64)
	if held := quarantineHeld(); len(held) != 0 {
		t.Errorf("the quarantine held %d regions with zero limits", len(held))
	}
}

// TestQuarantine_HoldsNoLockBudget destroys far more buffers than any lock
// budget this suite runs under could hold at once. A held reservation that
// kept its pages locked, or committed, would exhaust the budget long before
// the loop ends.
func TestQuarantine_HoldsNoLockBudget(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	withQuarantineLimits(t, DefaultQuarantineLimits())
	first, err := NewEmptyBuffer(64)
	if err != nil {
		t.Skipf("NewEmptyBuffer: %v", err)
	}
	_ = first.Destroy()

	const rounds = 20000
	for i := 0; i < rounds; i++ {
		b, err := NewEmptyBuffer(64)
		if err != nil {
			t.Fatalf("allocation %d of %d failed with %d reservations held: %v", i, rounds, len(quarantineHeld()), err)
		}
		if err := b.Destroy(); err != nil {
			t.Fatalf("Destroy %d: %v", i, err)
		}
	}
	if n, limit := len(quarantineHeld()), DefaultQuarantineLimits().Regions; n > limit {
		t.Errorf("the quarantine holds %d regions, over its limit of %d", n, limit)
	}
}
