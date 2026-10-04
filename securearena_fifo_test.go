package secmem

import "testing"

// TestArena_ReuseIsFIFO pins the order slots come back in: a released slot
// goes to the END of the free list, so it is the last to be handed out again.
// The list used to be LIFO, which made the slot a caller had just released the
// very next one acquired, by anyone: a slice wrongly retained from the old
// tenant's callback then pointed at the new tenant's secret at once. FIFO
// does not prevent that (see "No isolation between slots" on SecureArena), it
// only puts every other free slot in between.
func TestArena_ReuseIsFIFO(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	a, err := NewArena(32, 4)
	if err != nil {
		t.Skipf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	acquire := func() *ArenaSlot {
		t.Helper()
		s, err := a.Acquire()
		if err != nil {
			t.Fatalf("Acquire: %v", err)
		}
		return s
	}
	first, second := acquire(), acquire() // slots 0 and 1; 2 and 3 are free
	if err := first.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	// Free list is now 2, 3, 0.
	for _, want := range []int{2, 3, 0} {
		if got := acquire().Index(); got != want {
			t.Fatalf("Acquire after releasing slot 0 returned slot %d, want %d: "+
				"a released slot must be reused last, not first", got, want)
		}
	}
	if _, err := a.Acquire(); err != ErrArenaFull { //nolint:errorlint // sentinel returned unwrapped
		t.Fatalf("Acquire on a full arena = %v, want ErrArenaFull", err)
	}

	// Emptied and refilled: the list must still thread every slot once.
	if err := second.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if got := acquire().Index(); got != 1 {
		t.Fatalf("the only free slot is 1, Acquire returned %d", got)
	}
	if got := a.LiveCount(); got != 4 {
		t.Errorf("LiveCount() = %d, want 4", got)
	}
}
