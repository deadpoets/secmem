package secmem

import (
	"errors"
	"sync"
	"testing"
)

// TestArena_IsLiveRejectsStaleHandle pins IsLive to the handle rather than to
// the slot index.
//
// A one-slot arena guarantees the re-Acquire reuses the same index, so the only
// thing separating the two handles is the generation. Testing inUse alone made
// the stale handle report live while WithBytes refused it as released — two
// methods on the same handle disagreeing about whether it was usable.
func TestArena_IsLiveRejectsStaleHandle(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	a, err := NewArena(32, 1)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	stale, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if relErr := stale.Release(); relErr != nil {
		t.Fatalf("Release: %v", relErr)
	}
	fresh, err := a.Acquire() // same index, new generation
	if err != nil {
		t.Fatalf("re-Acquire: %v", err)
	}
	defer func() { _ = fresh.Release() }()

	if stale.Index() != fresh.Index() {
		t.Fatalf("test premise broken: stale idx %d != fresh idx %d", stale.Index(), fresh.Index())
	}
	if stale.IsLive() {
		t.Error("stale handle reports IsLive() = true after its slot was re-acquired by another owner")
	}
	if !fresh.IsLive() {
		t.Error("fresh handle reports IsLive() = false")
	}
	// IsLive must agree with what the access path actually does.
	if wErr := stale.WithBytes(func([]byte) {}); !errors.Is(wErr, ErrSlotReleased) {
		t.Errorf("stale handle WithBytes = %v, want ErrSlotReleased — IsLive and WithBytes disagree", wErr)
	}
}

// checkFreeList walks the intrusive free list and asserts every structural
// invariant it is supposed to hold: it terminates, visits no slot twice, stays
// in range, every slot on it is marked free, every slot NOT on it is in use,
// and its length agrees with the cached live counter.
//
// Walking the list is worth doing directly rather than only inferring its shape
// from Acquire's behaviour. The list lives inside slots[i].next now, so a bug
// that corrupts a link is invisible from the outside until the arena either
// leaks a slot or hands one out twice — and both of those are exactly what a
// secret-holding pool must never do.
func checkFreeList(t *testing.T, a *SecureArena) {
	t.Helper()
	a.alloc.Lock()
	defer a.alloc.Unlock()

	seen := make(map[int32]bool, a.count)
	for i := a.freeHead; i != -1; i = a.slots[i].next {
		if i < 0 || int(i) >= a.count {
			t.Fatalf("free list holds out-of-range index %d (count=%d)", i, a.count)
		}
		if seen[i] {
			t.Fatalf("free list revisits slot %d — the list has a cycle, so Acquire "+
				"would hand this slot to an unbounded number of owners", i)
		}
		seen[i] = true
		if a.slots[i].inUse != 0 {
			t.Fatalf("slot %d is on the free list but marked inUse", i)
		}
	}
	if want := a.count - len(seen); want != a.live {
		t.Fatalf("live counter = %d but the free list implies %d live slots", a.live, want)
	}
	for i := int32(0); int(i) < a.count; i++ {
		if seen[i] {
			continue
		}
		if a.slots[i].inUse != 1 {
			t.Fatalf("slot %d is neither on the free list nor in use — it is leaked", i)
		}
		if a.slots[i].next != -1 {
			t.Fatalf("live slot %d still carries free-list link %d — a stale link on a live "+
				"slot can splice it back onto the list while an owner holds it",
				i, a.slots[i].next)
		}
	}
}

// TestArena_FreeListIntegrityAcrossChurn drives a deterministic acquire/release
// pattern and re-validates the list structure after every operation. The
// pattern deliberately interleaves partial drains with partial refills so the
// list is exercised in every state: empty, full, and fragmented.
func TestArena_FreeListIntegrityAcrossChurn(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	const count = 16
	a, err := NewArena(24, count)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	checkFreeList(t, a)

	var held []*ArenaSlot
	// A deliberately uneven pattern: grab more than we give back, then unwind.
	for _, take := range []int{5, 3, 7, 1, 4} {
		for i := 0; i < take; i++ {
			s, acqErr := a.Acquire()
			if acqErr != nil {
				break // full is a legitimate outcome; the list must still be sane
			}
			held = append(held, s)
			checkFreeList(t, a)
		}
		// Give back every other one, from the front, so the list fragments.
		var keep []*ArenaSlot
		for i, s := range held {
			if i%2 == 0 {
				if relErr := s.Release(); relErr != nil {
					t.Fatalf("Release: %v", relErr)
				}
				checkFreeList(t, a)
				continue
			}
			keep = append(keep, s)
		}
		held = keep
	}

	for _, s := range held {
		if relErr := s.Release(); relErr != nil {
			t.Fatalf("final Release: %v", relErr)
		}
		checkFreeList(t, a)
	}
	if a.LiveCount() != 0 {
		t.Fatalf("LiveCount after releasing everything = %d, want 0", a.LiveCount())
	}
	// Every slot must be reachable again.
	for i := 0; i < count; i++ {
		if _, acqErr := a.Acquire(); acqErr != nil {
			t.Fatalf("re-Acquire %d after full unwind: %v — the list lost a slot", i, acqErr)
		}
	}
	checkFreeList(t, a)
}

// TestArena_FreeListNoDuplicateSlot is the invariant the free stack must hold:
// an index is on it at most once, so no two live handles can ever address the
// same slot. Concurrently double-Releasing one handle is the way to break it —
// both callers can pass the early liveness check, and a naive implementation
// pushes the index twice, after which two Acquires hand out the same secret
// bytes.
func TestArena_FreeListNoDuplicateSlot(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	const count = 4
	a, err := NewArena(32, count)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	for round := 0; round < 50; round++ {
		slot, acqErr := a.Acquire()
		if acqErr != nil {
			t.Fatalf("round %d: Acquire: %v", round, acqErr)
		}
		// All releasers are held at a barrier and let go at once. The bug needs
		// two goroutines INSIDE Release at the same time; started one by one
		// they tend to finish one by one, every releaser after the first fails
		// the early liveness check, and whether the regression is caught comes
		// down to scheduling luck. Measured, not assumed: with the guard in
		// Release deleted, the barrier-less version of this test went GREEN on a
		// single run and only failed once the run count was raised. With the
		// barrier it fails on round 0, plain and under -race. A test for a race
		// should not need to be run five times to see it.
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_ = slot.Release()
			}()
		}
		close(start)
		wg.Wait()

		// Exactly one slot came back: the arena must hold `count` slots total,
		// no more (a duplicated index) and no fewer (a lost one).
		//
		// The drain is BOUNDED. The free list is intrusive, so a double push
		// makes slots[i].next point back into the list and Acquire would keep
		// handing out slots forever, never returning ErrArenaFull. An unbounded
		// loop here would hang the suite instead of reporting the regression —
		// and a test that hangs on the exact bug it exists to catch is worse
		// than no test.
		var live []*ArenaSlot
		for len(live) <= count {
			s, e := a.Acquire()
			if e != nil {
				break
			}
			live = append(live, s)
		}
		if len(live) > count {
			t.Fatalf("round %d: arena kept handing out slots past its capacity of %d — "+
				"the free list has a cycle (an index was pushed twice)", round, count)
		}
		if len(live) != count {
			t.Fatalf("round %d: arena handed out %d slots, want %d "+
				"(free stack corrupted by concurrent double Release)", round, len(live), count)
		}
		seen := make(map[int]bool, count)
		for _, s := range live {
			if seen[s.Index()] {
				t.Fatalf("round %d: slot index %d handed out twice — two owners share one slot",
					round, s.Index())
			}
			seen[s.Index()] = true
		}
		for _, s := range live {
			if relErr := s.Release(); relErr != nil {
				t.Fatalf("round %d: Release: %v", round, relErr)
			}
		}
		checkFreeList(t, a)
	}
}

// TestArena_LiveCountTracksFreeList checks the O(1) counter stays in step with
// the free stack across acquire, release, idempotent re-release and refill.
func TestArena_LiveCountTracksFreeList(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	const count = 8
	a, err := NewArena(16, count)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	if got := a.LiveCount(); got != 0 {
		t.Fatalf("LiveCount on a fresh arena = %d, want 0", got)
	}

	slots := make([]*ArenaSlot, 0, count)
	for i := 0; i < count; i++ {
		s, acqErr := a.Acquire()
		if acqErr != nil {
			t.Fatalf("Acquire %d: %v", i, acqErr)
		}
		slots = append(slots, s)
		if got := a.LiveCount(); got != i+1 {
			t.Fatalf("LiveCount after %d Acquires = %d, want %d", i+1, got, i+1)
		}
	}
	if _, acqErr := a.Acquire(); acqErr == nil {
		t.Fatal("Acquire on a full arena returned no error, want ErrArenaFull")
	}

	for i, s := range slots {
		if relErr := s.Release(); relErr != nil {
			t.Fatalf("Release %d: %v", i, relErr)
		}
		if relErr := s.Release(); relErr != nil { // idempotent — must not double-count
			t.Fatalf("second Release %d: %v", i, relErr)
		}
		if want := count - i - 1; a.LiveCount() != want {
			t.Fatalf("LiveCount after %d Releases = %d, want %d", i+1, a.LiveCount(), want)
		}
	}

	// Every slot must be reusable — the free stack is back to full capacity.
	for i := 0; i < count; i++ {
		s, acqErr := a.Acquire()
		if acqErr != nil {
			t.Fatalf("re-Acquire %d after full drain: %v", i, acqErr)
		}
		defer func() { _ = s.Release() }()
	}
}

// TestArena_AcquireOrderIsAscendingOnFreshArena pins the observable ordering
// the free stack is seeded to preserve: a fresh arena hands out 0, 1, 2, …
func TestArena_AcquireOrderIsAscendingOnFreshArena(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	a, err := NewArena(16, 5)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	for want := 0; want < 5; want++ {
		s, acqErr := a.Acquire()
		if acqErr != nil {
			t.Fatalf("Acquire: %v", acqErr)
		}
		defer func() { _ = s.Release() }()
		if s.Index() != want {
			t.Fatalf("Acquire %d returned index %d, want %d", want, s.Index(), want)
		}
	}
}

func BenchmarkArenaAcquireRelease(b *testing.B) {
	if !platformHasSecureMemory {
		b.Skip("no secure memory on this platform")
	}
	counts := []int{8, 512, 4096}

	// The largest arena locks ~192 KiB, which exceeds BOTH default budgets this
	// runs under: Linux's 64 KiB RLIMIT_MEMLOCK and Windows' default minimum
	// working set (VirtualLock's ceiling). Raise it with the library's own
	// remedy — the same call NewArena's doc tells consumers to make at startup.
	// Safe in-process: EnsureMemlockLimit only ever raises (see
	// TestEnsureMemlockLimit_NeverLowers). Headroom covers guard pages, page
	// rounding, and anything else the binary already holds locked.
	largest := uint64(counts[len(counts)-1]) * uint64(32+canaryLen)
	if _, err := EnsureMemlockLimit(largest + 256*1024); err != nil {
		b.Logf("EnsureMemlockLimit: %v (hard cap reached; arenas that do not fit are skipped)", err)
	}

	for _, count := range counts {
		a, err := NewArena(32, count)
		if err != nil {
			// An unprivileged hard cap can still refuse the budget. That is an
			// environment limit, not a benchmark failure — the repo treats a
			// refused lock as a condition to report, never to fail on.
			b.Run(itoa(count), func(b *testing.B) {
				b.Skipf("cannot lock a %d-slot arena (%d KiB): %v",
					count, count*(32+canaryLen)/1024, err)
			})
			continue
		}
		// Hold all but one slot so the old linear scan would walk the whole
		// index on every Acquire — the case the free stack removes.
		held := make([]*ArenaSlot, 0, count-1)
		for i := 0; i < count-1; i++ {
			s, acqErr := a.Acquire()
			if acqErr != nil {
				b.Fatalf("prefill Acquire: %v", acqErr)
			}
			held = append(held, s)
		}
		b.Run(itoa(count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				s, acqErr := a.Acquire()
				if acqErr != nil {
					b.Fatalf("Acquire: %v", acqErr)
				}
				if relErr := s.Release(); relErr != nil {
					b.Fatalf("Release: %v", relErr)
				}
			}
		})
		for _, s := range held {
			_ = s.Release()
		}
		_ = a.Destroy()
	}
}
