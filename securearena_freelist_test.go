package secmem

import (
	"sync"
	"testing"
)

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
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = slot.Release()
			}()
		}
		wg.Wait()

		// Exactly one slot came back: the arena must hold `count` slots total,
		// no more (a duplicated index) and no fewer (a lost one).
		var live []*ArenaSlot
		for {
			s, e := a.Acquire()
			if e != nil {
				break
			}
			live = append(live, s)
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
