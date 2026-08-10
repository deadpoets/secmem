package secmem

import (
	"testing"
)

// Contention benchmarks for SecureArena.
//
// These exist because a premise went unmeasured for the whole life of the type.
// slotMeta carried 48 bytes per slot of cache-line padding "to avoid false
// sharing between concurrent slot operations", and a note about a future
// lock-free upgrade — but every arena benchmark was single-goroutine, so
// nothing in the repo had ever established that concurrent slot operations
// contend at all, or where. Padding is a fix for a measured problem; without
// the measurement it is 48 bytes per slot of guesswork.
//
// The two benchmarks below bracket the question:
//
//   - ChurnParallel is maximum sharing. Every goroutine hits the same free-list
//     head, so it is a direct measurement of the alloc mutex under contention.
//   - BorrowParallel is ZERO sharing. Each goroutine owns its own slot for the
//     whole run and only borrows it. Nothing is logically shared between
//     goroutines, so anything less than flat scaling here is the shared lock
//     and cannot be anything else.
//
// Run them across core counts, which is where the shape shows up:
//
//	go test -run '^$' -bench 'Arena.*Parallel' -cpu 1,2,4,8,16 -count 10 .
//
// Read TESTING.md before quoting a number: these price the cost of the
// guarantee, they are not a performance claim, and an unpinned run measures the
// governor rather than the code.

// benchArena builds an arena for a contention benchmark, raising the locked
// budget the way NewArena's own documentation tells callers to. A refused lock
// is an environment limit, not a benchmark failure, so it skips rather than
// fails — the same discipline BenchmarkArenaAcquireRelease uses.
func benchArena(b *testing.B, slotSize, count int) *SecureArena {
	b.Helper()
	if !platformHasSecureMemory {
		b.Skip("no secure memory on this platform")
	}
	if _, err := EnsureMemlockLimit(uint64(count*(slotSize+canaryLen)) + 256*1024); err != nil {
		b.Logf("EnsureMemlockLimit: %v (hard cap reached)", err)
	}
	a, err := NewArena(slotSize, count)
	if err != nil {
		b.Skipf("cannot lock a %d-slot arena (%d KiB): %v", count, count*(slotSize+canaryLen)/1024, err)
	}
	b.Cleanup(func() { _ = a.Destroy() })
	return a
}

// BenchmarkArenaChurnParallel measures Acquire+Release from every core at once:
// the maximum-sharing case, since all goroutines pop and push the same free-list
// head under the same mutex.
//
// The arena is sized far above the concurrency so ErrArenaFull is unreachable
// and the number reflects lock behaviour rather than exhaustion.
func BenchmarkArenaChurnParallel(b *testing.B) {
	a := benchArena(b, 32, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s, err := a.Acquire()
			if err != nil {
				// b.Error, not b.Fatal: Fatal calls Goexit, which from a
				// RunParallel body kills one worker and hangs the rest.
				b.Error("Acquire:", err)
				return
			}
			if err := s.Release(); err != nil {
				b.Error("Release:", err)
				return
			}
		}
	})
}

// BenchmarkArenaBorrowParallel is the sharper of the two. Each goroutine
// acquires ONE slot up front and then only borrows it, so no two goroutines
// touch the same slot, the same free-list node, or the same secret bytes for the
// whole run. It is the "allocate once, borrow often" shape this type's own
// documentation recommends.
//
// With nothing logically shared, perfect scaling is the null hypothesis. Any
// departure from it is attributable to the one thing that IS shared — the alloc
// mutex that WithBytesErr takes to check liveness before it takes the arena's
// read lock — and to nothing else.
func BenchmarkArenaBorrowParallel(b *testing.B) {
	a := benchArena(b, 32, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		s, err := a.Acquire()
		if err != nil {
			b.Error("Acquire:", err)
			return
		}
		defer func() { _ = s.Release() }()
		for pb.Next() {
			if err := s.WithBytes(func(p []byte) { p[0]++ }); err != nil {
				b.Error("WithBytes:", err)
				return
			}
		}
	})
}

// BenchmarkArenaBorrowSerial is the uncontended floor for the borrow path, so
// the parallel number above has something to be a multiple of.
func BenchmarkArenaBorrowSerial(b *testing.B) {
	a := benchArena(b, 32, 4096)
	s, err := a.Acquire()
	if err != nil {
		b.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = s.Release() }()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := s.WithBytes(func(p []byte) { p[0]++ }); err != nil {
			b.Fatalf("WithBytes: %v", err)
		}
	}
}
