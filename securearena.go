// securearena.go implements SecureArena, a fixed-size slot
// pool backed by a single mmap'd slab.
//
// # Motivation
//
// Each SecureBuffer occupies at least one full OS page (≥4 KiB on amd64) and
// registers individually with the emergency janitor.  For O(10) long-lived
// secrets this is correct.  Under server-grade concurrency (hundreds of
// short-lived per-session keys), per-buffer page overhead would exhaust
// RLIMIT_MEMLOCK and create O(N) janitor entries.
//
// SecureArena provisions one contiguous mmap'd slab subdivided into fixed-size
// slots.  All slots share the same mlock, MADV_DONTDUMP, and janitor
// registration — N session keys incur O(1) overhead at the OS and GC layers.
//
// # Pointer-Free Slot Index
//
// slotMeta contains only scalar fields (no pointer fields, no slice
// headers, no interface values).  The GC treats a []slotMeta as a
// "leaf" allocation — it scans the slice header but does NOT trace into the
// backing array.  This eliminates per-slot GC scanning entirely.
//
// The index is also the ONLY per-slot heap allocation, at 16 bytes per slot.
// It used to be three — a 64-byte padded slotMeta, an 8-byte free-stack entry,
// and a 16-byte materialized canary zone, 88 bytes total, or nearly twice the
// locked bytes of a 32-byte slot. A type whose whole purpose is to make
// per-secret overhead small should not cost more in swappable GC-visible heap
// than the locked secret it holds. The free list moved into slotMeta.next, the
// canary zones became a descriptor (canaryLayout), and the cache-line padding
// went — see slotMeta for why it protected nothing.
//
// # When to Use SecureArena vs SecureBuffer
//
//   - SecureBuffer: long-lived or high-value material (master keys, CA keys,
//     signing keys, provider tokens).  Isolated page, per-buffer mprotect.
//   - SecureArena: many small, same-size, short-lived secrets (SSH session
//     keys, ephemeral HMAC keys, per-request nonces).  One slab, one mlock.
//
// # Concurrency Model
//
//   - mu (bufferRWLock): rLock held during any WithBytes/WithBytesErr callback
//     on any slot.  Exclusive lock held only by Destroy.  Ensures no callback
//     races with munmap.
//   - alloc (sync.Mutex): held briefly during Acquire and Release to update
//     slot bookkeeping (inUse flag, destroyed flag).  Never held across a
//     callback.
//
// Each ArenaSlot should be owned by a single goroutine at a time.  Concurrent
// access to the same slot is not prevented by internal locking — callers are
// responsible for external synchronization if needed.
//
// # Neighbor-Slot Isolation
//
// Because multiple slots share a page, sub-page mprotect is not possible.
// ReadOnly / ReadWrite operate on the full slab — use judiciously.  Slot
// indices are bounds-checked on every access to prevent cross-slot writes.

package secmem

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
)

// slotMeta holds per-slot metadata. Exactly 16 bytes, with no wasted padding.
//
// Pointer-free: only scalars. The GC treats a []slotMeta backing array as a
// leaf — no per-slot GC scanning occurs regardless of how many slots the arena
// contains. This is the arena's O(1)-GC-overhead property and every field here
// is chosen to preserve it.
//
// # Why there is no cache-line padding
//
// This struct used to be padded to 64 bytes to give each slot its own cache
// line, against false sharing "between concurrent slot operations". There are
// none: every read and every write of every field below happens with
// arena.alloc held (Acquire, Release, WithBytesErr's liveness check, IsLive).
// A mutex that serializes all of them leaves no two cores touching adjacent
// entries, so the padding protected nothing that could happen — it was
// forward-looking, for a lock-free upgrade that has not been written.
//
// It was not free: 48 bytes per slot of ordinary, swappable, GC-visible Go
// heap, which for a 32-byte slot was more than the secret itself. Since the
// arena exists precisely to make per-secret overhead small, paying a 4x
// metadata multiplier for a hypothetical future rewrite is the wrong trade.
// If that rewrite lands, padding comes back with it — measured against the
// implementation that needs it, not guessed at years early. Note also that the
// intrusive free list below is the canonical shape for a lock-free Treiber
// stack, whose contention is on the head rather than on these entries.
type slotMeta struct {
	// generation is incremented on every Acquire and is the ABA guard: a stale
	// ArenaSlot handle whose generation no longer matches is refused by
	// WithBytes* and Release.
	//
	// It is uint64, not uint32, because the guard has to outlive the counter.
	// The free list is LIFO, so a workload that acquires and releases one slot
	// at a time increments the SAME slot's counter every cycle — at the ~320
	// ns/op this arena benchmarks at, a 32-bit counter wraps in about 23
	// minutes of churn, well inside the lifetime of the long-running server
	// this type exists for. Past the wrap a stale handle matches again and can
	// read, overwrite, or free a slot another owner is live in. 64 bits is not
	// reachable.
	generation uint64

	// next is the intrusive free-list link: the index of the next free slot, or
	// -1 to terminate. Meaningful only while inUse == 0; Acquire sets it to -1
	// on the way out so a live slot never carries a stale link.
	//
	// int32 rather than int because it costs nothing here — 8-aligning
	// generation leaves exactly 8 bytes for next and inUse together — and
	// because holding the link inside slotMeta is what let the separate
	// free []int stack be deleted. That stack was another 8 bytes per slot for
	// information this field already implies. The int32 width is why NewArena
	// rejects count > math.MaxInt32 explicitly rather than overflowing quietly.
	next int32

	// inUse is uint32 (not bool) to allow a future lock-free upgrade to
	// atomic.Uint32; 1 = live (acquired), 0 = free; accessed under arena.alloc.
	// It occupies padding that 8-aligning generation would have wasted anyway.
	inUse uint32
}

// SecureArena is a single mmap'd slab providing N fixed-size secret slots.
//
// Create with [NewArena].  Acquire slots with [SecureArena.Acquire].  Release
// individual slots with [ArenaSlot.Release].  Wipe and free the entire slab
// with [SecureArena.Destroy].
//
// Destroy is idempotent and goroutine-safe.  After Destroy, all subsequent
// Acquire calls return [ErrArenaDestroyed].
type SecureArena struct {
	// arenaRedactor is embedded (not a value receiver on SecureArena itself —
	// alloc below is a value sync.Mutex that go vet's copylocks would flag on
	// any value-receiver method declared directly on SecureArena) so its
	// String/GoString/Format/LogValue methods promote into both SecureArena's
	// and *SecureArena's method sets. See redact.go.
	arenaRedactor

	// mu: rLock is held by all WithBytes/WithBytesErr callbacks; exclusive lock
	// is held only by Destroy.  Uses bufferRWLock (not sync.RWMutex) so all
	// blocking states are durably blocked under testing/synctest.
	mu *bufferRWLock

	// alloc guards the destroyed flag and slots[i].inUse bookkeeping.
	// Never held across a callback or across mu.lock.
	alloc sync.Mutex

	// region is the guarded slab: inner (wipe/lock/protect target, canary
	// strips included) bracketed by PROT_NONE guard pages inside outer (the
	// unmap target). See secRegion for the field contract. Zeroed after
	// Destroy.
	region secRegion

	// readOnly is true while ReadOnly() has set the slab to PROT_READ.
	// ArenaSlot.Release checks it and returns ErrReadOnly rather than faulting
	// on the slot wipe (a write to the PROT_READ slab). Destroy is unaffected —
	// its wipe path forces the slab writable first. Protected by mu.
	readOnly bool

	// slots is the metadata index, and — through slotMeta.next — the free list
	// itself. Pointer-free leaf: the GC scans the slice header but NOT the
	// backing array. len(slots) == count. This is the ONLY heap allocation in
	// the arena that scales with count; see NewArena on why that matters.
	slots []slotMeta

	// freeHead is the head of the intrusive LIFO free list threaded through
	// slots[i].next, or -1 when the arena is full. It is what makes Acquire and
	// Release O(1) rather than a scan over slots. Guarded by alloc.
	//
	// Invariant: a slot is reachable from freeHead at most once, and exactly
	// when its slots[i].inUse == 0. Release enforces it by re-checking inUse
	// and the generation under alloc before pushing, so a double Release of the
	// same handle cannot hand the same slot to two live owners.
	//
	// That re-check is load-bearing in a way it was not when the free list was
	// a slice: pushing an index twice onto a slice produced a duplicate entry,
	// which is bad; pushing a node twice onto a linked list produces a CYCLE,
	// after which Acquire hands out the same slot forever and never reports
	// ErrArenaFull. Same guard, strictly higher stakes — do not weaken it.
	//
	// Seeded so slots[i].next == i+1 and the last is -1, which makes the first
	// Acquires pop 0, 1, 2, … — the natural order a fresh arena used to hand
	// out, preserved because it is the observable part. After any Release the
	// order is most-recently-freed-first, which is deliberate: a just-released
	// slot is the one most likely to still be cache-warm.
	//
	// int32 to match slotMeta.next, so the whole free list is one width and no
	// narrowing conversion exists anywhere to get wrong. NewArena's count
	// ceiling is what makes that width sufficient.
	freeHead int32

	// live is the number of acquired slots, cached so LiveCount is O(1) instead
	// of walking the free list. Guarded by alloc, and updated in the same
	// critical section as every freeHead change so the two cannot drift.
	live int

	// slotSize is the usable bytes per slot (caller-requested).
	slotSize int

	// stride is slotSize + canaryLen: each slot is followed by a canary strip
	// so an overflow out of slot i corrupts the strip instead of silently
	// running into slot i+1's secret. Slot i's data is
	// inner[i*stride : i*stride+slotSize]; its strip fills the rest of the
	// stride. Guard PAGES between slots are deliberately absent — a page per
	// gap would defeat the slab's O(1)-OS-overhead purpose; the slab's two
	// outer edges are guarded by the allocation itself.
	stride int

	// count is len(slots) — cached to avoid a len() on the hot path.
	count int

	// backing records which protections the slab allocation actually received.
	// Immutable after construction; read by Capabilities without any lock.
	backing allocInfo

	// destroyed mirrors region.inner == nil under alloc, allowing early
	// rejection of Acquire without acquiring mu.
	destroyed bool

	// wiped is set by WipeAllSecrets when the slab was wiped in place and
	// deliberately left mapped. Shared with janitorRegion — the emergency path
	// holds no *SecureArena, so this flag is how it reaches one. Acquire then
	// refuses with ErrWiped: handing out a slot would put a fresh secret in a
	// slab the emergency wipe already reported as handled. Existing slots stay
	// readable (they hold zeros), preserving the no-fault guarantee.
	wiped *atomic.Bool

	// cleanup is the AddCleanup handle.  Stopped by Destroy.
	cleanup runtime.Cleanup

	// janitorKey identifies this arena's raw slab in emergencyJanitor.
	janitorKey uintptr
}

// ArenaSlot is a handle to one fixed-size slot in a [SecureArena].
//
// Access secret data via [ArenaSlot.WithBytes] or [ArenaSlot.WithBytesErr].
// Return the slot to the pool with [ArenaSlot.Release].
//
// A slot should be owned by a single goroutine at a time; concurrent access
// to the same slot from multiple goroutines is not internally synchronized.
type ArenaSlot struct {
	arena *SecureArena
	// idx is int32 for the same reason slotMeta.next is: it is an index into
	// slots, whose length NewArena caps at math.MaxInt32, and keeping one width
	// across the whole free list means there is no narrowing conversion in the
	// hot path to get wrong (or to have to explain to gosec).
	idx        int32
	generation uint64 // matches slots[idx].generation at Acquire time — ABA guard
}

// NewArena creates a SecureArena with count fixed-size slots, each of
// slotSize bytes.
//
// The underlying slab is one contiguous guarded mmap region: PROT_NONE guard
// pages bracket the slab's two outer edges, and each slot is followed by a
// canaryLen-byte canary strip, verified on [ArenaSlot.Release] and on
// [SecureArena.Destroy]. There are deliberately NO guard pages between slots
// (a page per gap would defeat the slab's O(1)-OS-overhead purpose); the
// strips detect inter-slot overflows instead of trapping them.
// A single emergency janitor registration covers all slots.
//
// slotSize and count must both be > 0, and count must be <= math.MaxInt32.
//
// Common errors: EPERM / ENOMEM from mlock (RLIMIT_MEMLOCK exceeded). On
// platforms with no lockable off-heap memory the error is [ErrNoSecureMemory]
// unless [WithInsecureFallback] is passed.
//
// # Memory budget
//
// An arena costs (slotSize+16) bytes of LOCKED memory per slot, plus 16 bytes
// per slot of ordinary Go heap for the slot index — so roughly 1.3x the locked
// slab for a 32-byte slot, and proportionally less as slots get larger. Budget
// for both: the locked half draws on RLIMIT_MEMLOCK (see [EnsureMemlockLimit]),
// the heap half does not and is swappable and GC-visible like any other slice.
//
// The order of the two allocations is deliberate and load-bearing. The locked
// slab is requested FIRST and fails by returning an error; the heap index that
// follows can only fail by runtime.throw, which is not recoverable — no
// deferred function runs, [WipeAllSecrets] never gets called, the process is
// simply gone. Requesting the larger, recoverable allocation first means that
// on any budget too small for the arena you get an error from mlock rather than
// a dead process. The per-slot heap cost is deliberately kept below the
// per-slot locked cost (16 < slotSize+16 for every legal slotSize) so this
// ordering holds for every shape of arena, not just large-slot ones.
//
// That guard weakens as the locked budget rises: an arena with a memlock budget
// of a third of RAM can lock its slab successfully and then die on the heap
// index. If you raise RLIMIT_MEMLOCK to unlimited — which many container
// configurations do by default — bound count yourself. See [EnsureMemlockLimit].
func NewArena(slotSize, count int, opts ...Option) (*SecureArena, error) {
	if slotSize <= 0 {
		return nil, fmt.Errorf("secmem.NewArena: slotSize must be > 0, got %d", slotSize)
	}
	if count <= 0 {
		return nil, fmt.Errorf("secmem.NewArena: count must be > 0, got %d", count)
	}
	if count > math.MaxInt32 {
		// slotMeta.next is an int32 index into slots (see the field comment), so
		// a larger count would wrap the free-list links silently. Refuse it here
		// rather than corrupt the list. The slab for such an arena is at least
		// 36 GiB and would be refused below anyway; this exists so the failure
		// is an error with a reason instead of a subtle miscount.
		return nil, fmt.Errorf("secmem.NewArena: count must be <= %d, got %d", math.MaxInt32, count)
	}
	stride := slotSize + canaryLen
	if slotSize > math.MaxInt/count-canaryLen {
		return nil, fmt.Errorf("secmem.NewArena: (slotSize+canary)*count overflows int (slotSize=%d, count=%d)", slotSize, count)
	}
	if err := gateInsecure(platformHasSecureMemory, applyOptions(opts)); err != nil {
		return nil, fmt.Errorf("secmem.NewArena: %w", err)
	}

	// ORDER IS LOAD-BEARING — do not hoist the cheap allocations above this one.
	//
	// The locked slab is the only allocation here that fails by RETURNING AN
	// ERROR. Everything after it is Go heap, where an allocation the OS refuses
	// is runtime.throw: no recover, no deferred wipe, no WipeAllSecrets, process
	// gone. So the biggest request has to be the recoverable one, and it has to
	// go first — on any budget that cannot hold this arena, mlock/VirtualLock
	// refuses here and NewArena returns cleanly.
	//
	// See the "Memory budget" section of the doc comment for how much heap
	// follows and why it is now smaller than the slab per slot.
	totalBytes := stride * count
	region, _, info, err := allocSecretMem(totalBytes)
	if err != nil {
		return nil, fmt.Errorf("secmem.NewArena: %w", err)
	}

	// Arm the canary strips (one after each slot) and the page-rounding tail.
	// The SAME descriptor is handed to the janitor below, so the ranges armed
	// here and the ranges verified before the wipe cannot drift apart.
	canary := arenaCanary(stride, slotSize, count, len(region.inner))
	if err := canary.arm(region.inner); err != nil {
		_ = freeSecretMem(region) // nothing secret written yet
		return nil, fmt.Errorf("secmem.NewArena: %w", err)
	}

	// The one heap allocation that scales with count. Seed the intrusive free
	// list in ascending order so the first Acquires hand out 0, 1, 2, …
	slots := make([]slotMeta, count)
	for i := range slots {
		slots[i].next = int32(i + 1)
	}
	slots[count-1].next = -1

	a := &SecureArena{
		mu:       newBufferRWLock(),
		wiped:    new(atomic.Bool),
		region:   region,
		slots:    slots,
		freeHead: 0,
		slotSize: slotSize,
		stride:   stride,
		count:    count,
		backing:  info,
	}

	// Register the slab with emergency janitor using raw metadata only.
	// Arenas have no Seal, hence no seal-cipher state.
	a.janitorKey = emergencyJanitor.register(region, canary, a.mu, nil, a.wiped)

	// Safety-net cleanup: wipe and free the slab if Destroy was forgotten.
	// Only the slab size is captured (not a reference to a) so that the
	// cleanup closure cannot keep a alive and prevent it from becoming
	// unreachable.
	slabBytes := len(region.inner)
	a.cleanup = runtime.AddCleanup(a, func(key uintptr) {
		slog.Warn("secmem: SecureArena finalized without explicit Destroy()",
			slog.Int("slab_bytes", slabBytes),
			slog.String("advice", "call Destroy() explicitly for deterministic wipe"),
		)
		if err := emergencyJanitor.release(key, false); err != nil {
			slog.Error("secmem: SecureArena cleanup release failed",
				slog.Any("error", err),
			)
		}
	}, a.janitorKey)

	return a, nil
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// Destroy wipes the entire slab and releases the mmap'd region.
//
// Steps:
//  1. Mark arena destroyed under alloc (blocks new Acquire).
//  2. Acquire exclusive mu lock (waits for all in-flight callbacks to return).
//  3. Wipe full raw region (REP STOSB + CLFLUSH on amd64).
//  4. Madvise DONTNEED.
//  5. Munlock + Munmap.
//  6. Nil raw — makes IsDestroyed() = true and Destroy idempotent.
//
// Destroy is idempotent and goroutine-safe. A second concurrent Destroy blocks
// on the exclusive lock rather than returning the moment it sees the destroyed
// flag: "Destroy returned" has to mean "the slab is wiped" for every caller,
// not only for the one that won the flag, or a concurrent caller could act on
// "the secret is gone" while the first call is still mid-wipe. This matches
// SecureBuffer.Destroy, which takes its exclusive lock before testing state.
func (a *SecureArena) Destroy() error {
	if a == nil {
		return nil
	}

	// Mark destroyed so new Acquire calls fail fast without acquiring mu.
	a.alloc.Lock()
	a.destroyed = true
	a.alloc.Unlock()

	// Acquire exclusive lock — waits for all in-flight WithBytes callbacks,
	// and for any Destroy already running.
	a.mu.lock()
	defer a.mu.unlock()

	if a.region.inner == nil {
		return nil // already destroyed — idempotent
	}

	a.cleanup.Stop()

	// Take exclusive ownership from janitor registry and wipe/free exactly once.
	// If the cleanup or emergency-wipe path already released it, do not touch raw.
	err := emergencyJanitor.release(a.janitorKey, true)
	a.region = secRegion{}

	runtime.KeepAlive(a)

	if err != nil {
		return fmt.Errorf("secmem.SecureArena.Destroy: %w", err)
	}
	return nil
}

// IsDestroyed reports whether the arena has been destroyed.
func (a *SecureArena) IsDestroyed() bool {
	if a == nil {
		return true
	}
	a.alloc.Lock()
	d := a.destroyed
	a.alloc.Unlock()
	return d
}

// ---------------------------------------------------------------------------
// Slot management
// ---------------------------------------------------------------------------

// Acquire returns the next free slot for exclusive use by the caller.
//
// Returns [ErrArenaFull] if all slots are occupied.
// Returns [ErrArenaDestroyed] if the arena has been destroyed.
func (a *SecureArena) Acquire() (*ArenaSlot, error) {
	if a == nil {
		return nil, ErrArenaDestroyed
	}

	a.alloc.Lock()
	defer a.alloc.Unlock()

	if a.destroyed {
		return nil, ErrArenaDestroyed
	}
	if a.wiped.Load() {
		return nil, ErrWiped
	}

	i := a.freeHead
	if i < 0 {
		return nil, ErrArenaFull
	}
	a.freeHead = a.slots[i].next
	// Clear the link on the way out: a live slot must not carry a stale index.
	// It costs one store and makes "reachable from freeHead" and "inUse == 0"
	// checkable against each other rather than merely believed.
	a.slots[i].next = -1
	a.slots[i].inUse = 1
	a.slots[i].generation++
	a.live++
	return &ArenaSlot{arena: a, idx: i, generation: a.slots[i].generation}, nil
}

// LiveCount returns the number of currently acquired (live) slots.
func (a *SecureArena) LiveCount() int {
	if a == nil {
		return 0
	}
	a.alloc.Lock()
	defer a.alloc.Unlock()
	return a.live
}

// Cap returns the total slot capacity of the arena.
func (a *SecureArena) Cap() int {
	if a == nil {
		return 0
	}
	return a.count
}

// SlotSize returns the usable bytes per slot.
func (a *SecureArena) SlotSize() int {
	if a == nil {
		return 0
	}
	return a.slotSize
}

// ReadOnly sets the entire slab to read-only (PROT_READ).
// Affects ALL slots — sub-page mprotect is not possible.
//
// Call ReadWrite before releasing a slot: [ArenaSlot.Release] wipes the slot,
// which is a write, so it returns [ErrReadOnly] while the slab is read-only
// rather than faulting. [SecureArena.Destroy] needs no such call — its wipe
// path makes the slab writable first.
//
// The exclusive lock is held to drain all in-flight WithBytes callbacks
// before the mprotect, preventing a SIGSEGV from a concurrent write hitting
// a PROT_READ page.
func (a *SecureArena) ReadOnly() error {
	if a == nil {
		return errors.New("secmem.SecureArena.ReadOnly: nil receiver")
	}
	a.mu.lock()
	defer a.mu.unlock()
	if a.region.inner == nil {
		return fmt.Errorf("secmem.SecureArena.ReadOnly: %w", ErrArenaDestroyed)
	}
	if err := mprotectSecretMem(a.region, 1 /*PROT_READ*/); err != nil {
		return fmt.Errorf("secmem.SecureArena.ReadOnly: %w", err)
	}
	a.readOnly = true
	return nil
}

// ReadWrite restores read-write access to the entire slab.
//
// The exclusive lock is held to drain all in-flight callbacks before the
// mprotect (arena SB-3 equivalent fix).
func (a *SecureArena) ReadWrite() error {
	if a == nil {
		return errors.New("secmem.SecureArena.ReadWrite: nil receiver")
	}
	a.mu.lock()
	defer a.mu.unlock()
	if a.region.inner == nil {
		return fmt.Errorf("secmem.SecureArena.ReadWrite: %w", ErrArenaDestroyed)
	}
	if err := mprotectSecretMem(a.region, 3 /*PROT_READ|PROT_WRITE*/); err != nil {
		return fmt.Errorf("secmem.SecureArena.ReadWrite: %w", err)
	}
	a.readOnly = false
	return nil
}

// ---------------------------------------------------------------------------
// ArenaSlot — access API
// ---------------------------------------------------------------------------

// WithBytes calls fn with the slot's byte region.
//
// The slice is valid ONLY for the duration of fn.  Never store or pass it to
// a goroutine.  Returns [ErrSlotReleased] if the slot has been released.
// Returns [ErrArenaDestroyed] if the arena has been destroyed.
func (s *ArenaSlot) WithBytes(fn func([]byte)) error {
	if fn == nil {
		return errors.New("secmem.ArenaSlot.WithBytes: nil fn")
	}
	return s.WithBytesErr(func(b []byte) error {
		fn(b)
		return nil
	})
}

// WithBytesErr is like [ArenaSlot.WithBytes] but fn may return an error.
func (s *ArenaSlot) WithBytesErr(fn func([]byte) error) error {
	if fn == nil {
		return errors.New("secmem.ArenaSlot.WithBytesErr: nil fn")
	}
	if s == nil {
		return ErrSlotReleased
	}

	// Check liveness under alloc — fast path before acquiring the arena RLock.
	s.arena.alloc.Lock()
	if s.arena.destroyed {
		s.arena.alloc.Unlock()
		return ErrArenaDestroyed
	}
	if s.arena.slots[s.idx].inUse == 0 || s.arena.slots[s.idx].generation != s.generation {
		s.arena.alloc.Unlock()
		return ErrSlotReleased
	}
	s.arena.alloc.Unlock()

	// Hold arena RLock for the callback — blocks Destroy from unmapping.
	s.arena.mu.rLock()
	defer s.arena.mu.rUnlock()

	if s.arena.region.inner == nil {
		return ErrArenaDestroyed
	}

	// Capacity-clamped to the slot's usable bytes: fn cannot re-slice its
	// argument into the canary strip or the neighbouring slot.
	start := int(s.idx) * s.arena.stride
	end := start + s.arena.slotSize
	return fn(s.arena.region.inner[start:end:end])
}

// Release wipes the slot's byte region and returns it to the arena pool.
//
// After Release, all subsequent WithBytes/WithBytesErr calls return
// [ErrSlotReleased].  Calling Release again is a no-op (idempotent).
//
// The wipe happens BEFORE the slot is marked free (SA-1 fix): this ensures
// the next Acquire cannot read stale secret data from this slot.
//
// Release also verifies the slot's trailing canary strip. If code overflowed
// this slot, Release returns [ErrCanaryViolation] — the wipe, the re-arming
// of the strip, and the return of the slot to the pool all complete
// regardless; the error is a bug report, not a refusal.
//
// If the arena is read-only ([SecureArena.ReadOnly]), Release returns
// [ErrReadOnly] without wiping — the wipe is a write the PROT_READ slab would
// fault on. The slot stays in use; call [SecureArena.ReadWrite] first, or let
// [SecureArena.Destroy] wipe it (it makes the slab writable internally).
func (s *ArenaSlot) Release() error {
	if s == nil {
		return nil
	}

	// Early idempotent check under alloc — no-op if already free or stale handle.
	s.arena.alloc.Lock()
	if s.arena.slots[s.idx].inUse == 0 || s.arena.slots[s.idx].generation != s.generation {
		s.arena.alloc.Unlock()
		return nil
	}
	s.arena.alloc.Unlock()

	// Verify + wipe FIRST — under rLock to prevent Destroy from unmapping
	// mid-wipe. The slot is still marked inUse=1, so no other goroutine can
	// Acquire the same index until we mark it free below.
	var violated bool
	s.arena.mu.rLock()
	if s.arena.region.inner != nil {
		if s.arena.readOnly {
			// The slab is PROT_READ; the canary re-arm and slot wipe below are
			// writes that would fault the process. Refuse cleanly instead. The
			// slot stays in use and un-wiped — still protected by the read-only
			// page, and wiped when the caller ReadWrite()s and releases again,
			// or on Destroy (which forces the slab writable). This honors the
			// "ReadWrite before a slot write" contract on ReadOnly. Checked
			// inside the live-region guard so a Release after Destroy (region
			// already nil) stays an idempotent no-op, never ErrReadOnly.
			s.arena.mu.rUnlock()
			return fmt.Errorf("secmem.ArenaSlot.Release: %w", ErrReadOnly)
		}
		start := int(s.idx) * s.arena.stride
		end := start + s.arena.slotSize
		strip := s.arena.region.inner[end : start+s.arena.stride]
		if !canaryIntact(strip) {
			violated = true
			// Re-arm the strip so a later overflow of the recycled slot is
			// still detectable. fillCanary cannot fail here: the pattern was
			// already initialized when the arena armed it at construction.
			_ = fillCanary(strip)
		}
		secureWipeSlice(s.arena.region.inner[start:end])
	}
	// Arena was destroyed concurrently — Destroy already wiped everything.
	s.arena.mu.rUnlock()

	// NOW mark free — slot is only available for re-Acquire after wipe completes.
	//
	// The inUse/generation pair is re-checked under alloc before the slot goes
	// back on the free list. The early check above is not enough: two goroutines
	// calling Release on the SAME handle can both pass it, and pushing twice
	// would put one slot on the list twice — handing the same secret bytes to
	// two live owners. Setting inUse=0 twice was harmless under the original
	// linear scan; pushing twice is not, and on the intrusive list it is worse
	// still: slots[i].next would point at i, and every future Acquire would hand
	// out that one slot forever. This re-check is the only thing preventing it.
	s.arena.alloc.Lock()
	if s.arena.slots[s.idx].inUse == 1 && s.arena.slots[s.idx].generation == s.generation {
		s.arena.slots[s.idx].inUse = 0
		s.arena.live--
		s.arena.slots[s.idx].next = s.arena.freeHead
		s.arena.freeHead = s.idx
	}
	s.arena.alloc.Unlock()

	if violated {
		return fmt.Errorf("secmem.ArenaSlot.Release: %w", ErrCanaryViolation)
	}
	return nil
}

// Index returns the slot's zero-based index within the arena.
func (s *ArenaSlot) Index() int {
	if s == nil {
		return -1
	}
	return int(s.idx)
}

// IsLive reports whether the slot is currently acquired (not yet released).
func (s *ArenaSlot) IsLive() bool {
	if s == nil {
		return false
	}
	s.arena.alloc.Lock()
	live := s.arena.slots[s.idx].inUse == 1
	s.arena.alloc.Unlock()
	return live
}
