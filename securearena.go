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
)

// slotMeta holds per-slot metadata.
//
// Pointer-free: contains only uint32 and padding bytes.
// The GC treats a []slotMeta backing array as a leaf — no per-slot GC
// scanning occurs regardless of how many slots the arena contains.
//
// Padded to 64 bytes to align each slot metadata to a CPU cache line, avoiding
// false-sharing between concurrent slot operations.
type slotMeta struct {
	// inUse is uint32 (not bool) to allow future lock-free upgrade to atomic.Uint32;
	// 1 = live (acquired), 0 = free; accessed under arena.alloc.
	inUse      uint32
	generation uint32   // incremented on every Acquire — ABA guard (CQ-P0-ABA fix)
	_          [56]byte // pad to exactly 64 bytes (one cache line)
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

	// slots is the metadata index.  Pointer-free leaf — GC scans the slice
	// header but NOT the backing array.  len(slots) == count.
	slots []slotMeta

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
	arena      *SecureArena
	idx        int
	generation uint32 // matches slots[idx].generation at Acquire time — ABA guard
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
// slotSize and count must both be > 0.
//
// Common errors: EPERM / ENOMEM from mlock (RLIMIT_MEMLOCK exceeded). On
// platforms with no lockable off-heap memory the error is [ErrNoSecureMemory]
// unless [WithInsecureFallback] is passed.
func NewArena(slotSize, count int, opts ...Option) (*SecureArena, error) {
	if slotSize <= 0 {
		return nil, fmt.Errorf("secmem.NewArena: slotSize must be > 0, got %d", slotSize)
	}
	if count <= 0 {
		return nil, fmt.Errorf("secmem.NewArena: count must be > 0, got %d", count)
	}
	stride := slotSize + canaryLen
	if slotSize > math.MaxInt/count-canaryLen {
		return nil, fmt.Errorf("secmem.NewArena: (slotSize+canary)*count overflows int (slotSize=%d, count=%d)", slotSize, count)
	}
	if err := gateInsecure(platformHasSecureMemory, applyOptions(opts)); err != nil {
		return nil, fmt.Errorf("secmem.NewArena: %w", err)
	}

	totalBytes := stride * count
	region, _, info, err := allocSecretMem(totalBytes)
	if err != nil {
		return nil, fmt.Errorf("secmem.NewArena: %w", err)
	}

	// Arm the canary strips (one after each slot) and the page-rounding tail.
	// These are also the janitor's verification zones, checked before the
	// slab is wiped on Destroy or signal shutdown.
	zones := make([][2]int, 0, count+1)
	for i := 0; i < count; i++ {
		zones = append(zones, [2]int{i*stride + slotSize, (i + 1) * stride})
	}
	if count*stride < len(region.inner) {
		zones = append(zones, [2]int{count * stride, len(region.inner)})
	}
	for _, z := range zones {
		if err := fillCanary(region.inner[z[0]:z[1]]); err != nil {
			_ = freeSecretMem(region) // nothing secret written yet
			return nil, fmt.Errorf("secmem.NewArena: %w", err)
		}
	}

	a := &SecureArena{
		mu:       newBufferRWLock(),
		region:   region,
		slots:    make([]slotMeta, count),
		slotSize: slotSize,
		stride:   stride,
		count:    count,
		backing:  info,
	}

	// Register the slab with emergency janitor using raw metadata only.
	// Arenas have no Seal, hence no seal-cipher state.
	a.janitorKey = emergencyJanitor.register(region, zones, a.mu, nil)

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
// Destroy is idempotent and goroutine-safe.
func (a *SecureArena) Destroy() error {
	if a == nil {
		return nil
	}

	// Mark destroyed so new Acquire calls fail fast without acquiring mu.
	a.alloc.Lock()
	if a.destroyed {
		a.alloc.Unlock()
		return nil // already destroyed — idempotent
	}
	a.destroyed = true
	a.alloc.Unlock()

	// Acquire exclusive lock — waits for all in-flight WithBytes callbacks.
	a.mu.lock()
	defer a.mu.unlock()

	if a.region.inner == nil {
		return nil // idempotent double-check under exclusive lock
	}

	a.cleanup.Stop()

	// Take exclusive ownership from janitor registry and wipe/free exactly once.
	// If cleanup/signal already released the slab, do not touch raw again.
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

	for i := range a.slots {
		if a.slots[i].inUse == 0 {
			a.slots[i].inUse = 1
			a.slots[i].generation++
			return &ArenaSlot{arena: a, idx: i, generation: a.slots[i].generation}, nil
		}
	}
	return nil, ErrArenaFull
}

// LiveCount returns the number of currently acquired (live) slots.
func (a *SecureArena) LiveCount() int {
	if a == nil {
		return 0
	}
	a.alloc.Lock()
	defer a.alloc.Unlock()
	n := 0
	for i := range a.slots {
		if a.slots[i].inUse == 1 {
			n++
		}
	}
	return n
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
// Call ReadWrite before Destroy or before any slot Write.
//
// The exclusive lock is held to drain all in-flight WithBytes callbacks
// before the mprotect, preventing a SIGSEGV from a concurrent write hitting
// a PROT_READ page (SB-3 / arena equivalent fix).
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
	start := s.idx * s.arena.stride
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
		start := s.idx * s.arena.stride
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
	s.arena.alloc.Lock()
	s.arena.slots[s.idx].inUse = 0
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
	return s.idx
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
