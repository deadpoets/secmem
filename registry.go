package secmem

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"unsafe"
)

// janitorRegion is one live secret-mapping record.
//
// It intentionally stores only raw mapping metadata and the RW lock shared by
// access callbacks. It does NOT store *SecureBuffer or *SecureArena pointers,
// so GC can still collect wrapper objects and run AddCleanup fallback.
type janitorRegion struct {
	region secRegion
	mu     *bufferRWLock

	// canaryZones are [start,end) offsets into region.inner that were filled
	// with the canary pattern at allocation time (a buffer's tail slack; an
	// arena's inter-slot strips and tail). wipeAndFree verifies them — after
	// restoring RW protection, before the wipe destroys the evidence — and
	// reports ErrCanaryViolation without ever skipping the teardown.
	canaryZones [][2]int

	// sealCipher, when non-nil and true, records that the region's contents
	// are currently CryptProtectMemory ciphertext (Windows sealed state).
	// Ciphertext would read as a canary violation, so wipeAndFree skips the
	// canary check while set — the wipe itself proceeds unconditionally.
	// Shared with the owning SecureBuffer; nil for arenas (no Seal).
	sealCipher *atomic.Bool

	// wiped is set by the emergency path when the region has been wiped in
	// place and left mapped. It is shared with the owning SecureBuffer or
	// SecureArena, which is the whole point: the janitor deliberately holds no
	// owner pointer, so this flag is the only channel by which the owner can
	// learn its secret is gone and refuse to be reused. Reads still succeed
	// (they return the zeros), which keeps the documented "a late access reads
	// zeros rather than faulting" guarantee; every mutation returns ErrWiped.
	wiped *atomic.Bool
}

// janitor tracks live secret mappings so they can be wiped in place: on
// Destroy/Release, on GC cleanup, or all at once via WipeAllSecrets (which an
// opt-in InstallTerminationWipe handler — or the application's own signal
// handler — calls on termination). It installs no signal handler itself.
type janitor struct {
	mu      sync.Mutex
	regions map[uintptr]janitorRegion

	// wiped holds regions that WipeAllSecrets wiped IN PLACE and deliberately
	// left mapped (see wipeAndFree's unmap=false path). Their contents are
	// already zero; the entry exists only so a later explicit Destroy — or the
	// GC cleanup once the wrapper is unreachable — can reclaim the address
	// space instead of leaking the mapping until process exit. Entries are
	// stored with canaryZones and sealCipher cleared: the wipe already
	// destroyed the canary pattern, so re-verifying it would report a spurious
	// ErrCanaryViolation.
	wiped map[uintptr]janitorRegion
}

// emergencyJanitor is the package-level crash registry.
// Populated by init() so that the package-var initialization cycle is avoided.
var emergencyJanitor *janitor //nolint:gochecknoglobals // Crash-safety registry — must outlive all registered secrets.

func init() { //nolint:gochecknoinits // Emergency janitor must be initialized before any secrets are created.
	emergencyJanitor = &janitor{
		regions: make(map[uintptr]janitorRegion),
		wiped:   make(map[uintptr]janitorRegion),
	}
	// No signal handler is installed here: touching process-global signal state
	// as a side effect of import is the application's decision, not the
	// library's. Opt in with InstallTerminationWipe, or call WipeAllSecrets from
	// your own handler. Only the per-object runtime.AddCleanup fallback and this
	// registry are wired up by default.
}

// regionKey returns a stable per-mapping key: the base address of the outer
// reservation, which is unique for the mapping's whole lifetime.
func regionKey(region secRegion) uintptr {
	//nolint:gosec // G103: deriving a stable identity key from the mapping base; no dereference.
	return uintptr(unsafe.Pointer(&region.outer[0]))
}

// register records one live secret mapping and returns its janitor key.
// canaryZones may be nil when the allocation has no armed slack; sealCipher
// may be nil when the owner has no seal-cipher state (arenas).
func (j *janitor) register(region secRegion, canaryZones [][2]int, mu *bufferRWLock, sealCipher, wiped *atomic.Bool) uintptr {
	key := regionKey(region)
	j.mu.Lock()
	j.regions[key] = janitorRegion{
		region:      region,
		mu:          mu,
		canaryZones: canaryZones,
		sealCipher:  sealCipher,
		wiped:       wiped,
	}
	j.mu.Unlock()
	return key
}

// take removes and returns one region. The bool is false when already removed.
func (j *janitor) take(key uintptr) (janitorRegion, bool) {
	j.mu.Lock()
	region, ok := j.regions[key]
	if ok {
		delete(j.regions, key)
	}
	j.mu.Unlock()
	return region, ok
}

// peekAny returns one region WITHOUT removing it, so a caller can inspect its
// lock before committing to take it. Both sets are searched: a region the
// emergency path already wiped in place is still MAPPED and its owner is still
// usable, so it can hold a secret written since — a later wipe must not skip
// it just because the first one moved it.
func (j *janitor) peekAny(key uintptr) (janitorRegion, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if region, ok := j.regions[key]; ok {
		return region, true
	}
	region, ok := j.wiped[key]
	return region, ok
}

// takeAny removes and returns one region from whichever set holds it — the
// take counterpart of peekAny.
func (j *janitor) takeAny(key uintptr) (janitorRegion, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if region, ok := j.regions[key]; ok {
		delete(j.regions, key)
		return region, true
	}
	if region, ok := j.wiped[key]; ok {
		delete(j.wiped, key)
		return region, true
	}
	return janitorRegion{}, false
}

// retainWiped records a region that was wiped in place and left mapped, so a
// later release can still reclaim the address space. The canary zones and the
// seal-cipher flag are cleared: the wipe destroyed the canary pattern, and
// re-verifying zeroed slack would report a violation that never happened.
func (j *janitor) retainWiped(key uintptr, region janitorRegion) {
	region.canaryZones = nil
	region.sealCipher = nil
	j.mu.Lock()
	j.wiped[key] = region
	j.mu.Unlock()
}

// takeWiped removes and returns one wiped-but-still-mapped region.
func (j *janitor) takeWiped(key uintptr) (janitorRegion, bool) {
	j.mu.Lock()
	region, ok := j.wiped[key]
	if ok {
		delete(j.wiped, key)
	}
	j.mu.Unlock()
	return region, ok
}

// wipeAndFree wipes one mapping and, when unmap is true, releases it. When
// lockHeld is false, it first acquires the region's exclusive lock to block
// in-flight callbacks.
//
// Order is deliberate and load-bearing:
//  1. mprotect RW — a sealed/read-only region must be writable to wipe, and
//     readable to verify canaries.
//  2. verify canary zones — BEFORE the wipe destroys the evidence.
//  3. wipe — unconditionally: a canary violation reports a bug, it never
//     leaves secret memory mapped.
//  4. madvise + unmap — only when unmap is true.
//
// unmap is false ONLY on the emergency-wipe path (see WipeAllSecrets): there the
// process is exiting imminently and the kernel reclaims every mapping on exit,
// so the region is wiped but left MAPPED. Unmapping it while application
// goroutines are still running in the shutdown window would turn any late
// access into a use-after-munmap SIGSEGV; a wiped-but-mapped region instead
// reads as zeros. The explicit Destroy path (wrapper nil'd under the lock) and
// the GC-cleanup path (wrapper unreachable) have no such live accessor and pass
// unmap=true to fully release.
//
// A canary violation and a free failure are both returned (joined).
func wipeAndFree(region janitorRegion, lockHeld, unmap bool) error {
	if !lockHeld {
		region.mu.lock()
		defer region.mu.unlock()
	}

	if err := mprotectSecretMem(region.region, 3 /*PROT_READ|PROT_WRITE*/); err != nil {
		// A sealed region is PROT_NONE and a read-only one is PROT_READ, so
		// without write access the canary read below and the wipe after it
		// both fault the process. "Continue cleanup" would mean continue into
		// a SIGSEGV — inside a signal handler, on the emergency path, aborting
		// the wipe of every region this pass had not reached yet. Give up on
		// the wipe instead and go straight to the release: an unwiped region
		// that is unmapped is bad, but a crash mid-emergency-wipe is worse.
		slog.Error("secmem: janitor could not restore write access — releasing WITHOUT wiping",
			slog.Any("error", err),
		)
		werr := fmt.Errorf("secmem: janitor: restoring write access failed, region released unwiped: %w", err)
		if !unmap {
			return werr
		}
		// MADV_DONTNEED needs no write access and, on a private anonymous
		// mapping, drops the frames outright — a partial wipe by other means
		// where the platform supports it.
		madviseBeforeFree(region.region)
		return errors.Join(werr, freeSecretMem(region.region))
	}

	// Ciphertext (Windows sealed state) cannot be canary-verified — skip the
	// check, never the wipe. The explicit Destroy path decrypts first, so
	// this branch is only reached by the emergency-wipe and GC-cleanup paths.
	var canaryErr error
	if region.sealCipher == nil || !region.sealCipher.Load() {
		for _, zone := range region.canaryZones {
			if !canaryIntact(region.region.inner[zone[0]:zone[1]]) {
				canaryErr = ErrCanaryViolation
				break
			}
		}
	}

	secureWipeSlice(region.region.inner)

	// The region holds zeros now, not ciphertext. The flag is shared with the
	// owning SecureBuffer, so leaving it set would let a later Unseal run
	// CryptUnprotectMemory over wiped memory and hand the caller the resulting
	// pseudorandom garbage as if it were the secret.
	if region.sealCipher != nil {
		region.sealCipher.Store(false)
	}

	if !unmap {
		// Emergency-wipe path: secret is wiped; leave the region mapped so a
		// late access reads zeros rather than faulting on freed memory.
		return canaryErr
	}

	madviseBeforeFree(region.region)
	return errors.Join(canaryErr, freeSecretMem(region.region))
}

// markWiped tells the owning SecureBuffer/SecureArena that its secret is gone,
// so every mutating entry point starts refusing with ErrWiped. Called only on
// the emergency path, and only with the region's exclusive lock held, so it
// cannot land while an accessor is mid-flight.
//
// The explicit Destroy and GC-cleanup paths do NOT call it: they unmap the
// region and nil the owner's own state, which already makes the object refuse
// with ErrDestroyed.
func markWiped(region janitorRegion) {
	if region.wiped != nil {
		region.wiped.Store(true)
	}
}

// release wipes and frees the region for key exactly once. Safe to race with
// Destroy and AddCleanup: the first taker wins, others observe "already gone".
//
// A region that WipeAllSecrets already wiped in place is still holding its
// mapping; release finds it in the wiped set and completes the unmap it
// deliberately deferred. That is safe here and not there: release runs under
// the region's exclusive lock (held by Destroy, or uncontended because the GC
// cleanup proved the wrapper unreachable), so no accessor can be in flight.
func (j *janitor) release(key uintptr, lockHeld bool) error {
	if region, ok := j.take(key); ok {
		return wipeAndFree(region, lockHeld, true)
	}
	region, ok := j.takeWiped(key)
	if !ok {
		return nil
	}
	return wipeAndFree(region, lockHeld, true)
}

// wipeInPlace wipes the region for key exactly once WITHOUT unmapping it (via
// take, so it never races Destroy into a double-free), then records it in the
// wiped set so a later release can reclaim the mapping. Used by WipeAllSecrets:
// unmapping there would risk a use-after-munmap fault against a goroutine still
// holding the buffer (see wipeAndFree).
//
// This blocks until the region's exclusive lock is free — i.e. until any
// in-flight borrowing callback returns. Callers that must not stall behind a
// slow borrow should try tryWipeInPlace first.
//
// The lock is taken BEFORE the region leaves the registry, and held across the
// retainWiped that puts it back. Taking it first would open a window in which
// the region is in neither map: a Destroy already queued on this same lock
// would then find nothing to free, report success, and never unmap — and the
// retainWiped landing afterwards would strand the mapping in the wiped set,
// where nothing collects it. Same ordering as tryWipeInPlace, same reason.
func (j *janitor) wipeInPlace(key uintptr) error {
	peeked, ok := j.peekAny(key)
	if !ok {
		return nil
	}
	peeked.mu.lock()
	defer peeked.mu.unlock()

	// Re-take under our own exclusive lock: Destroy or the GC cleanup may have
	// completed the whole teardown while we waited, in which case there is
	// nothing left to wipe.
	region, ok := j.takeAny(key)
	if !ok {
		return nil
	}
	err := wipeAndFree(region, true, false)
	markWiped(region)
	j.retainWiped(key, region)
	return err
}

// tryWipeInPlace is wipeInPlace without the wait. done is false only when the
// region is still registered but its lock is held — a borrowing callback is in
// flight — in which case nothing was wiped and the caller should retry with the
// blocking path. An already-released region reports done (there is nothing left
// to do), not a retry.
func (j *janitor) tryWipeInPlace(key uintptr) (done bool, err error) {
	peeked, ok := j.peekAny(key)
	if !ok {
		return true, nil // already released by another path
	}
	if !peeked.mu.tryLock() {
		return false, nil // borrow in flight — leave it for the blocking pass
	}
	defer peeked.mu.unlock()

	// Re-take under our own exclusive lock so the wipe still happens exactly
	// once even if Destroy or the GC cleanup won the race in between.
	region, ok := j.takeAny(key)
	if !ok {
		return true, nil
	}
	err = wipeAndFree(region, true, false)
	markWiped(region)
	j.retainWiped(key, region)
	return true, err
}

// wipeAllInPlace wipes every currently-registered secret in place, exactly once
// each, and returns any canary/wipe errors joined.
//
// Two passes, deliberately. The first wipes every region whose lock is free at
// that instant; the second blocks on whatever is left. A single goroutine parked
// inside a long WithBytes callback therefore delays only ITS OWN buffer — every
// other secret in the process is already zeroed by the time the first pass
// returns. A one-pass loop would let that one borrow hold the whole emergency
// wipe hostage in registry-map order.
//
// The already-wiped set is swept too. Those regions are still mapped and their
// owners are still usable, so anything written to one since the last wipe is a
// live secret; skipping them would let a second WipeAllSecrets report success
// over plaintext it never touched. Re-wiping a region that really is still
// zeroed costs one memclr and reports nothing (retainWiped cleared its canary
// zones, so there is no stale pattern to fail against).
func (j *janitor) wipeAllInPlace() error {
	j.mu.Lock()
	keys := make([]uintptr, 0, len(j.regions)+len(j.wiped))
	for key := range j.regions {
		keys = append(keys, key)
	}
	for key := range j.wiped {
		keys = append(keys, key)
	}
	j.mu.Unlock()

	var errs error
	deferred := make([]uintptr, 0, len(keys))
	for _, key := range keys {
		done, err := j.tryWipeInPlace(key)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		if !done {
			deferred = append(deferred, key)
		}
	}
	for _, key := range deferred {
		if err := j.wipeInPlace(key); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

// WipeAllSecrets immediately wipes the contents of every live [SecureBuffer] and
// [SecureArena] registered in this process, then returns. It is an emergency /
// pre-termination wipe you can call from your OWN shutdown or panic-recovery
// handler:
//
//	sig := make(chan os.Signal, 1)
//	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
//	go func() { <-sig; _ = secmem.WipeAllSecrets(); os.Exit(0) }()
//
// Semantics:
//
//   - Regions are wiped in place but NOT unmapped: the process is assumed to be
//     terminating and the kernel reclaims the mappings on exit. Unmapping while
//     another goroutine might still hold a buffer would risk a use-after-munmap
//     fault, so a read of an already-wiped buffer returns zeroed bytes, never a
//     fault. A later explicit [SecureBuffer.Destroy] (or the GC cleanup, once
//     the wrapper is unreachable) does complete the unmap — by then the caller
//     has stated it is done with the buffer, so the mapping is reclaimed rather
//     than held until exit.
//
//   - After this call every affected buffer is dead: its secret is gone and it
//     cannot be reused. Reads still succeed and return zeros — the region is
//     deliberately left mapped so a late access does not fault — but every
//     mutating method returns [ErrWiped] (which wraps [ErrDestroyed]), and
//     [SecureArena.Acquire] refuses. This is a one-way emergency wipe, not a
//     reusable clear.
//
//     One gap, stated rather than papered over: an [ArenaSlot] acquired BEFORE
//     the wipe still hands out a writable slice, because WithBytes returns one
//     slice for reading and writing and reads have to keep working. A later
//     WipeAllSecrets does catch anything written that way — the sweep covers
//     regions already wiped once, precisely for this case.
//
//   - Safe to call concurrently with Destroy and from multiple goroutines; each
//     region is wiped exactly once.
//
// # It can block
//
// Wiping a region takes that region's exclusive lock, so a buffer whose
// borrowing callback ([SecureBuffer.WithBytes] and friends) is still running
// cannot be wiped until the callback returns — and a callback that never
// returns blocks this call forever. The alternative would be zeroing memory a
// callback is actively reading, which is a data race and a likely crash.
//
// The cost is contained to the offending buffer, not the process: regions are
// wiped in two passes, so every buffer NOT currently borrowed is already zeroed
// by the time this call starts waiting on the ones that are. If your shutdown
// path must be bounded, run WipeAllSecrets in its own goroutine and exit on a
// timer — the first pass will have done its work regardless — and keep
// borrowing callbacks short, which the borrowing contract asks for anyway.
//
// secmem installs NO signal handler on its own. For automatic wiping on
// termination signals, call [InstallTerminationWipe] once at startup, or wire
// WipeAllSecrets into your own handler as above.
func WipeAllSecrets() error {
	return emergencyJanitor.wipeAllInPlace()
}
