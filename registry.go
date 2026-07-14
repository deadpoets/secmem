package secmem

import (
	"errors"
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
}

// janitor tracks live secret mappings and wipes them on process termination via
// SIGTERM/SIGINT/SIGQUIT.
type janitor struct {
	mu      sync.Mutex
	regions map[uintptr]janitorRegion
}

// emergencyJanitor is the package-level crash registry.
// Populated by init() so that the package-var initialization cycle is avoided.
var emergencyJanitor *janitor //nolint:gochecknoglobals // Crash-safety registry — must outlive all registered secrets.

func init() { //nolint:gochecknoinits // Emergency janitor must be initialized before any secrets are created.
	emergencyJanitor = &janitor{
		regions: make(map[uintptr]janitorRegion),
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
func (j *janitor) register(region secRegion, canaryZones [][2]int, mu *bufferRWLock, sealCipher *atomic.Bool) uintptr {
	key := regionKey(region)
	j.mu.Lock()
	j.regions[key] = janitorRegion{region: region, mu: mu, canaryZones: canaryZones, sealCipher: sealCipher}
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
		slog.Error("secmem: janitor mprotect failed — continuing cleanup",
			slog.Any("error", err),
		)
	}

	// Ciphertext (Windows sealed state) cannot be canary-verified — skip the
	// check, never the wipe. The explicit Destroy path decrypts first, so
	// this branch is only reached by the signal and GC-cleanup paths.
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

	if !unmap {
		// Signal-shutdown path: secret is wiped; leave the region mapped so a
		// late access reads zeros rather than faulting on freed memory.
		return canaryErr
	}

	madviseBeforeFree(region.region)
	return errors.Join(canaryErr, freeSecretMem(region.region))
}

// release wipes and frees the region for key exactly once. Safe to race with
// Destroy and AddCleanup: the first taker wins, others observe "already gone".
func (j *janitor) release(key uintptr, lockHeld bool) error {
	region, ok := j.take(key)
	if !ok {
		return nil
	}
	return wipeAndFree(region, lockHeld, true)
}

// wipeInPlace wipes the region for key exactly once WITHOUT unmapping it (via
// take, so it never races Destroy into a double-free). Used by WipeAllSecrets:
// the process is expected to be terminating, so the mapping is reclaimed on
// exit; unmapping here would risk a use-after-munmap fault against a goroutine
// still holding the buffer (see wipeAndFree).
func (j *janitor) wipeInPlace(key uintptr) error {
	region, ok := j.take(key)
	if !ok {
		return nil
	}
	return wipeAndFree(region, false, false)
}

// wipeAllInPlace wipes every currently-registered secret in place, exactly once
// each, and returns any canary/wipe errors joined.
func (j *janitor) wipeAllInPlace() error {
	j.mu.Lock()
	keys := make([]uintptr, 0, len(j.regions))
	for key := range j.regions {
		keys = append(keys, key)
	}
	j.mu.Unlock()

	var errs error
	for _, key := range keys {
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
//     fault.
//   - After this call every affected buffer is dead — its secret is gone. If
//     the process keeps running, the wiped mappings linger until exit rather
//     than being freed; this is a one-way emergency wipe, not a reusable clear.
//   - Safe to call concurrently with Destroy and from multiple goroutines; each
//     region is wiped exactly once.
//
// secmem installs NO signal handler on its own. For automatic wiping on
// termination signals, call [InstallTerminationWipe] once at startup, or wire
// WipeAllSecrets into your own handler as above.
func WipeAllSecrets() error {
	return emergencyJanitor.wipeAllInPlace()
}
