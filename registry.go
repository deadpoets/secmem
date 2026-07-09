package secmem

import (
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"unsafe"
)

// janitorRegion is one live secret-mapping record.
//
// It intentionally stores only raw mapping metadata and the RW lock shared by
// access callbacks. It does NOT store *SecureBuffer or *SecureArena pointers,
// so GC can still collect wrapper objects and run AddCleanup fallback.
type janitorRegion struct {
	raw []byte
	mu  *bufferRWLock
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
	emergencyJanitor.install()
}

// regionKey returns a stable per-mapping key. raw must be a non-empty mapping
// from allocSecretMem/allocMapAnon.
func regionKey(raw []byte) uintptr {
	return uintptr(unsafe.Pointer(&raw[0]))
}

// register records one live secret mapping and returns its janitor key.
func (j *janitor) register(raw []byte, mu *bufferRWLock) uintptr {
	key := regionKey(raw)
	j.mu.Lock()
	j.regions[key] = janitorRegion{raw: raw, mu: mu}
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

// wipeAndFree wipes and releases one raw mapping. When lockHeld is false, it
// first acquires the region's exclusive lock to block in-flight callbacks.
func wipeAndFree(region janitorRegion, lockHeld bool) error {
	if !lockHeld {
		region.mu.lock()
		defer region.mu.unlock()
	}

	if err := mprotectSecretMem(region.raw, 3 /*PROT_READ|PROT_WRITE*/); err != nil {
		slog.Error("security: janitor mprotect failed — continuing cleanup",
			slog.Any("error", err),
		)
	}
	secureWipeSlice(region.raw)
	madviseBeforeFree(region.raw)
	return freeSecretMem(region.raw)
}

// release wipes and frees the region for key exactly once. Safe to race with
// Destroy and AddCleanup: the first taker wins, others observe "already gone".
func (j *janitor) release(key uintptr, lockHeld bool) error {
	region, ok := j.take(key)
	if !ok {
		return nil
	}
	return wipeAndFree(region, lockHeld)
}

// wipeAll wipes all remaining regions. Called on termination signals.
func (j *janitor) wipeAll() {
	j.mu.Lock()
	regions := make([]janitorRegion, 0, len(j.regions))
	for key, region := range j.regions {
		regions = append(regions, region)
		delete(j.regions, key)
	}
	j.mu.Unlock()

	for _, region := range regions {
		if err := wipeAndFree(region, false); err != nil {
			slog.Error("security: emergencyJanitor wipe failed during signal shutdown",
				slog.Any("error", err),
			)
		}
	}
}

// install registers a signal handler that wipes all secrets on SIGTERM/SIGINT/SIGQUIT.
// After wiping, the signal is re-raised with default handling so the process exits
// with the expected status code.
//
// Signal handling during wipe: signals are ignored for the duration of wipeAll()
// so that a second termination signal arriving while the wipe is in progress does
// not kill the process before the wipe completes (INF-2 fix).
func (j *janitor) install() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)

	go func() {
		sig, ok := <-ch
		if !ok {
			return
		}

		// Block further termination signals while wipeAll runs so a second
		// signal does not kill the process before the wipe completes.
		signal.Ignore(syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)

		// Wipe all live secrets before the process dies.
		j.wipeAll()

		// Re-raise the signal with default handling so exit code and core dump
		// behavior matches what the caller would expect.
		signal.Reset(syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
		proc, err := os.FindProcess(os.Getpid())
		if err == nil {
			_ = proc.Signal(sig)
		}
	}()
}
