// securebuf.go implements SecureBuffer, the hardened off-heap memory type.
//
// # Architecture layering
//
//	Layer 2 — off-heap  : mmap(MAP_ANON|MAP_PRIVATE)  — all platforms
//	Layer 3 — swap-proof: mlock / VirtualLock          — all platforms
//	Layer 4 — kernel-isolated (Linux 5.14+): memfd_secret (via allocSecretMem)
//
// # Critical invariants
//
//   - raw is IMMUTABLE after construction: it holds the exact slice returned
//     by allocSecretMem/allocMapAnon.
//     Truncate MUST NOT modify raw.
//
//   - mu.rLock is held by ALL access methods for the duration of the operation.
//     mu.lock is held ONLY by Destroy.  This prevents TOCTOU races between
//     Destroy (Munmap) and in-flight access callbacks.
//
//   - The lock is a sync.Cond-based reader-writer lock (not sync.RWMutex) so
//     that all blocking states are durably blocked under testing/synctest.
//
//   - cleanup.Stop() is called before the wipe in Destroy to prevent double-free.
//     runtime.KeepAlive(s) is called at the end of Destroy to keep the GC from
//     running the cleanup between Stop() and the actual wipe.

package secmem

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"
)

// SecureBuffer holds sensitive data in a page-aligned, mlock'd, off-heap memory
// region. The region is allocated via mmap(MAP_ANON|MAP_PRIVATE) (or higher-
// privilege equivalents on supported platforms) and is invisible to the Go GC.
//
// Callers MUST call [SecureBuffer.Destroy] explicitly. The AddCleanup fallback
// is a safety net only — it runs non-deterministically at GC time.
//
// WARNING: Never retain a reference from [SecureBuffer.WithBytes]
// beyond the buffer's lifetime.  After Destroy,
// the backing memory is unmapped; any retained slice becomes a dangling pointer.
type SecureBuffer struct {
	// data is the usable portion, raw[:requestedSize]. Access is controlled
	// via methods — never exported directly to prevent heap copies.
	data []byte

	// raw is the full page-rounded mmap region as returned by allocSecretMem.
	// ALL syscalls (mprotect, madvise, munlock, munmap) MUST use raw, never data.
	// Invariant: &raw[0] == &data[0], len(raw) >= len(data), raw is IMMUTABLE.
	raw []byte

	// mu: rLock=access methods, lock=Destroy. Prevents Munmap racing a callback.
	// Uses a sync.Cond-based RWLock (not sync.RWMutex) so that all blocking
	// states are durably blocked under testing/synctest.
	mu *bufferRWLock

	// cleanup is the handle returned by runtime.AddCleanup, used to Stop (cancel)
	// the cleanup when Destroy is called explicitly — prevents double-free.
	cleanup runtime.Cleanup

	// janitorKey identifies this buffer's raw mapping in emergencyJanitor.
	janitorKey uintptr

	// sealed is true when the buffer's mmap region has been set to PROT_NONE.
	// All access methods return ErrSealed while sealed is true.
	// Protected by mu (same lock used for all state changes).
	sealed bool

	// backing records which protections this allocation actually received.
	// Immutable after construction; read by Capabilities without the lock.
	backing allocInfo
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

// NewBuffer allocates a hardened memory region and copies raw into it.
//
// The backing allocation is page-rounded (typically 4096 bytes), mlock'd,
// and invisible to the Go GC.  raw is zeroed after the copy (defense-in-depth).
//
// WARNING: raw is zeroed after copying. The caller must not reuse raw after
// this call. If the same secret must be used multiple times, copy it first.
//
// Common errors: EPERM / ENOMEM from mlock (RLIMIT_MEMLOCK exceeded — check
// `ulimit -l` or systemd LimitMEMLOCK=).
func NewBuffer(raw []byte) (*SecureBuffer, error) {
	if len(raw) == 0 {
		return nil, errors.New("secmem.NewBuffer: empty input")
	}
	allocRaw, data, info, err := allocSecretMem(len(raw))
	if err != nil {
		return nil, fmt.Errorf("secmem.NewBuffer: %w", err)
	}
	copy(data, raw)
	secureWipeSlice(raw) // zero the caller's copy defense-in-depth
	return newSecureBuffer(allocRaw, data, info), nil
}

// NewEmptyBuffer allocates an mlock'd zero-filled region of exactly size bytes.
// Equivalent to NewBuffer(make([]byte, size)) without the intermediate heap copy.
func NewEmptyBuffer(size int) (*SecureBuffer, error) {
	if size <= 0 {
		return nil, fmt.Errorf("secmem.NewEmptyBuffer: invalid size %d", size)
	}
	allocRaw, data, info, err := allocSecretMem(size)
	if err != nil {
		return nil, fmt.Errorf("secmem.NewEmptyBuffer: %w", err)
	}
	return newSecureBuffer(allocRaw, data, info), nil
}

// NewSyscallSafeBuffer allocates via MAP_ANON only (no memfd_secret attempt).
// Use this for ingestion paths where syscall arguments are read directly into
// the buffer — memfd_secret's extra isolation is not needed because the data
// arrives from a kernel-controlled channel.
func NewSyscallSafeBuffer(raw []byte) (*SecureBuffer, error) {
	if len(raw) == 0 {
		return nil, errors.New("secmem.NewSyscallSafeBuffer: empty input")
	}
	allocRaw, data, info, err := allocMapAnon(len(raw))
	if err != nil {
		return nil, fmt.Errorf("secmem.NewSyscallSafeBuffer: %w", err)
	}
	copy(data, raw)
	secureWipeSlice(raw)
	return newSecureBuffer(allocRaw, data, info), nil
}

// newSecureBuffer wires up a SecureBuffer from a pre-allocated (raw, data)
// pair plus its allocation facts, and registers the AddCleanup finalization
// fallback.
//
// The janitor key is passed to AddCleanup by value; cleanup resolution happens
// through emergencyJanitor's raw-mapping registry.
func newSecureBuffer(allocRaw, data []byte, backing allocInfo) *SecureBuffer {
	sb := &SecureBuffer{
		data:    data,
		raw:     allocRaw,
		mu:      newBufferRWLock(),
		backing: backing,
	}

	// Register with the emergency janitor first. The janitor stores raw mapping
	// metadata (not *SecureBuffer), so this does not keep sb reachable for GC.
	sb.janitorKey = emergencyJanitor.register(allocRaw, sb.mu)

	// Safety-net cleanup: if the caller forgets Destroy(), this wipes and frees
	// the mmap'd region when the *SecureBuffer is GC'd.
	//
	// runtime.AddCleanup callbacks MUST NOT reference sb directly (that would
	// keep sb alive and prevent the cleanup from running).  The raw slice is
	// passed as the argument, capturing only the off-heap mapping metadata.
	//
	// IMPORTANT: The cleanup fires when sb becomes unreachable — NOT when all
	// references to data are gone.  Any retained []byte from WithBytes
	// becomes a dangling pointer after the cleanup runs.
	sb.cleanup = runtime.AddCleanup(sb, func(key uintptr) {
		slog.Warn("secmem: SecureBuffer finalized without explicit Destroy()",
			slog.Int("size", len(allocRaw)),
			slog.String("advice", "call Destroy() explicitly for deterministic wipe"),
		)
		if err := emergencyJanitor.release(key, false); err != nil {
			slog.Error("secmem: SecureBuffer cleanup release failed",
				slog.Any("error", err),
			)
		}
	}, sb.janitorKey)

	return sb
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// Destroy performs an architectural wipe of the entire mapped region:
//
//  1. Stop the AddCleanup fallback (prevents double-free).
//  2. Mprotect(RW) — ensure the page is writable before wiping.
//  3. secureWipeSlice — zero + CLFLUSH/CLFLUSHOPT + SFENCE/LFENCE.
//  4. Madvise(DONTNEED) — release physical frames immediately.
//  5. freeSecretMem — Munlock + Munmap / VirtualUnlock + VirtualFree.
//  6. Nil out data and raw — makes Destroy idempotent.
//  7. runtime.KeepAlive(s) — ensures the GC does not run the cleanup
//     concurrently between Stop() and the wipe.
//
// Destroy is idempotent and goroutine-safe.  After Destroy, IsDestroyed()
// returns true and all subsequent method calls return ErrDestroyed.
func (s *SecureBuffer) Destroy() error {
	if s == nil {
		return nil
	}

	s.mu.lock()
	defer s.mu.unlock()

	if s.raw == nil {
		return nil // already destroyed — idempotent
	}

	// Stop the safety-net cleanup first.  If Destroy was called explicitly
	// (the expected path), the cleanup is no longer needed.  Stop() is a no-op
	// if the cleanup has already fired.
	s.cleanup.Stop()

	// Take exclusive ownership from janitor registry and wipe/free exactly once.
	// If the entry is already gone (cleanup/signal path won the race), treat as
	// successfully destroyed and skip touching raw to avoid use-after-free.
	err := emergencyJanitor.release(s.janitorKey, true)

	// Step 5 — nil references.  Makes IsDestroyed() true and Destroy idempotent.
	s.data = nil
	s.raw = nil

	// Step 6 — ensure the GC does not run the cleanup concurrently between
	// Stop() and here.  KeepAlive pins s in the liveness analysis until this
	// point, preventing the finalizer goroutine from scheduling the already-
	// Stopped cleanup during the wipe window.
	runtime.KeepAlive(s)

	if err != nil {
		return fmt.Errorf("secmem.SecureBuffer.Destroy: %w", err)
	}
	return nil
}

// IsDestroyed reports whether the buffer has been destroyed.
func (s *SecureBuffer) IsDestroyed() bool {
	if s == nil {
		return true
	}
	s.mu.rLock()
	defer s.mu.rUnlock()
	return s.raw == nil
}

// ---------------------------------------------------------------------------
// Size & mprotect
// ---------------------------------------------------------------------------

// Len returns the usable size of the buffer (the size requested by the caller).
// May be smaller than [MappedLen] due to page-rounding.
func (s *SecureBuffer) Len() int {
	if s == nil {
		return 0
	}
	s.mu.rLock()
	defer s.mu.rUnlock()
	return len(s.data)
}

// MappedLen returns the actual size of the underlying mmap'd region.
// Always a multiple of the OS page size (≥ Len).
func (s *SecureBuffer) MappedLen() int {
	if s == nil {
		return 0
	}
	s.mu.rLock()
	defer s.mu.rUnlock()
	return len(s.raw)
}

// ReadOnly sets the buffer's memory protection to read-only.
// This prevents accidental overwrites once a secret is fully loaded.
// Call [ReadWrite] before [Destroy] to restore write access.
//
// The exclusive lock is held to drain all in-flight Write/SetByteAt calls
// before the mprotect, preventing a SIGSEGV from a concurrent write hitting a
// PROT_READ page.
//
// NOTE: Operates on the full page-rounded region; sub-page protection
// is not possible on any supported OS.
func (s *SecureBuffer) ReadOnly() error {
	if s == nil {
		return errors.New("secmem.SecureBuffer.ReadOnly: nil receiver")
	}
	s.mu.lock()
	defer s.mu.unlock()
	if s.raw == nil {
		return fmt.Errorf("secmem.SecureBuffer.ReadOnly: %w", ErrDestroyed)
	}
	if s.sealed {
		return fmt.Errorf("secmem.SecureBuffer.ReadOnly: %w", ErrSealed)
	}
	if err := mprotectSecretMem(s.raw, 1 /*PROT_READ*/); err != nil {
		return fmt.Errorf("secmem.SecureBuffer.ReadOnly: %w", err)
	}
	return nil
}

// ReadWrite restores read-write access to the buffer.
// Must be called before [Destroy] if [ReadOnly] was previously applied.
//
// The exclusive lock is held to drain all in-flight access before the
// mprotect.
func (s *SecureBuffer) ReadWrite() error {
	if s == nil {
		return errors.New("secmem.SecureBuffer.ReadWrite: nil receiver")
	}
	s.mu.lock()
	defer s.mu.unlock()
	if s.raw == nil {
		return fmt.Errorf("secmem.SecureBuffer.ReadWrite: %w", ErrDestroyed)
	}
	if s.sealed {
		return fmt.Errorf("secmem.SecureBuffer.ReadWrite: %w", ErrSealed)
	}
	if err := mprotectSecretMem(s.raw, 3 /*PROT_READ|PROT_WRITE*/); err != nil {
		return fmt.Errorf("secmem.SecureBuffer.ReadWrite: %w", err)
	}
	return nil
}

// Seal sets the buffer's memory protection to PROT_NONE, making any access
// (including speculative reads) cause a hardware fault. This is the hardened
// dormant state for long-lived secrets that are not actively being used.
//
// While sealed, all access methods (WithBytes, WithBytesErr, Read, Write, etc.)
// return [ErrSealed]. Call [SecureBuffer.Unseal] before accessing the buffer.
//
// [SecureBuffer.Destroy] works correctly on sealed buffers — it lifts the
// PROT_NONE restriction internally before wiping.
//
// Note: [ReadOnly] and [ReadWrite] return [ErrSealed] while sealed. To
// transition from Sealed to ReadOnly, call Unseal then ReadOnly.
//
// Seal is idempotent: calling it on an already-sealed buffer is a no-op.
func (s *SecureBuffer) Seal() error {
	if s == nil {
		return errors.New("secmem.SecureBuffer.Seal: nil receiver")
	}
	s.mu.lock()
	defer s.mu.unlock()
	if s.raw == nil {
		return fmt.Errorf("secmem.SecureBuffer.Seal: %w", ErrDestroyed)
	}
	if s.sealed {
		return nil // idempotent
	}
	if err := mprotectSecretMem(s.raw, 0 /*PROT_NONE*/); err != nil {
		return fmt.Errorf("secmem.SecureBuffer.Seal: %w", err)
	}
	s.sealed = true
	return nil
}

// Unseal lifts the PROT_NONE protection applied by [SecureBuffer.Seal],
// restoring PROT_READ|PROT_WRITE access to the buffer.
//
// After Unseal, all access methods work normally. To re-protect after use,
// call Seal again.
//
// Unseal is idempotent: calling it on an already-unsealed buffer is a no-op.
func (s *SecureBuffer) Unseal() error {
	if s == nil {
		return errors.New("secmem.SecureBuffer.Unseal: nil receiver")
	}
	s.mu.lock()
	defer s.mu.unlock()
	if s.raw == nil {
		return fmt.Errorf("secmem.SecureBuffer.Unseal: %w", ErrDestroyed)
	}
	if !s.sealed {
		return nil // idempotent
	}
	if err := mprotectSecretMem(s.raw, 3 /*PROT_READ|PROT_WRITE*/); err != nil {
		return fmt.Errorf("secmem.SecureBuffer.Unseal: %w", err)
	}
	s.sealed = false
	return nil
}

// IsSealed reports whether the buffer is currently in the sealed (PROT_NONE) state.
func (s *SecureBuffer) IsSealed() bool {
	if s == nil {
		return false
	}
	s.mu.rLock()
	defer s.mu.rUnlock()
	return s.sealed
}

// Truncate re-slices data to n bytes and wipes the freed tail [n:].
//
// Invariant: raw is NEVER modified. Only data is re-sliced.
// This ensures the AddCleanup finalization closure always holds the correct
// full-page allocation regardless of Truncate calls.
func (s *SecureBuffer) Truncate(n int) error {
	if s == nil {
		return errors.New("secmem.SecureBuffer.Truncate: nil receiver")
	}
	s.mu.lock()
	defer s.mu.unlock()
	if s.raw == nil {
		return fmt.Errorf("secmem.SecureBuffer.Truncate: %w", ErrDestroyed)
	}
	if n < 0 || n > len(s.data) {
		return fmt.Errorf("secmem.SecureBuffer.Truncate: n=%d out of range [0, %d]", n, len(s.data))
	}
	tail := s.data[n:]
	if len(tail) > 0 {
		secureWipeSlice(tail)
	}
	s.data = s.data[:n]
	return nil
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------
