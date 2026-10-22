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
//   - region is IMMUTABLE after construction: it holds the exact secRegion
//     returned by allocSecretMem/allocMapAnon (guarded outer reservation +
//     inner secret area). Truncate MUST NOT modify region.
//
//   - mu.rLock is held by every read-side access method (WithBytes, ByteAt,
//     CopyOut, ConstantTimeEqual, ...) for the duration of the operation.
//     mu.lock (exclusive) is held by Destroy and by every method that changes
//     the buffer's state or contents: CopyIn, SetByteAt, Truncate, ReadFrom,
//     Seal, Unseal, ReadOnly, ReadWrite — and by the janitor's wipe paths.
//     A borrowed slice therefore never observes a concurrent mutation,
//     protection change, or unmap: they wait for the callback to return.
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
	"sync"
	"sync/atomic"
)

// SecureBuffer holds sensitive data in a page-aligned, mlock'd, off-heap memory
// region. The region is an off-heap mapping (mmap, memfd_secret, or
// VirtualAlloc) and is invisible to the Go GC.
//
// Callers MUST call [SecureBuffer.Destroy] explicitly. The AddCleanup fallback
// is a safety net only — it runs non-deterministically at GC time.
//
// WARNING: Never retain a reference from [SecureBuffer.WithBytes]
// beyond the buffer's lifetime.  After Destroy, any retained slice is a
// dangling pointer. On Linux and Windows the destroyed range is kept for a
// while as a no-access reservation, so using such a slice faults; once the
// range leaves that quarantine (see [SetQuarantineLimits]), and everywhere
// else, it can point into whatever was allocated there next.
//
// # Copies are aliases
//
// Use a SecureBuffer through the pointer the constructors return. A copy of
// the value (c := *buf) or an assignment through the pointer (*a = *b) does
// not duplicate anything: like a copied [os.File], it is a second handle on
// the same region, the same lock and the same state. Sealing, truncating or
// destroying through one handle is seen by every other, and Destroy on any of
// them destroys the buffer for all. The secret is never copied this way, and a
// handle cannot be left pointing at memory that another handle unmapped.
//
// The zero value is a destroyed buffer: every method returns what it returns
// after Destroy.
type SecureBuffer struct {
	// Every field lives behind this one pointer, so that liveness cannot
	// differ between two copies of the struct. Nil in the zero value, which
	// is why the zero value reads as destroyed; never nil in a buffer a
	// constructor returned, and never reset (a destroyed buffer is one whose
	// state says so, visible to every copy).
	*bufferState
}

// bufferState is a SecureBuffer's state. One exists per allocation, shared by
// every copy of the SecureBuffer that refers to it, and it is what the
// AddCleanup fallback is attached to: the region is released when the last
// handle is gone, not when the first one is.
type bufferState struct {
	// data is the usable portion, region.inner[:size:size]. Access is
	// controlled via methods — never exported directly to prevent heap
	// copies. The capacity is clamped to the requested size so no re-slice
	// can reach the canary slack behind it.
	data []byte

	// region is the guarded allocation: inner (wipe/lock/protect target,
	// canary slack included) bracketed by PROT_NONE guard pages inside outer
	// (the unmap target). See secRegion for the field contract.
	// Invariant: &region.inner[0] == &data[0]; region is IMMUTABLE.
	region secRegion

	// mu: rLock=access methods, lock=Destroy. Prevents Munmap racing a callback.
	// Uses a sync.Cond-based RWLock (not sync.RWMutex) so that all blocking
	// states are durably blocked under testing/synctest.
	mu *bufferRWLock

	// cleanup is the handle returned by runtime.AddCleanup, used to Stop (cancel)
	// the cleanup when Destroy is called explicitly — prevents double-free.
	cleanup runtime.Cleanup

	// janitorKey identifies this buffer's raw mapping in emergencyJanitor.
	janitorKey uint64

	// sealed is true when the buffer's mmap region has been set to PROT_NONE,
	// or when Seal encrypted the contents and could then neither protect the
	// page nor decrypt them again — an unsealed buffer is never ciphertext.
	// All access methods return ErrSealed while sealed is true.
	// Protected by mu (same lock used for all state changes).
	sealed bool

	// readOnly is true when [SecureBuffer.ReadOnly] has set the region to
	// PROT_READ. The mutating methods (CopyIn, SetByteAt, Truncate, ReadFrom)
	// return ErrReadOnly while it is set — the API-boundary guard that turns a
	// would-be PROT_READ write fault into a clean error. It also lets Seal lift
	// and Unseal restore the protection so the physical page protection always
	// matches the flag across a seal cycle. Protected by mu.
	readOnly bool

	// sealCipher is true while the contents are seal-cipher ciphertext
	// (Windows: CryptProtectMemory under Seal). Atomic because it is read on
	// the janitor's wipe paths on another goroutine. Shared with janitorRegion.
	sealCipher *atomic.Bool

	// wiped is set by WipeAllSecrets when this buffer's region was wiped in
	// place and deliberately left mapped. Shared with janitorRegion, which is
	// how the emergency path reaches a buffer it holds no pointer to. Every
	// borrow, read and mutator refuses with ErrWiped, so a process that keeps
	// running after an emergency wipe can neither compute with the zeros as if
	// they were a key nor write a fresh secret into a region the wipe already
	// reported as handled.
	wiped *atomic.Bool

	// backing records which protections this allocation actually received.
	// Immutable after construction; read by Capabilities without the lock.
	backing allocInfo

	// Seal authentication (sealauth.go). sealAuth is the construction-time
	// choice: false only with WithUnauthenticatedSeal. sealTagged records
	// that sealTag/sealNonce/sealGen describe the current sealed bytes; Unseal
	// and Destroy verify only then, so a Seal that could not take a tag (the
	// unreachable already-ciphertext branch) is never misreported as a
	// corruption. All protected by mu.
	sealAuth   bool
	sealTagged bool
	sealGen    uint64
	sealNonce  [sealNonceLen]byte
	sealTag    [sealTagLen]byte

	// closedAtRest is set by [WithClosedAtRest]: the region is no-access
	// except while a borrow or an access method is using it. Immutable after
	// construction. See closedatrest.go.
	closedAtRest bool

	// openMu guards openers, the number of uses that currently hold a
	// closed-at-rest region open. Borrows hold mu shared, so they need a lock
	// of their own to agree on who opens and who closes.
	openMu  sync.Mutex
	openers int
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
// raw is zeroed whether this call SUCCEEDS OR FAILS. Wiping only on success
// would leave the caller's plaintext sitting in an ordinary heap slice that the
// warning above has just told them is gone — the worst of both, since they will
// not wipe it themselves. The only exception is an empty raw, where there is
// nothing to wipe.
//
// That means a retry after [ErrNoSecureMemory] has nothing left to copy. It does
// not need one: that error depends only on the platform and on
// [WithInsecureFallback], both knowable before the call — see [Probe].
//
// Common errors: EPERM / ENOMEM from mlock (RLIMIT_MEMLOCK exceeded — check
// `ulimit -l` or systemd LimitMEMLOCK=). On platforms with no lockable
// off-heap memory the error is [ErrNoSecureMemory] unless
// [WithInsecureFallback] is passed.
func NewBuffer(raw []byte, opts ...Option) (*SecureBuffer, error) {
	if len(raw) == 0 {
		return nil, errors.New("secmem.NewBuffer: empty input")
	}
	// Deferred, not placed after the copy: every early return below is an error
	// path that used to hand the caller back their plaintext intact. A defer
	// also means a future error path cannot forget it.
	defer secureWipeSlice(raw)
	defer clearRegisters() // the copy below moves the secret through registers; see SecureBuffer.WithBytes
	cfg := applyOptions(opts)
	if err := gateInsecure(platformHasSecureMemory, cfg); err != nil {
		return nil, fmt.Errorf("secmem.NewBuffer: %w", err)
	}
	region, data, info, err := cfg.alloc(len(raw))
	if err != nil {
		return nil, fmt.Errorf("secmem.NewBuffer: %w", err)
	}
	if err := fillCanary(region.inner[len(data):]); err != nil {
		_ = freeSecretMem(region) // nothing secret written yet
		return nil, fmt.Errorf("secmem.NewBuffer: %w", err)
	}
	// Register first, copy second — see fillInitial for why the order matters.
	sb, err := newSecureBuffer(region, data, info, cfg)
	if err != nil {
		return nil, err
	}
	if err := sb.fillInitial(raw); err != nil {
		return nil, fmt.Errorf("secmem.NewBuffer: %w", err)
	}
	return sb, nil
}

// NewEmptyBuffer allocates an mlock'd zero-filled region of exactly size bytes.
// Equivalent to NewBuffer(make([]byte, size)) without the intermediate heap copy.
func NewEmptyBuffer(size int, opts ...Option) (*SecureBuffer, error) {
	if size <= 0 {
		return nil, fmt.Errorf("secmem.NewEmptyBuffer: invalid size %d", size)
	}
	cfg := applyOptions(opts)
	if err := gateInsecure(platformHasSecureMemory, cfg); err != nil {
		return nil, fmt.Errorf("secmem.NewEmptyBuffer: %w", err)
	}
	region, data, info, err := cfg.alloc(size)
	if err != nil {
		return nil, fmt.Errorf("secmem.NewEmptyBuffer: %w", err)
	}
	if err := fillCanary(region.inner[len(data):]); err != nil {
		_ = freeSecretMem(region)
		return nil, fmt.Errorf("secmem.NewEmptyBuffer: %w", err)
	}
	return newSecureBuffer(region, data, info, cfg)
}

// fillInitial copies raw into a buffer newSecureBuffer has just registered,
// under the exclusive lock. It exists so that the janitor knows the region
// BEFORE the secret is in it. The copying constructors used to copy first and
// register second, so a WipeAllSecrets that ran in between could not see the
// buffer: for that window the plaintext existed only in an unregistered
// region, and the caller's copy had already been wiped. Now every secret byte
// ever written into a SecureBuffer is written into a registered one.
//
// The lock is what makes the copy correct against that same wipe. A pass that
// takes the region before this does leaves it zeroed and flagged; a copy that
// then went ahead would write a live secret into a region the wipe has already
// reported as handled — the exact thing the wiped flag exists to refuse for
// every other mutator. So this refuses too: the buffer is destroyed and
// ErrWiped returned, which is the honest outcome for a secret created while
// the process is emergency-wiping.
func (s *SecureBuffer) fillInitial(raw []byte) error {
	s.mu.lock()
	if s.wiped.Load() {
		s.mu.unlock()
		_ = s.Destroy()
		return ErrWiped
	}
	if err := s.open(); err != nil {
		s.mu.unlock()
		_ = s.Destroy()
		return err
	}
	copy(s.data, raw)
	err := s.close()
	s.mu.unlock()
	if err != nil {
		_ = s.Destroy()
	}
	return err
}

// newSecureBuffer wires up a SecureBuffer from a pre-allocated (region, data)
// pair plus its allocation facts, and registers the AddCleanup finalization
// fallback. The canary slack must already be filled by the caller.
//
// The janitor key is passed to AddCleanup by value; cleanup resolution happens
// through emergencyJanitor's raw-mapping registry.
//
// On a refused registration (identity collision — see nextJanitorKey) the
// region is wiped and released here and the error returned: a buffer no wipe
// path can reach must not exist. It holds no secret yet — the constructors
// copy after registering, see fillInitial — so the wipe is belt and braces.
func newSecureBuffer(region secRegion, data []byte, backing allocInfo, cfg config) (*SecureBuffer, error) {
	backing.unauthenticatedSeal = cfg.unauthenticatedSeal
	st := &bufferState{
		data:       data,
		region:     region,
		mu:         newBufferRWLock(),
		backing:    backing,
		sealCipher: new(atomic.Bool),
		wiped:      new(atomic.Bool),
		sealAuth:   !cfg.unauthenticatedSeal,
	}
	sb := &SecureBuffer{bufferState: st}

	// The canary zone is the slack between the caller's size and the page
	// boundary, described once, here, from the construction-time size. The
	// janitor keeps this layout and verifies it on Destroy and on the
	// emergency wipe, so a later Truncate — which shrinks data's length AND
	// capacity — cannot move the zone.
	canary := bufferCanary(cap(data), len(region.inner))

	// Register with the emergency janitor first. The janitor stores raw mapping
	// metadata (not *SecureBuffer), so this does not keep sb reachable for GC.
	key, err := emergencyJanitor.register(region, canary, sb.mu, sb.sealCipher, sb.wiped)
	if err != nil {
		secureWipeSlice(region.inner)
		_ = freeSecretMem(region)
		return nil, err
	}
	sb.janitorKey = key

	// Safety-net cleanup: if the caller forgets Destroy(), this wipes and frees
	// the mmap'd region when the buffer's state is GC'd. It is attached to the
	// state, not to sb: a copy of the SecureBuffer value shares the state, and
	// the region must outlive every such copy, not just the first handle.
	//
	// runtime.AddCleanup callbacks MUST NOT reference st directly (that would
	// keep it alive and prevent the cleanup from running).  The raw slice is
	// passed as the argument, capturing only the off-heap mapping metadata.
	//
	// IMPORTANT: The cleanup fires when the last handle becomes unreachable —
	// NOT when all references to data are gone.  Any retained []byte from
	// WithBytes becomes a dangling pointer after the cleanup runs.
	st.cleanup = runtime.AddCleanup(st, func(key uint64) {
		slog.Warn("secmem: SecureBuffer finalized without explicit Destroy()",
			slog.Int("size", len(region.inner)),
			slog.String("advice", "call Destroy() explicitly for deterministic wipe"),
		)
		if err := emergencyJanitor.release(key, false); err != nil {
			slog.Error("secmem: SecureBuffer cleanup release failed",
				slog.Any("error", err),
			)
		}
	}, sb.janitorKey)

	// Closed at rest: the buffer is born closed. A copying constructor opens
	// it for the copy like any other use (fillInitial). Not on the insecure
	// heap fallback, where there is no page protection to apply.
	if cfg.closedAtRest && !backing.insecure {
		if err := mprotectSecretMem(region, 0 /*PROT_NONE*/); err != nil {
			_ = sb.Destroy()
			return nil, fmt.Errorf("secmem: closing a closed-at-rest buffer: %w", err)
		}
		st.closedAtRest = true
		st.backing.closedAtRest = true
	}

	return sb, nil
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// Destroy wipes the entire locked area and releases it:
//
//  1. Cancel the garbage-collection fallback, so the region is released once.
//  2. Make the area writable again, whatever Seal, ReadOnly or
//     [WithClosedAtRest] left it at; a sealed buffer's tag is verified and,
//     on Windows, its contents decrypted first.
//  3. Check the canary slack behind the data for an out-of-bounds write.
//  4. Overwrite the whole area with zeros by a routine the compiler cannot
//     elide; on amd64 and arm64 it also flushes the cache lines (see
//     [Capabilities.FlushedWipe]).
//  5. Drop the physical pages and release the range. On Linux and Windows
//     the range is first kept as a no-access reservation in the destroy-time
//     quarantine (see [SetQuarantineLimits]), so a slice retained past
//     Destroy faults; elsewhere, or with the quarantine off, it is unmapped
//     at once.
//
// Destroy is idempotent and goroutine-safe; it waits for any in-flight access
// to finish. The effect is seen through this handle and through every copy of
// it (see "Copies are aliases" on [SecureBuffer]). Afterwards
// [SecureBuffer.IsDestroyed] is true, the access, mutation, Seal/Unseal and
// protection methods return [ErrDestroyed], [SecureBuffer.Len] and
// [SecureBuffer.MappedLen] return 0, [SecureBuffer.IsSealed] is false, a
// further Destroy returns nil, and [SecureBuffer.Capabilities] and
// [SecureBuffer.LockOrder] keep reporting the values they had.
//
// An error reports a problem found on the way; it does not stop the
// teardown, and the buffer is destroyed either way. Destroy returns
// [ErrCanaryViolation] if the canary slack was overwritten (the wipe still
// runs), [ErrIntegrity] if a sealed buffer's contents changed while dormant
// (the wipe still runs), and a wrapped OS error if releasing the range or
// placing it in quarantine failed, or if write access could not be restored,
// in which case the range is released without the wipe; several may be
// joined.
func (s *SecureBuffer) Destroy() error {
	if s == nil || s.bufferState == nil {
		return nil
	}

	s.mu.lock()
	defer s.mu.unlock()

	if s.region.inner == nil {
		return nil // already destroyed — idempotent
	}

	// Stop the safety-net cleanup first.  If Destroy was called explicitly
	// (the expected path), the cleanup is no longer needed.  Stop() is a no-op
	// if the cleanup has already fired.
	s.cleanup.Stop()

	// A sealed buffer is checked against its tag and, if seal-cipher
	// ciphertext, decrypted before release so the janitor's canary
	// verification sees the real slack. Both are reports, not gates: on any
	// failure the cipher flag stays set and wipeAndFree skips the canary check
	// instead — the wipe and unmap are never skipped. A buffer the emergency
	// wipe already handled holds zeros and its tag cannot match; that is
	// ErrWiped's story, not a corruption, so it is not verified.
	var integrityErr error
	verify := s.sealed && s.sealTagged && !s.wiped.Load()
	if verify || s.sealCipher.Load() {
		if err := mprotectSecretMem(s.region, 3 /*PROT_READ|PROT_WRITE*/); err == nil {
			// Best-effort re-lock (see Unseal): the plaintext is about to
			// exist for the length of the wipe. A refusal must not stop the
			// teardown.
			_ = relockSecretMem(s.region)
			if verify {
				if verr := s.sealVerify(); errors.Is(verr, ErrIntegrity) {
					integrityErr = verr
				}
			}
			if s.sealCipher.Load() {
				if derr := sealDecrypt(s.region); derr == nil {
					s.sealCipher.Store(false)
				}
			}
		}
	}

	// Take exclusive ownership from janitor registry and wipe/free exactly once.
	// If the entry is already gone (cleanup or emergency-wipe path won), treat as
	// successfully destroyed and skip touching raw to avoid use-after-free.
	err := errors.Join(integrityErr, emergencyJanitor.release(s.janitorKey, true))

	// Step 5 — nil references.  Makes IsDestroyed() true and Destroy idempotent.
	s.data = nil
	s.region = secRegion{}

	// Step 6 — ensure the GC does not run the cleanup concurrently between
	// Stop() and here.  KeepAlive pins the state in the liveness analysis until
	// this point, preventing the finalizer goroutine from scheduling the
	// already-Stopped cleanup during the wipe window.
	runtime.KeepAlive(s.bufferState)

	if err != nil {
		return fmt.Errorf("secmem.SecureBuffer.Destroy: %w", err)
	}
	return nil
}

// IsDestroyed reports whether the buffer has been destroyed.
func (s *SecureBuffer) IsDestroyed() bool {
	if s == nil || s.bufferState == nil {
		return true
	}
	s.mu.rLock()
	defer s.mu.rUnlock()
	return s.region.inner == nil
}

// ---------------------------------------------------------------------------
// Size & mprotect
// ---------------------------------------------------------------------------

// Len returns the usable size of the buffer (the size requested by the caller).
// May be smaller than [SecureBuffer.MappedLen] due to page-rounding.
func (s *SecureBuffer) Len() int {
	if s == nil || s.bufferState == nil {
		return 0
	}
	s.mu.rLock()
	defer s.mu.rUnlock()
	return len(s.data)
}

// MappedLen returns the size of the locked secret area (the page-rounded
// region holding the data and its canary slack). Always a multiple of the OS
// page size (≥ Len). The PROT_NONE guard pages bracketing the area are NOT
// counted — they are reserved address space, not lockable memory.
func (s *SecureBuffer) MappedLen() int {
	if s == nil || s.bufferState == nil {
		return 0
	}
	s.mu.rLock()
	defer s.mu.rUnlock()
	return len(s.region.inner)
}

// ReadOnly sets the buffer's memory protection to read-only.
// This prevents accidental overwrites once a secret is fully loaded.
// [SecureBuffer.Destroy] needs no [SecureBuffer.ReadWrite] first: it restores
// write access itself.
//
// ReadOnly takes the buffer's exclusive lock, so it waits for every in-flight
// access — including a concurrent CopyIn, SetByteAt, ReadFrom or Truncate —
// to finish before changing the protection; no such write can then hit the
// PROT_READ page.
//
// The guard is at the API boundary: [SecureBuffer.CopyIn],
// [SecureBuffer.SetByteAt], [SecureBuffer.Truncate] and
// [SecureBuffer.ReadFrom] return [ErrReadOnly] instead of writing. It does
// not reach a write made THROUGH THE SLICE a borrowing accessor hands out
// ([SecureBuffer.WithBytes], [SecureBuffer.WithBytesErr]): no supported OS
// has sub-page protection, and the accessor cannot know what fn will do with
// the slice, so such a write hits the PROT_READ page and faults the process.
// Treat a borrowed slice as read-only for as long as the buffer is.
//
// NOTE: Operates on the full page-rounded region; sub-page protection
// is not possible on any supported OS.
func (s *SecureBuffer) ReadOnly() error {
	if s == nil {
		return errors.New("secmem.SecureBuffer.ReadOnly: nil receiver")
	}
	if s.bufferState == nil {
		return fmt.Errorf("secmem.SecureBuffer.ReadOnly: %w", ErrDestroyed)
	}
	s.mu.lock()
	defer s.mu.unlock()
	if s.region.inner == nil {
		return fmt.Errorf("secmem.SecureBuffer.ReadOnly: %w", ErrDestroyed)
	}
	if s.wiped.Load() {
		return fmt.Errorf("secmem.SecureBuffer.ReadOnly: %w", ErrWiped)
	}
	if s.sealed {
		return fmt.Errorf("secmem.SecureBuffer.ReadOnly: %w", ErrSealed)
	}
	// A closed-at-rest buffer stays closed: the mode is recorded and applied
	// each time it is opened.
	if !s.closedAtRest {
		if err := mprotectSecretMem(s.region, 1 /*PROT_READ*/); err != nil {
			return fmt.Errorf("secmem.SecureBuffer.ReadOnly: %w", err)
		}
	}
	s.readOnly = true
	return nil
}

// ReadWrite restores read-write access to the buffer. It is not needed before
// [SecureBuffer.Destroy], which makes the region writable for its own wipe.
//
// The exclusive lock is held to drain all in-flight access before the
// mprotect.
func (s *SecureBuffer) ReadWrite() error {
	if s == nil {
		return errors.New("secmem.SecureBuffer.ReadWrite: nil receiver")
	}
	if s.bufferState == nil {
		return fmt.Errorf("secmem.SecureBuffer.ReadWrite: %w", ErrDestroyed)
	}
	s.mu.lock()
	defer s.mu.unlock()
	if s.region.inner == nil {
		return fmt.Errorf("secmem.SecureBuffer.ReadWrite: %w", ErrDestroyed)
	}
	if s.wiped.Load() {
		return fmt.Errorf("secmem.SecureBuffer.ReadWrite: %w", ErrWiped)
	}
	if s.sealed {
		return fmt.Errorf("secmem.SecureBuffer.ReadWrite: %w", ErrSealed)
	}
	if !s.closedAtRest { // see ReadOnly
		if err := mprotectSecretMem(s.region, 3 /*PROT_READ|PROT_WRITE*/); err != nil {
			return fmt.Errorf("secmem.SecureBuffer.ReadWrite: %w", err)
		}
	}
	s.readOnly = false
	return nil
}

// Seal sets the buffer's memory protection to PROT_NONE, making any access
// cause a hardware fault. This is the hardened
// dormant state for long-lived secrets that are not actively being used.
//
// On Windows, Seal additionally encrypts the contents in place with a
// KERNEL-HELD per-boot key (CryptProtectMemory): a full process memory dump
// taken while the buffer is sealed — procdump, Task Manager, a WER full dump,
// the hibernation file — contains ciphertext, and the key is not in the dump.
// This protects the sealed window only, and is not a defense against code
// executing inside the process (which can call CryptUnprotectMemory itself)
// nor against cold-boot RAM capture (the kernel's key is in RAM too). On
// other platforms Seal has no cipher; on Linux the allocation-time
// protections (memfd_secret, MADV_DONTDUMP) are the dump defenses.
//
// While sealed, all access methods (WithBytes, WithBytesErr, CopyOut, CopyIn,
// etc.) return [ErrSealed]. Call [SecureBuffer.Unseal] before accessing the
// buffer.
//
// [SecureBuffer.Destroy] works correctly on sealed buffers — it lifts the
// PROT_NONE restriction (and decrypts) internally before wiping.
//
// Note: [SecureBuffer.ReadOnly] and [SecureBuffer.ReadWrite] return
// [ErrSealed] while sealed. To
// transition from Sealed to ReadOnly, call Unseal then ReadOnly. A buffer that
// was read-only before Seal stays read-only after [SecureBuffer.Unseal] — the
// protection is preserved across the seal cycle.
//
// Seal is idempotent: calling it on an already-sealed buffer is a no-op.
//
// Seal also takes a keyed tag over the bytes it leaves at rest, and Unseal
// verifies it before anything reads them: a bit that changed while the buffer
// was dormant — a Rowhammer flip, a DRAM soft error — is refused with
// [ErrIntegrity] rather than handed out as the secret. The key is derived from
// a 16 KiB prekey locked once per process on the first Seal; if that
// allocation fails, Seal fails. A buffer constructed with
// [WithUnauthenticatedSeal] skips the tag. The tag costs one hash of the
// prekey and one of the region per Seal and per Unseal, tens of microseconds
// for a page.
//
// On Windows the contents are encrypted before the page protection is applied.
// If the protection then fails and the encryption cannot be rolled back either,
// Seal returns the error but leaves the buffer sealed anyway: the contents are
// ciphertext, and an unsealed buffer would hand them out as the secret. The
// accessors return [ErrSealed] and [SecureBuffer.Unseal] decrypts and recovers
// it; Unseal then Seal again retries the page protection. Off Windows there is
// no cipher, and a failed Seal leaves the buffer unsealed with its contents
// intact.
func (s *SecureBuffer) Seal() error {
	if s == nil {
		return errors.New("secmem.SecureBuffer.Seal: nil receiver")
	}
	if s.bufferState == nil {
		return fmt.Errorf("secmem.SecureBuffer.Seal: %w", ErrDestroyed)
	}
	s.mu.lock()
	defer s.mu.unlock()
	if s.region.inner == nil {
		return fmt.Errorf("secmem.SecureBuffer.Seal: %w", ErrDestroyed)
	}
	if s.wiped.Load() {
		return fmt.Errorf("secmem.SecureBuffer.Seal: %w", ErrWiped)
	}
	if s.sealed {
		return nil // idempotent
	}
	if s.sealCipher.Load() {
		// Unreachable: the rollback below leaves the buffer sealed whenever
		// the contents stay ciphertext. Kept because the cost of being wrong
		// is a second cipher pass that one Unseal cannot reverse — the secret
		// would be gone for good. Close the accessors over what is already
		// ciphertext and let Unseal recover it.
		s.sealed = true
		return errors.New("secmem.SecureBuffer.Seal: contents are already seal-cipher ciphertext; buffer left sealed, Unseal decrypts it")
	}
	// The seal cipher encrypts in place (Windows: CryptProtectMemory), so the
	// region must be writable during Seal. If the caller had set it read-only,
	// lift the PROT_READ protection just for the encrypt: the region ends at
	// PROT_NONE regardless, s.readOnly stays set, and Unseal re-applies
	// PROT_READ. On non-Windows the cipher is a no-op, but the lift keeps the
	// path uniform; the rollback paths below restore PROT_READ.
	if s.readOnly || s.closedAtRest {
		if err := mprotectSecretMem(s.region, 3 /*PROT_READ|PROT_WRITE*/); err != nil {
			return fmt.Errorf("secmem.SecureBuffer.Seal: %w", err)
		}
	}
	// Encrypt BEFORE dropping write access. The flag is set immediately so
	// the janitor's emergency-wipe path never canary-checks ciphertext.
	s.sealTagged = false
	applied, err := sealEncrypt(s.region)
	if err != nil {
		s.reapplyReadOnly()
		return fmt.Errorf("secmem.SecureBuffer.Seal: %w", err)
	}
	if applied {
		s.sealCipher.Store(true)
	}
	// Tag the bytes as they will sit at rest — after the cipher, before the
	// protection — so Unseal verifies before it decrypts (sealauth.go).
	if s.sealAuth {
		if err := s.sealAuthenticate(); err != nil {
			return s.rollbackSeal(applied, err)
		}
	}
	if err := sealProtect(s.region); err != nil {
		return s.rollbackSeal(applied, err)
	}
	s.sealed = true
	return nil
}

// rollbackSeal undoes the seal cipher after a later Seal step failed with
// cause, so the buffer stays usable plaintext, and returns the error to hand
// back. Caller holds s.mu with the region writable.
//
// If the cipher cannot be rolled back the contents are ciphertext with no
// page protection. Every accessor gates on sealed, so returning unsealed
// would hand the ciphertext out as the secret; sealed is the one state whose
// invariants still hold, and Unseal's decrypt path is the recovery. The tag,
// when one was taken, still describes these bytes, so that Unseal verifies
// them like any other sealed state.
func (s *SecureBuffer) rollbackSeal(applied bool, cause error) error {
	if applied {
		if derr := sealDecrypt(s.region); derr != nil {
			s.sealed = true
			s.reapplyReadOnly()
			return fmt.Errorf("secmem.SecureBuffer.Seal: %w; rolling the cipher back failed too: %w (buffer left sealed, Unseal decrypts it)", cause, derr)
		}
		s.sealCipher.Store(false)
	}
	s.sealTagged = false
	s.reapplyReadOnly()
	return fmt.Errorf("secmem.SecureBuffer.Seal: %w", cause)
}

// sealProtect is Seal's PROT_NONE step. A package var, not an inline call,
// solely so a test can make it fail on demand together with sealDecrypt and
// drive the rollback path above; production always runs the value here.
var sealProtect = func(region secRegion) error {
	return mprotectSecretMem(region, 0 /*PROT_NONE*/)
}

// reapplyReadOnly re-applies the buffer's rest protection: PROT_READ when it
// is flagged read-only, PROT_NONE when it is closed at rest.
// Seal lifts that protection to run the in-place seal cipher; on a Seal
// rollback path this restores it so the physical page protection stays in sync
// with the buffer's state. Best-effort — the caller is already returning an error.
// Caller holds s.mu and the region is live.
func (s *SecureBuffer) reapplyReadOnly() {
	if prot := s.restProtection(); prot != 3 /*PROT_READ|PROT_WRITE*/ {
		_ = mprotectSecretMem(s.region, prot)
	}
}

// Unseal lifts the PROT_NONE protection applied by [SecureBuffer.Seal] and
// restores the buffer's protection at rest: read-write, read-only if
// [SecureBuffer.ReadOnly] was in force when it was sealed, or no access for a
// buffer built with [WithClosedAtRest] (which opens per use).
//
// Unseal verifies the seal tag before anything reads the bytes. If they
// changed while dormant it returns [ErrIntegrity] and the buffer stays sealed.
// Every other failure also leaves it sealed: on Windows, where Seal gave up
// the page lock, a refused re-lock; a failed decrypt; or a failure to restore
// the rest protection. The secret is never handed out unlocked, undecrypted
// or with the wrong protection.
//
// After a successful Unseal, all access methods work normally. To re-protect
// after use, call Seal again.
//
// Unseal is idempotent: calling it on an already-unsealed buffer is a no-op.
func (s *SecureBuffer) Unseal() error {
	if s == nil {
		return errors.New("secmem.SecureBuffer.Unseal: nil receiver")
	}
	if s.bufferState == nil {
		return fmt.Errorf("secmem.SecureBuffer.Unseal: %w", ErrDestroyed)
	}
	s.mu.lock()
	defer s.mu.unlock()
	if s.region.inner == nil {
		return fmt.Errorf("secmem.SecureBuffer.Unseal: %w", ErrDestroyed)
	}
	if s.wiped.Load() {
		return fmt.Errorf("secmem.SecureBuffer.Unseal: %w", ErrWiped)
	}
	if !s.sealed {
		return nil // idempotent
	}
	if err := mprotectSecretMem(s.region, 3 /*PROT_READ|PROT_WRITE*/); err != nil {
		return fmt.Errorf("secmem.SecureBuffer.Unseal: %w", err)
	}
	// Windows dropped the page lock when Seal made the page no-access, and
	// lifting the protection does not restore it. Lock again BEFORE the
	// decrypt, so the plaintext never exists in a pageable page; if the lock
	// is refused (the working-set quota it gave up has gone elsewhere),
	// re-protect and stay sealed rather than hand out an unlocked secret.
	if err := relockSecretMem(s.region); err != nil {
		_ = mprotectSecretMem(s.region, 0 /*PROT_NONE*/)
		return fmt.Errorf("secmem.SecureBuffer.Unseal: restoring the page lock: %w", err)
	}
	// Verify before anything reads or transforms the bytes. On a mismatch
	// the buffer stays sealed — the altered secret is never handed out, see
	// ErrIntegrity — and a later Unseal verifies again, so a test that flips
	// a bit and flips it back does recover.
	if s.sealTagged {
		if err := s.sealVerify(); err != nil {
			_ = mprotectSecretMem(s.region, 0 /*PROT_NONE*/)
			return fmt.Errorf("secmem.SecureBuffer.Unseal: %w", err)
		}
	}
	if s.sealCipher.Load() {
		if err := sealDecrypt(s.region); err != nil {
			// Contents are still ciphertext: re-protect and stay sealed so
			// no access method can hand out garbage as the secret.
			_ = mprotectSecretMem(s.region, 0 /*PROT_NONE*/)
			return fmt.Errorf("secmem.SecureBuffer.Unseal: %w", err)
		}
		s.sealCipher.Store(false)
	}
	// Unseal lifted the region to PROT_READ|PROT_WRITE to decrypt in place. If
	// the caller had set the buffer read-only before sealing, re-apply
	// PROT_READ so the physical protection matches s.readOnly — a post-Unseal
	// mutator then refuses with ErrReadOnly instead of faulting. On failure the
	// buffer stays sealed (fail closed) rather than exposing a writable region.
	if rest := s.restProtection(); rest != 3 /*PROT_READ|PROT_WRITE*/ {
		if err := unsealRestoreReadOnly(s.region, rest); err != nil {
			// The region is read-write plaintext at this point, which is not
			// what sealed means, and Seal would return nil without touching
			// it. Seal it again: encrypt where the seal cipher applies, then
			// protect. Both best-effort — the error returned is the restore's
			// — but the cipher flag follows what actually happened, so a
			// later Unseal decrypts exactly when there is ciphertext.
			if applied, eerr := sealEncrypt(s.region); eerr == nil && applied {
				s.sealCipher.Store(true)
			}
			// The bytes at rest are new (the cipher does not repeat), so
			// the old tag no longer describes them: take a fresh one, and if
			// that fails leave the state honestly untagged rather than let
			// the next Unseal report a corruption that never happened.
			s.sealTagged = false
			if s.sealAuth {
				_ = s.sealAuthenticate()
			}
			_ = sealProtect(s.region)
			return fmt.Errorf("secmem.SecureBuffer.Unseal: restoring read-only: %w", err)
		}
	}
	s.sealed = false
	s.sealTagged = false
	return nil
}

// unsealRestoreReadOnly is Unseal's last step for a buffer whose rest
// protection is not read-write: PROT_READ for one that was read-only when
// sealed, PROT_NONE for one that is closed at rest. A package var for the reason sealProtect is one: so a
// test can make it fail and drive the path that has to seal again.
var unsealRestoreReadOnly = func(region secRegion, prot int) error {
	return mprotectSecretMem(region, prot)
}

// IsSealed reports whether the buffer is currently in the sealed (PROT_NONE) state.
func (s *SecureBuffer) IsSealed() bool {
	if s == nil || s.bufferState == nil {
		return false
	}
	s.mu.rLock()
	defer s.mu.rUnlock()
	return s.sealed
}

// Truncate shortens Len to n and wipes the freed tail; the allocation itself
// is unchanged, and Destroy and [WipeAllSecrets] still wipe all of it. n must
// be in [0, Len]. Like the other mutators it returns [ErrSealed] while sealed
// and [ErrReadOnly] while read-only.
func (s *SecureBuffer) Truncate(n int) error {
	if s == nil {
		return errors.New("secmem.SecureBuffer.Truncate: nil receiver")
	}
	if s.bufferState == nil {
		return fmt.Errorf("secmem.SecureBuffer.Truncate: %w", ErrDestroyed)
	}
	s.mu.lock()
	defer s.mu.unlock()
	if s.region.inner == nil {
		return fmt.Errorf("secmem.SecureBuffer.Truncate: %w", ErrDestroyed)
	}
	if s.wiped.Load() {
		return fmt.Errorf("secmem.SecureBuffer.Truncate: %w", ErrWiped)
	}
	if s.sealed {
		// The region is PROT_NONE while sealed; wiping the freed tail would
		// fault. Match the other mutating methods (CopyIn/SetByteAt/ReadFrom).
		return fmt.Errorf("secmem.SecureBuffer.Truncate: %w", ErrSealed)
	}
	if s.readOnly {
		// The region is PROT_READ; wiping the freed tail would fault. Refuse
		// at the API boundary instead of crashing.
		return fmt.Errorf("secmem.SecureBuffer.Truncate: %w", ErrReadOnly)
	}
	if n < 0 || n > len(s.data) {
		return fmt.Errorf("secmem.SecureBuffer.Truncate: n=%d out of range [0, %d]", n, len(s.data))
	}
	tail := s.data[n:]
	if len(tail) > 0 {
		if err := s.open(); err != nil {
			return fmt.Errorf("secmem.SecureBuffer.Truncate: %w", err)
		}
		secureWipeSlice(tail)
		if err := s.close(); err != nil {
			return fmt.Errorf("secmem.SecureBuffer.Truncate: %w", err)
		}
	}
	// Capacity clamped to n as well as length: the slice a later borrow hands
	// out can then not be re-sliced back over the tail just wiped. Harmless if
	// it could (the tail is zero and inside this buffer's own allocation), but
	// a borrowed slice that reaches exactly the live bytes is the cleaner
	// contract, and it costs nothing.
	s.data = s.data[:n:n]
	return nil
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------
