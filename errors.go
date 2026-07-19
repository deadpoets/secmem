package secmem

import "errors"

// ErrDestroyed is returned by SecureBuffer methods after the buffer has been
// destroyed. It is the canonical sentinel for the destroyed/wiped state.
var ErrDestroyed = errors.New("secmem: secure buffer has been destroyed")

// ErrSealed is returned by SecureBuffer access methods when the buffer is in
// the sealed (PROT_NONE) state. Call [SecureBuffer.Unseal] before accessing.
var ErrSealed = errors.New("secmem: secure buffer is sealed")

// ErrReadOnly is returned by the mutating methods (CopyIn, SetByteAt, Truncate,
// ReadFrom) when the buffer is in the read-only (PROT_READ) state set by
// [SecureBuffer.ReadOnly]. Call [SecureBuffer.ReadWrite] before mutating.
//
// The guard is a memory-safety boundary: a mutating method that wrote through
// to the PROT_READ page would fault the process, so secmem refuses the write at
// the API boundary instead — misuse returns an error, it never crashes.
var ErrReadOnly = errors.New("secmem: secure buffer is read-only — call ReadWrite before mutating")

// ErrArenaDestroyed is returned by SecureArena and ArenaSlot methods after the
// arena has been destroyed via Destroy().
var ErrArenaDestroyed = errors.New("secmem: secure arena has been destroyed")

// ErrArenaFull is returned by SecureArena.Acquire when all slots are in use.
var ErrArenaFull = errors.New("secmem: secure arena is full — no free slots")

// ErrSlotReleased is returned by ArenaSlot methods after the slot has been
// released via Release(). Calling Release again is a no-op (idempotent).
var ErrSlotReleased = errors.New("secmem: arena slot has been released")

// ErrNoSecureMemory is returned by constructors on platforms with no lockable
// off-heap memory (everything except linux, darwin, and windows). secmem
// refuses to place secrets on the unprotected Go heap; a caller that accepts
// that exposure must say so explicitly with [WithInsecureFallback].
var ErrNoSecureMemory = errors.New(
	"secmem: no lockable off-heap memory on this platform — refusing the unprotected heap (opt in with WithInsecureFallback)")

// ErrCanaryViolation is returned by Destroy (and ArenaSlot.Release) when the
// canary slack adjacent to the secret was overwritten: some code in this
// process wrote past the end of a buffer or slot. The wipe and release
// complete regardless — the violation is reported, never left mapped.
//
// This is a memory-safety bug report, not a security breach by itself: treat
// it like a failed assertion. Find and fix the overflow; do not suppress the
// error.
var ErrCanaryViolation = errors.New(
	"secmem: canary violation — memory adjacent to a secret was overwritten (out-of-bounds write bug in this process)")
