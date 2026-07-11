package secmem

import "errors"

// ErrDestroyed is returned by SecureBuffer methods after the buffer has been
// destroyed. It is the canonical sentinel for the destroyed/wiped state.
var ErrDestroyed = errors.New("secmem: secure buffer has been destroyed")

// ErrSealed is returned by SecureBuffer access methods when the buffer is in
// the sealed (PROT_NONE) state. Call [SecureBuffer.Unseal] before accessing.
var ErrSealed = errors.New("secmem: secure buffer is sealed")

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
