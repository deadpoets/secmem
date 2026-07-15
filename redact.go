// redact.go makes SecureBuffer, SecureArena, and ArenaSlot redact themselves
// under every formatting and logging path.
//
// Without this, fmt reflects into the guarded, mmap'd struct — and rather than
// dumping plaintext, it hits a hardware fault reflecting past the guard pages:
// fmt.Printf("%v", buf), slog.Any("k", buf), %s, %+v, %#v, and %x all crash the
// process. Implementing fmt.Formatter routes every verb through the same fixed
// redaction; Stringer/GoStringer/slog.LogValuer cover the non-fmt callers (the
// standard log package, an error wrapped with %w whose %v chain includes a
// buffer, ...).
//
// The redaction is the fixed "[REDACTED]" constant already used by [Secret] —
// it reads no fields, so it never locks, never touches the guarded region, and
// is safe to call even from inside a WithBytes/WithBytesErr callback.
//
// SecureBuffer and ArenaSlot use VALUE receivers so both the pointer and an
// accidental dereference redact — a value copy would otherwise escape these
// pointer-receiver-only APIs and fall through to raw reflection. This is safe
// specifically because the methods read no fields: the struct copy the value
// receiver triggers is never inspected. SecureArena can't take a value receiver
// directly — its slot-bookkeeping mutex is a value sync.Mutex that go vet's
// copylocks check would flag on any value-receiver method declared directly on
// SecureArena — so it embeds the zero-size [arenaRedactor] instead: an embedded
// type's methods promote into both the value and pointer method sets of the
// embedding struct without copying it, so redaction covers both forms while
// copylocks still correctly flags any accidental SecureArena value copy
// elsewhere in the codebase.
package secmem

import (
	"fmt"
	"io"
	"log/slog"
)

// --- SecureBuffer ---

// String implements [fmt.Stringer]. It always returns "[REDACTED]".
func (s SecureBuffer) String() string { return redacted }

// GoString implements [fmt.GoStringer], so %#v also redacts.
func (s SecureBuffer) GoString() string { return redacted } //nolint:gocritic // hugeParam: value receiver intentional — redacts *buf and a dereferenced buf; reads no fields.

// Format implements [fmt.Formatter], so every verb (%v, %s, %x, %+v, %#v, ...)
// emits the redaction instead of reflecting into the guarded struct.
func (s SecureBuffer) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) } //nolint:gocritic // hugeParam: value receiver intentional — redacts *buf and a dereferenced buf; reads no fields.

// LogValue implements [slog.LogValuer], so slog.Any("key", buf) redacts.
func (s SecureBuffer) LogValue() slog.Value { return slog.StringValue(redacted) } //nolint:gocritic // hugeParam: value receiver intentional — redacts *buf and a dereferenced buf; reads no fields.

// --- ArenaSlot ---

// String implements [fmt.Stringer]. It always returns "[REDACTED]".
func (s ArenaSlot) String() string { return redacted }

// GoString implements [fmt.GoStringer], so %#v also redacts.
func (s ArenaSlot) GoString() string { return redacted }

// Format implements [fmt.Formatter], so every verb redacts.
func (s ArenaSlot) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue implements [slog.LogValuer], so slog.Any("key", slot) redacts.
func (s ArenaSlot) LogValue() slog.Value { return slog.StringValue(redacted) }

// --- SecureArena ---

// arenaRedactor carries SecureArena's redaction methods on a zero-size value
// receiver so they can be embedded — see the package-level doc comment above
// for why SecureArena can't declare these directly. Reads no fields (not even
// the embedding SecureArena's), so calling one never locks, never touches the
// slab, and never races Destroy.
type arenaRedactor struct{}

func (arenaRedactor) String() string             { return redacted }
func (arenaRedactor) GoString() string           { return redacted }
func (arenaRedactor) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }
func (arenaRedactor) LogValue() slog.Value       { return slog.StringValue(redacted) }
