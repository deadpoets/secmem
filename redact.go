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
// All three use VALUE receivers so both the pointer and an accidental
// dereference redact — a value copy would otherwise escape these
// pointer-receiver-only APIs and fall through to raw reflection. The methods
// read no fields, and the copy a value receiver makes is cheap and harmless:
// SecureBuffer and SecureArena are one pointer to their shared state (a copy
// is an alias, see their type docs), and an ArenaSlot is a handle.
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
func (s SecureBuffer) GoString() string { return redacted }

// Format implements [fmt.Formatter], so every verb (%v, %s, %x, %+v, %#v, ...)
// emits the redaction instead of reflecting into the guarded struct.
func (s SecureBuffer) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue implements [slog.LogValuer], so slog.Any("key", buf) redacts.
func (s SecureBuffer) LogValue() slog.Value { return slog.StringValue(redacted) }

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

// String implements [fmt.Stringer]. It always returns "[REDACTED]".
func (a SecureArena) String() string { return redacted }

// GoString implements [fmt.GoStringer], so %#v also redacts.
func (a SecureArena) GoString() string { return redacted }

// Format implements [fmt.Formatter], so every verb redacts.
func (a SecureArena) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue implements [slog.LogValuer], so slog.Any("key", arena) redacts.
func (a SecureArena) LogValue() slog.Value { return slog.StringValue(redacted) }
