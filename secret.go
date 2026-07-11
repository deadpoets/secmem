// secret.go implements Secret, the leak-safe value type for raw tokens,
// passwords, and API keys (DESIGN cross-cutter A).
//
// The redaction methods are IMPLEMENTED, not omitted: fmt and encoding/json
// reflect into struct fields, so a type without String/GoString/Marshal*
// methods leaks its contents the moment someone logs the enclosing struct.
// Every formatting and marshalling path returns the fixed "[REDACTED]"
// sentinel instead.

package secmem

import (
	"crypto/subtle"
	"io"
	"log/slog"
)

// redacted is the fixed sentinel every leak-safe method returns. It is
// deliberately constant: it never varies with the secret's length, content,
// or lifecycle state, so nothing can be inferred from it.
const redacted = "[REDACTED]"

// Secret wraps a [SecureBuffer] as a value that is safe to embed in structs
// that get logged, formatted, or marshalled: every such path produces
// "[REDACTED]" instead of the contents. Access the real bytes only through
// [Secret.WithBytes].
//
// Methods use a value receiver so fmt and encoding/json pick up the
// redaction whether a field is Secret or *Secret. The value holds a pointer
// to the underlying buffer, so COPIES SHARE ONE BACKING STORE AND ONE
// DESTROY: destroying any copy destroys them all. This is the sharp edge of
// the design — treat a Secret like the *SecureBuffer it wraps, not like a
// self-contained value.
//
// The zero value behaves like a destroyed Secret: access returns
// [ErrDestroyed], redaction still works, nothing panics.
//
// UnmarshalJSON and UnmarshalText are intentionally NOT provided: they would
// silently land plaintext on the GC heap during decoding. To ingest a secret
// from a decoded document, unmarshal into a []byte and hand it to [NewSecret],
// which wipes the input — the transient heap copy is then explicit at the
// call site instead of hidden inside a decoder.
type Secret struct {
	buf *SecureBuffer
}

// NewSecret copies b into hardened memory and returns the Secret. b is wiped
// after the copy (defense-in-depth) — the caller must not reuse it.
//
// Errors are those of [NewBuffer]: empty input, allocation or mlock failure,
// and [ErrNoSecureMemory] on platforms without secure memory unless
// [WithInsecureFallback] is passed.
func NewSecret(b []byte, opts ...Option) (Secret, error) {
	buf, err := NewBuffer(b, opts...)
	if err != nil {
		return Secret{}, err
	}
	return Secret{buf: buf}, nil
}

// WithBytes calls fn with the secret's bytes. The slice is valid only for
// the duration of fn and must not be retained — see [SecureBuffer.WithBytes]
// for the full borrowing contract (locking, non-reentrancy).
//
// Returns [ErrDestroyed] on a zero-value or destroyed Secret.
func (s Secret) WithBytes(fn func([]byte)) error {
	return s.buf.WithBytes(fn)
}

// Equal reports whether s and other hold the same bytes, in constant time
// with respect to the contents. Differing lengths return false immediately —
// the length itself is not concealed. Two Secrets sharing one backing store
// (value copies of each other) are equal without comparing bytes.
//
// A zero-value or destroyed Secret is equal to nothing, including another
// zero-value Secret: there are no bytes to compare, and false is the
// conservative answer.
func (s Secret) Equal(other Secret) bool {
	if s.buf == nil || other.buf == nil {
		return false
	}
	if s.buf == other.buf {
		// Same backing store — trivially equal if still accessible. Comparing
		// through nested WithBytes here would read-lock the same buffer twice,
		// which the borrowing contract forbids (writer-preference deadlock).
		return s.buf.WithBytes(func([]byte) {}) == nil
	}
	equal := false
	err := s.buf.WithBytesErr(func(a []byte) error {
		return other.buf.WithBytesErr(func(b []byte) error {
			if len(a) == len(b) {
				equal = subtle.ConstantTimeCompare(a, b) == 1
			}
			return nil
		})
	})
	return err == nil && equal
}

// WriteTo implements [io.WriterTo]. It writes the PLAINTEXT secret to w —
// this is the deliberate egress path, for handing the secret to a socket,
// pipe, or child process stdin. See [SecureBuffer.WriteTo] for the locking
// and wiping contract. Do not point it at a log.
func (s Secret) WriteTo(w io.Writer) (int64, error) {
	return s.buf.WriteTo(w)
}

// Destroy wipes and releases the underlying buffer. Every value copy of this
// Secret shares that buffer, so all of them are destroyed with it.
// Destroying a zero-value or already-destroyed Secret is a no-op returning
// nil (idempotent, matching [SecureBuffer.Destroy]).
func (s Secret) Destroy() error {
	return s.buf.Destroy()
}

// String implements [fmt.Stringer]. It always returns "[REDACTED]".
func (s Secret) String() string { return redacted }

// GoString implements [fmt.GoStringer], covering the %#v verb.
// It always returns "[REDACTED]".
func (s Secret) GoString() string { return redacted }

// MarshalText implements [encoding.TextMarshaler].
// It always returns "[REDACTED]" — a Secret never serializes its contents.
func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// MarshalJSON implements json.Marshaler.
// It always returns the JSON string "[REDACTED]".
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// LogValue implements [slog.LogValuer]. It always returns "[REDACTED]".
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }
