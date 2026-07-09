package secmem

import (
	"fmt"
	"log/slog"
)

// UseAsString exposes a SecureBuffer as a string for APIs that cannot accept
// bytes. The string is heap-backed and cannot be wiped; use this only at
// reviewed third-party/library boundaries and keep fn synchronous.
func UseAsString(buf *SecureBuffer, purpose string, fn func(string) error) error {
	if buf == nil {
		return ErrDestroyed
	}
	if purpose == "" {
		purpose = "unspecified"
	}
	if purpose == "unspecified" {
		slog.Warn("security: UseAsString called with unspecified purpose — document the string boundary",
			slog.String("advice", "pass a descriptive purpose string to UseAsString"))
	}
	return buf.WithBytesErr(func(b []byte) error {
		// ACCEPTED RISK: Go strings are immutable heap values. This helper
		// centralizes unavoidable string handoffs so they are searchable and
		// reviewable instead of scattered across callsites.
		if err := fn(string(b)); err != nil { //nolint:secmem-lint
			return fmt.Errorf("secure string boundary %q: %w", purpose, err)
		}
		return nil
	})
}
