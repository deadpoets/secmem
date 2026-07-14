// Package secmemlint provides a go/analysis analyzer that flags secret material
// escaping a secmem borrowing closure.
//
// secmem hands out a secret's bytes only inside a borrowing closure — the
// argument to SecureBuffer.WithBytes / WithBytesErr (and the WithScalar /
// WithSeed / WithDER accessors in secmem-crypto). The library documents one
// rule for that slice: it is valid ONLY for the duration of the closure and
// must not be stored, copied into an escaping value, sent to another goroutine,
// or otherwise allowed to outlive the call. This analyzer enforces that rule
// statically, so a misuse fails at build time instead of leaking a secret to
// the GC heap at run time.
//
// # Checks
//
//   - string(borrowed): converting the borrowed slice to a heap string.
//   - append(dst, borrowed...): spreading it into an escaping slice.
//   - copy, channel send, goroutine capture, or assignment to a variable
//     declared outside the closure: moving it out of the lease.
//   - borrowed bytes passed to a heap-copying or logging standard-library sink
//     (fmt, encoding/json, encoding/hex, encoding/base64, log, log/slog,
//     crypto/ed25519.Sign, crypto/hmac.New, bytes/slices.Clone).
//   - a secmem access method called on the SAME buffer inside its own closure
//     (the accessors take the buffer lock and are not reentrant — they deadlock).
//
// # Strict mode
//
// The -strict flag (off by default) enables two higher-noise, heuristic checks:
//
//   - a locally constructed SecureBuffer / signer / key that is never Destroyed
//     and never handed off (returned or passed on) — add a defer Destroy().
//   - a secret-named identifier (password, token, apiKey, …) held in a plain
//     string rather than a *secmem.SecureBuffer.
//
// # Suppression
//
// Any finding can be suppressed with a //nolint:secmem-lint comment on the
// reported line, for the deliberate egress points a secret sometimes needs.
//
// # Scope and limits
//
// This is a high-signal tripwire over DIRECT escapes of the borrowed
// identifier, at the same altitude as go vet — not a proof of non-escape. It
// does not follow the slice through a helper function, across assignments it
// cannot resolve, or through reflection. It reports where a secret provably
// leaves the closure, not everywhere one might.
//
// # Usage
//
//	go install github.com/deadpoets/secmem/secmem-lint/cmd/secmem-lint@latest
//	go vet -vettool=$(command -v secmem-lint) ./...
package secmemlint
