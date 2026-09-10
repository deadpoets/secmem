// Package secmemlint provides a go/analysis analyzer that flags secret material
// escaping a secmem borrowing closure.
//
// secmem hands out a secret's bytes only inside a borrowing closure — the
// argument to SecureBuffer.WithBytes / WithBytesErr, ArenaSlot.WithBytes /
// WithBytesErr and Secret.WithBytes (and the WithScalar / WithSeed / WithDER
// accessors in secmem-crypto). The library documents one rule for that slice:
// it is valid ONLY for the duration of the closure and must not be stored,
// copied into an escaping value, sent to another goroutine, or otherwise
// allowed to outlive the call. This analyzer detects the common shapes in
// which code breaks that rule, so a misuse fails at build time instead of
// leaking a secret to the GC heap at run time. It checks a bounded set of
// shapes; it does not prove that nothing escapes.
//
// # What is resolved
//
// A check runs on every accessor call whose closure resolves to a body: a func
// literal written inline, a local variable assigned exactly once to a func
// literal, or a function declared at package level in the same package. The
// accessor may be called directly or through a local method value bound once
// (f := buf.WithBytes). The receiver must be a secmem / secmem-crypto type or
// an interface whose WithBytes-family method has the borrowing shape (one func
// parameter taking a []byte). Anything else — a closure returned by a call, a
// method value or field, a variable assigned more than once, a function from
// another package — is not checked; -strict reports it.
//
// Inside a body the borrowed []byte parameters are tainted, and taint
// propagates to every local declared inside the closure that is assigned a
// tainted value: aliases and sub-slices, elements, conversions (any(b),
// []byte(b)), composites holding it, &, append / copy into local memory,
// unsafe.String / SliceData / Slice / Pointer, reflect.ValueOf, the retaining
// constructors bytes.NewReader / NewBuffer / strings.NewReader, method calls
// on a tainted value, and func literals that capture one. Lengths,
// comparisons and the slice's address as a uintptr are not tainted.
//
// # Checks
//
//   - string(tainted): a heap string can never be wiped.
//   - append(dst, tainted...) / append(dst, tainted) / copy(dst, tainted) where
//     dst is memory outside the closure.
//   - a tainted value assigned to a variable declared outside the closure, or
//     to a field / element / pointee whose memory is outside it; sent on a
//     channel; returned from the closure; handed to a goroutine; or passed to
//     panic.
//   - a tainted value in any argument of a known standard-library sink (the
//     table in sinks.go): fmt, log, log/slog and testing log methods, encoders
//     and decoders, bytes / slices copying helpers, os.WriteFile and the Write
//     methods of bytes.Buffer, strings.Builder, bufio.Writer and os.File, and
//     the ciphers, key parsers and KDFs that copy a key into heap state.
//     Interface-typed writers (io.Writer, net.Conn) are the intended egress
//     and are not flagged.
//   - a lock-taking secmem method called synchronously on the SAME buffer
//     inside its own closure, the receiver matched by identity through field
//     chains, single-assignment aliases and method values. The read-only
//     inspectors count too: the lock is writer-preferring, so a nested read
//     deadlocks once a writer is queued.
//   - inside an ArenaSlot borrow: Release on the same slot, and Destroy /
//     ReadOnly / ReadWrite on the slot's arena when the slot came from
//     slot, err := arena.Acquire() in the same function (they take the
//     arena's exclusive lock, which the borrow holds for reading).
//
// Not flagged, because it is the recommended idiom: copy or append into
// another borrowed slice (the decrypt-into pattern), into an array or struct
// declared inside the closure, or into a local slice whose every value is a
// fresh allocation; writes into the borrowed slice itself; and a func literal
// that calls the buffer but is only assigned, returned or launched with go.
//
// # Strict mode
//
// The -strict flag (off by default; `go vet -vettool=... -strict ./...`)
// enables the higher-noise, heuristic checks:
//
//   - a locally constructed SecureBuffer / signer / key that is never Destroyed
//     and never handed off (returned or passed on) — add a defer Destroy().
//   - a secret-named identifier (password, token, apiKey, …) held in a plain
//     string rather than a *secmem.SecureBuffer.
//   - a borrowing closure the analyzer cannot resolve, and an arena method
//     inside a slot borrow whose arena it cannot identify.
//
// # Suppression
//
// Any finding can be suppressed with a //nolint:secmem-lint comment on the
// reported line, for the deliberate egress points a secret sometimes needs.
//
// # Scope and limits
//
// This is a tripwire at the altitude of go vet, over a bounded set of shapes
// inside one closure body — not a proof of non-escape. It does not follow the
// slice into a function you call (keep(b) is not reported, and that call's
// result is not tainted), does not see into a closure it cannot resolve,
// treats a write through a local slice of unknown provenance as outside (so an
// alias of outer memory is caught, at the cost of a possible false positive on
// an unusual scratch buffer), covers reflection and unsafe only in the shapes
// listed, and declines to guess the identity of receivers written as index
// expressions or call results. It reports where a secret provably leaves the
// closure in one of those shapes, not everywhere one might.
//
// # Usage
//
//	go install github.com/deadpoets/secmem/secmem-lint/cmd/secmem-lint@latest
//	go vet -vettool=$(command -v secmem-lint) ./...
package secmemlint
