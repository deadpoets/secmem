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
// literal, or a function declared at package level in the same package —
// including a generic one (func leak[T ~[]byte](b T)), passed by name or
// explicitly instantiated (leak[[]byte]), whose borrowed parameters are
// decided on the signature instantiated at the call. The accessor may be
// called directly, as a method expression
// ((*secmem.SecureBuffer).WithBytes(buf, fn)), or through a local variable
// holding the method value: bound once (f := buf.WithBytes), or bound several
// times to borrowing accessors of several receivers, in which case the
// closure is checked for escapes but the receiver's identity is unknown and
// the reentrancy check stays silent. The receiver must be a secmem /
// secmem-crypto type or an interface whose WithBytes-family method has the
// borrowing shape (one func parameter taking a []byte). Anything else — a
// closure returned by a call, a method value or field passed as the closure,
// a closure variable assigned more than once, a function from another package,
// a literal passed through a variable that is a borrowing method value on some
// assignments and something else on others — is not checked; -strict reports
// it.
//
// Inside a body the borrowed []byte parameters are tainted, and taint
// propagates to every local declared inside the closure that is assigned a
// tainted value: aliases and sub-slices, elements, conversions (any(b),
// []byte(b)), composites holding it, &, append / copy into local memory,
// unsafe.String / SliceData / Slice / Pointer, reflect.ValueOf, the retaining
// constructors bytes.NewReader / NewBuffer / strings.NewReader / bufio.NewReader
// / io.NopCloser / context.WithValue, the bytes and slices helpers that return
// a window onto the same bytes (bytes.TrimSpace, Trim*, Cut*, Split*, Fields*,
// Lines and the *Seq iterators; slices.Clip, Grow, Delete*, Compact*, Insert,
// Replace), the element variable of a range over any tainted operand (slice,
// array, string, map) and the received value of a range over a tainted
// channel, the variables of a range over a tainted iterator function (the sole
// variable of for v := range seq; of for k, v := range seq2, v always and k
// only when its type is a byte or can otherwise hold bytes, so an integer index
// key stays clean), method calls on a tainted value, and func literals that
// capture one.
// Lengths, comparisons and the slice's address as a uintptr are not tainted,
// and neither is the result of a sink: a leak is reported once, at the sink.
//
// # Checks
//
//   - string(tainted): a heap string can never be wiped.
//   - append(dst, tainted...) / append(dst, tainted) / copy(dst, tainted) where
//     dst is memory outside the closure.
//   - a tainted value assigned to a variable declared outside the closure, or
//     to a field / element / pointee whose storage is outside it; sent on a
//     channel; returned from the closure; handed to a goroutine; or passed to
//     panic.
//   - a tainted value in any argument of a known standard-library sink, or as
//     the receiver of a sink method (the table in sinks.go): fmt, log, log/slog
//     (including the package-level slog.With) and testing log methods, the
//     encoding decoders, json.Marshal and the json / xml / gob Encoder.Encode
//     methods, the hex / base64 / base32 / pem encoders, the bytes / slices
//     helpers that return a heap copy (Clone, Concat, Join, Repeat, ToUpper,
//     ToLower, ToTitle, Title, Map, Replace, ReplaceAll, ToValidUTF8, Runes),
//     math/big.Int.SetBytes / SetString, os.WriteFile and the Write methods of
//     bytes.Buffer, strings.Builder, bufio.Writer and os.File, the retaining
//     stores of sync.Map, atomic.Value and atomic.Pointer, and the ciphers, key
//     parsers, KDFs and ed25519.PrivateKey methods that copy a key into heap
//     state. Interface-typed writers (io.Writer, net.Conn) are the intended
//     egress and are not flagged.
//   - a lock-taking secmem method called synchronously on the SAME buffer
//     inside its own closure, the receiver matched by identity through field
//     chains, embedded-field promotions (e.Len() and e.SecureBuffer.Len() are
//     the same buffer), single-assignment aliases and method values. The
//     read-only inspectors count too: the lock is writer-preferring, so a
//     nested read deadlocks once a writer is queued.
//   - inside an ArenaSlot borrow: Release on the same slot, and Destroy /
//     ReadOnly / ReadWrite on the slot's arena when the slot came from
//     slot, err := arena.Acquire() in the same function (they take the
//     arena's exclusive lock, which the borrow holds for reading).
//
// Not flagged, because it is the recommended idiom: copy or append into
// another borrowed slice (the decrypt-into pattern), into a local slice whose
// every value is a fresh allocation, or into an array or struct value declared
// inside the closure; writes into the borrowed slice itself; and a func
// literal that calls the buffer but is only assigned, returned or launched
// with go. A local struct or array value's OWN storage is inside, but a slice,
// pointer or map held in one of its fields or elements is wherever that
// reference points: copy(s.buf, b) is inside when every value ever stored at
// s.buf (by the initialiser, a literal or an assignment to the field) is fresh
// or a borrowed slice, and outside after s.buf = callerSlice or once arr[:]
// has been taken (the slice can write arr's elements).
//
// # Strict mode
//
// The -strict flag (off by default; `go vet -vettool=... -strict ./...`)
// enables the higher-noise, heuristic checks:
//
//   - a locally constructed SecureBuffer / signer / key — x, err := New…(…)
//     or var x, err = New…(…) — that is never Destroyed and never handed off
//     (returned or passed on): add a defer Destroy().
//   - a secret-named identifier (password, token, apiKey, …) held in a plain
//     string rather than a *secmem.SecureBuffer.
//   - a borrowing closure the analyzer cannot resolve, a closure passed through
//     a variable that is only sometimes a borrowing method value, and an arena
//     method inside a slot borrow whose arena it cannot identify.
//
// # Suppression
//
// Any finding can be suppressed with a //nolint:secmem-lint comment on the
// reported line, for the deliberate egress points a secret sometimes needs. A
// bare //nolint and golangci-lint's //nolint:all are honoured too.
//
// # Scope and limits
//
// This is a tripwire at the altitude of go vet, over a bounded set of shapes
// inside one closure body — not a proof of non-escape. It does not follow the
// slice into a function you call (keep(b) is not reported, and that call's
// result is not tainted), does not see into a closure it cannot resolve,
// treats a write through a local slice, map or pointer of unknown provenance
// as outside — whether the local is bare or held in a field or element of a
// local struct or array value; and a reference reached through a pointer,
// slice or map, a struct copied from another variable, or a field of a value
// whose address has been taken (&s, a slice of it — arr[:] is (&arr)[:] — or
// a pointer-receiver method call or method value on s, which is (&s).m) is
// never provably fresh — so an alias of outer memory is caught, at the cost of
// a possible false positive on an unusual scratch buffer, whose remedy is to
// declare the scratch as a local value or an array, or as a fresh slice held
// directly in a local or in a field of a local struct value rather than
// behind a pointer, slice or map; covers reflection and unsafe only in the
// shapes listed; and declines to guess the identity of receivers written as
// index expressions or call results, or reached through a method value bound
// to several receivers. It reports where a secret provably leaves the closure
// in one of those shapes, not everywhere one might.
//
// # Usage
//
//	go install github.com/deadpoets/secmem/secmem-lint/cmd/secmem-lint@latest
//	go vet -vettool=$(command -v secmem-lint) ./...
package secmemlint
