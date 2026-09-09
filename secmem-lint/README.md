# secmem-lint

A [`go/analysis`](https://pkg.go.dev/golang.org/x/tools/go/analysis) linter that
checks [secmem](https://github.com/deadpoets/secmem)'s borrowing-closure
discipline at **compile time**.

secmem hands a secret's bytes to your code only inside a borrowing closure — the
argument to `SecureBuffer.WithBytes` / `WithBytesErr`, `ArenaSlot.WithBytes` /
`WithBytesErr`, `Secret.WithBytes` (and `WithScalar` / `WithSeed` / `WithDER` in
`secmem-crypto`). That slice is valid **only** for the duration of the closure
and must not be stored, copied into an escaping value, sent to another
goroutine, or otherwise allowed to outlive the call. secmem documents that rule
and tests it for its own code at run time; this analyzer looks for the common
ways **your code** breaks it, so those fail to build instead of leaking a
secret to the heap. It detects a bounded set of shapes (listed below) — it is
not a proof that nothing escapes.

It is a standalone module that depends only on `golang.org/x/tools` and imports
neither secmem module, so it never enters your library's dependency graph.

## Install

```sh
go install github.com/deadpoets/secmem/secmem-lint/cmd/secmem-lint@latest
```

## Use

```sh
go vet -vettool=$(command -v secmem-lint) ./...
go vet -vettool=$(command -v secmem-lint) -strict ./...   # plus the opt-in checks
```

It exits non-zero when it finds anything, so it drops straight into CI or a
pre-commit hook. `go vet` forwards flags it does not own to the vettool, so the
analyzer's `-strict` is passed as written. The exported `Analyzer` can also be
embedded in a golangci-lint module plugin.

## What it looks at

A check runs on every call of a borrowing accessor whose closure it can resolve
to a body:

- a func literal written inline — `buf.WithBytes(func(b []byte) { ... })`;
- a local variable assigned **exactly once** to a func literal —
  `fn := func(b []byte) { ... }; buf.WithBytes(fn)`;
- a function declared at package level **in the same package** —
  `buf.WithBytes(leak)`.

The accessor itself may be called directly or through a local method value
bound once — `f := buf.WithBytes; f(...)`. The receiver must be a secmem /
secmem-crypto type, **or** an interface whose `WithBytes` / `WithBytesErr` /
`WithScalar` / `WithSeed` / `WithDER` has the borrowing shape (one func
parameter taking a `[]byte`) — that heuristic exists because a
`*SecureBuffer` behind an interface is still the buffer; a concrete type from
another package with a look-alike method is not matched.

Anything else — a closure returned by a call (`buf.WithBytes(wrap(fn))`), a
method value or struct field, a variable assigned more than once, a function
from another package — is **not checked**. Default mode is silent about it;
`-strict` reports "borrowed closure is not a function literal and cannot be
checked" so a project can see where its coverage ends.

Inside a resolved body the analyzer tracks the borrowed `[]byte` parameters
(by resolved type, so `type raw = []byte` counts) as **tainted**, and
propagates taint to every local declared inside the closure that is assigned a
tainted value: an alias or sub-slice, an element, a conversion (`any(b)`,
`[]byte(b)`), a composite holding it (`holder{b}`, `[]any{b}`,
`map[string][]byte{"k": b}`), `&`, `append` / `copy` into local memory,
`unsafe.String` / `SliceData` / `Slice` / `Pointer`, `reflect.ValueOf`,
`bytes.NewReader` / `NewBuffer` / `strings.NewReader` (which retain their
argument), a method call on a tainted value, or a func literal that captures
one. Lengths, comparisons and the address as a `uintptr` are not tainted.

## Checks

Default (always on):

| # | Flags |
|---|---|
| E1 | `string(tainted)` — a heap string is immutable and can never be wiped, wherever it goes |
| E2 | `append(dst, tainted...)` or `append(dst, tainted)` where `dst` is memory outside the closure; `copy(dst, tainted)` likewise |
| E3 | a tainted value assigned to a variable declared outside the closure, to a struct field, map or slice element, or pointer target whose memory is outside the closure; sent on a channel; returned from the closure (`return &myErr{b}`); or handed to a goroutine (`go f(b)`, `go func() { ... b ... }()`); `panic(tainted)` |
| E4 | a tainted value in **any** argument position of a known sink — see the table in [`sinks.go`](sinks.go): `fmt`'s print / format / append functions, `log`, `log/slog` (package functions, `slog.Any` / `String` / `Group`, and `*Logger` methods including `With`), `testing.T` / `B` / `F` / `TB` log methods, `encoding/json` / `xml` / `gob` decoders and `json.Marshal`, `encoding/hex` / `base64` / `base32` / `pem` encoders, `bytes` / `slices` copying helpers (`Clone`, `Concat`, `Join`, `Repeat`), `os.WriteFile`, `Write` / `WriteString` on `*bytes.Buffer`, `*strings.Builder`, `*bufio.Writer` and `*os.File`, and the stdlib / `x/crypto` ciphers, key parsers and KDFs that copy the key into heap state (`aes.NewCipher`, `chacha20poly1305.New`, `hmac.New`, `ed25519.NewKeyFromSeed`, `x509.Parse*PrivateKey`, `ecdh.Curve.NewPrivateKey`, `hkdf` / `pbkdf2` / `scrypt` / `argon2` / `bcrypt`, …) |
| R1 | a lock-taking secmem method called on the **same** buffer inside its own closure, synchronously. The borrowing and mutating methods take the buffer lock and are not reentrant; the read-only inspectors (`Len`, `MappedLen`, `IsSealed`, `IsDestroyed`) deadlock too once a writer is queued, because the lock is writer-preferring. The receiver is matched by identity through field chains, local aliases bound once (`b2 := buf`) and method values bound once (`l := buf.Len`) |
| R2 | inside an `ArenaSlot` borrow: `Release` on the same slot, and `Destroy` / `ReadOnly` / `ReadWrite` on the slot's arena (they take the arena's exclusive lock, which the borrow holds for reading — a certain deadlock). The arena is known when the slot came from `slot, err := arena.Acquire()` in the same function; otherwise default mode is silent and `-strict` reports the call as unresolvable. `Acquire` and `LiveCount` take only the allocation mutex and are fine |

What is deliberately **not** flagged, because it is the recommended idiom:

- `copy` / `append` into another borrowed slice (the decrypt-into pattern,
  nested either way round), into an array or struct declared inside the
  closure, or into a local slice / map / pointer whose every value is a fresh
  allocation (`make`, `new`, a literal, `&local`) — and writes into the
  borrowed slice itself;
- `w.Write(b)` on an `io.Writer`, `io.Reader` or `net.Conn` interface value:
  writing the secret to a connection is the egress the program exists for, and
  the analyzer cannot tell a socket from a `bytes.Buffer` behind the interface.
  Name the concrete type to be told;
- a func literal that calls the buffer but is only assigned, returned or
  launched with `go` — it runs after the lease, not inside it;
- `len(b)`, `cap(b)`, comparisons, and the slice's address as a `uintptr`.

Strict (`-strict`, opt-in — heuristic and higher-noise):

| # | Flags |
|---|---|
| L1 | a locally constructed `SecureBuffer` / signer / key that is never `Destroy`ed and never handed off (returned or passed on) — add a `defer x.Destroy()` |
| N1 | a secret-named identifier (`password`, `token`, `apiKey`, …) held in a plain `string` rather than a `*secmem.SecureBuffer` |
| — | a borrowing closure the analyzer cannot resolve (see above), and an arena method inside a slot borrow whose arena it cannot identify |

## Suppress a finding

Put `//nolint:secmem-lint` on the reported line — for the deliberate egress
points a secret sometimes needs (persisting a generated key, a test that reads
a value out to assert on it):

```go
buf.WithBytes(func(b []byte) {
    stored = string(b) //nolint:secmem-lint // deliberate egress; caller now owns and must wipe it
})
```

## Scope and limits

This is a tripwire at the altitude of `go vet`, over a **bounded set of
shapes** inside one closure body. It does not prove non-escape, and it is
silent — by default — wherever it cannot decide. Specifically it does **not**:

- follow the slice into a function you call: `keep(b)` is not reported, and
  a value that call returns is not tainted (the exception is the sink table
  and the retaining constructors listed above). Interprocedural analysis is
  out of scope; keep the helpers that touch borrowed bytes small enough to
  read;
- see into a closure it cannot resolve (call results, method values, fields,
  variables assigned more than once, other packages) — `-strict` names them;
- flag a write into a local slice, map or pointer whose provenance it cannot
  see: if a local is not provably fresh, a write through it is reported as
  **outside**, so an alias of outer memory is caught at the cost of a possible
  false positive on an unusual scratch buffer. Declare scratch memory inside
  the closure with `make` or as an array;
- cover reflection or unsafe beyond the shapes listed: `reflect.ValueOf(b)`,
  `unsafe.String` / `SliceData` / `Slice` / `Pointer` are tracked as aliases,
  but a value laundered through further reflection or an `unsafe` pointer
  arithmetic is not;
- flag an interface-typed writer (`io.Writer`, `net.Conn`), a hash
  (`sha256.Sum256(b)`), or a `defer` — a deferred call runs before the closure
  returns, inside the lease;
- reason about another goroutine reading the buffer, about a different slot
  of the same arena borrowed inside a slot borrow, or about receivers written
  as index expressions or call results (`bufs[i]`, `getBuf()`), whose identity
  it declines to guess.

It reports where a secret provably leaves the closure in one of the shapes
above — not everywhere one might.
