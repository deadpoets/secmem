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
  `buf.WithBytes(leak)`, including a generic one (`func leak[T ~[]byte](b T)`)
  passed by name or explicitly instantiated (`leak[[]byte]`): the borrowed
  parameters are decided on the signature instantiated at the call, where `T`
  is a `[]byte`.

The accessor itself may be called directly, as a method expression
(`(*secmem.SecureBuffer).WithBytes(buf, fn)`), or through a local variable
holding the method value — bound once (`f := buf.WithBytes; f(...)`), or bound
several times to borrowing accessors of several receivers (the closure is
borrowed whichever runs, so its escapes are checked; only the receiver's
identity is unknown, so the reentrancy check stays silent). The receiver must
be a secmem / secmem-crypto type, **or** an interface whose `WithBytes` /
`WithBytesErr` / `WithScalar` / `WithSeed` / `WithDER` has the borrowing shape
(one func parameter taking a `[]byte`) — that heuristic exists because a
`*SecureBuffer` behind an interface is still the buffer; a concrete type from
another package with a look-alike method is not matched.

Anything else — a closure returned by a call (`buf.WithBytes(wrap(fn))`), a
method value or struct field passed as the closure, a closure variable
assigned more than once, a function from another package — is **not
checked**, and neither is a literal passed through a variable that is a
borrowing method value on some assignments and something else on others.
Default mode is silent about both; `-strict` reports them ("borrowed closure
is not a function literal and cannot be checked", "closure passed through a
variable that is sometimes a borrowing method value and sometimes not") so a
project can see where its coverage ends.

Inside a resolved body the analyzer tracks the borrowed `[]byte` parameters
(by resolved type, so `type raw = []byte` counts) as **tainted**, and
propagates taint to every local declared inside the closure that is assigned a
tainted value: an alias or sub-slice, an element, a conversion (`any(b)`,
`[]byte(b)`), a composite holding it (`holder{b}`, `[]any{b}`,
`map[string][]byte{"k": b}`), `&`, `append` / `copy` into local memory,
`unsafe.String` / `SliceData` / `Slice` / `Pointer`, `reflect.ValueOf`,
`bytes.NewReader` / `NewBuffer` / `strings.NewReader` / `bufio.NewReader` /
`io.NopCloser` / `context.WithValue` (which retain their argument), the
`bytes` / `slices` helpers that return a **window onto the same bytes**
(`bytes.TrimSpace` / `Trim*` / `Cut*` / `Split*` / `Fields*` / `Lines` /
`*Seq`, `slices.Clip` / `Grow` / `Delete*` / `Compact*` / `Insert` /
`Replace`), the element variable of a `range` over any tainted operand (slice,
array, string, map) and the received value of a `range` over a tainted channel,
the variables of a `range` over a tainted iterator function — the sole variable
of `for v := range seq`; of `for k, v := range seq2`, `v` always and `k` only
when its type is a `byte` or can otherwise hold bytes, so an integer index key
stays clean — a method call on a tainted value, or a func literal that captures
one. Lengths, comparisons and the address as a `uintptr` are not tainted.

## Checks

Default (always on):

| # | Flags |
|---|---|
| E1 | `string(tainted)` — a heap string is immutable and can never be wiped, wherever it goes |
| E2 | `append(dst, tainted...)` or `append(dst, tainted)` where `dst` is memory outside the closure; `copy(dst, tainted)` likewise |
| E3 | a tainted value assigned to a variable declared outside the closure, to a struct field, map or slice element, or pointer target whose storage is outside the closure (see the aggregate rule below); sent on a channel; returned from the closure (`return &myErr{b}`); or handed to a goroutine (`go f(b)`, `go func() { ... b ... }()`); `panic(tainted)` |
| E4 | a tainted value in **any** argument position of a known sink — or as the **receiver** of a sink method — see the table in [`sinks.go`](sinks.go): `fmt`'s print / format / append functions, `log`, `log/slog` (package functions including `slog.With`, `slog.Any` / `String` / `Group`, and `*Logger` methods including `With`), `testing.T` / `B` / `F` / `TB` log methods, `encoding/json` / `xml` / `gob` decoders, `json.Marshal` and the `Encoder.Encode` methods of all three, `encoding/hex` / `base64` / `base32` / `pem` encoders, the `bytes` / `slices` helpers that return a **heap copy** (`Clone`, `Concat`, `Join`, `Repeat`, `bytes.ToUpper` / `ToLower` / `ToTitle` / `Title` / `Map` / `Replace` / `ReplaceAll` / `ToValidUTF8` / `Runes`), `math/big.Int.SetBytes` / `SetString`, `os.WriteFile`, `Write` / `WriteString` on `*bytes.Buffer`, `*strings.Builder`, `*bufio.Writer` and `*os.File`, the retaining stores `sync.Map.Store` / `LoadOrStore` / `Swap` / `CompareAndSwap` and `Store` / `Swap` / `CompareAndSwap` on `atomic.Value` / `atomic.Pointer`, and the stdlib / `x/crypto` ciphers, key parsers and KDFs that copy the key into heap state (`aes.NewCipher`, `chacha20poly1305.New`, `hmac.New`, `ed25519.NewKeyFromSeed`, `ed25519.PrivateKey.Sign` / `Seed`, `x509.Parse*PrivateKey`, `ecdh.Curve.NewPrivateKey`, `hkdf` / `pbkdf2` / `scrypt` / `argon2` / `bcrypt`, …). A sink's result is not tainted again: one leak, one finding |
| R1 | a lock-taking secmem method called on the **same** buffer inside its own closure, synchronously. The borrowing and mutating methods take the buffer lock and are not reentrant; the read-only inspectors (`Len`, `MappedLen`, `IsSealed`, `IsDestroyed`) deadlock too once a writer is queued, because the lock is writer-preferring. The receiver is matched by identity through field chains, embedded-field promotions (`e.Len()` and `e.SecureBuffer.Len()` name the same buffer), local aliases bound once (`b2 := buf`) and method values bound once (`l := buf.Len`) |
| R2 | inside an `ArenaSlot` borrow: `Release` on the same slot, and `Destroy` / `ReadOnly` / `ReadWrite` on the slot's arena (they take the arena's exclusive lock, which the borrow holds for reading — a certain deadlock). The arena is known when the slot came from `slot, err := arena.Acquire()` in the same function; otherwise default mode is silent and `-strict` reports the call as unresolvable. `Acquire` and `LiveCount` take only the allocation mutex and are fine |

What is deliberately **not** flagged, because it is the recommended idiom:

- `copy` / `append` into another borrowed slice (the decrypt-into pattern,
  nested either way round), into a local slice / map / pointer whose every
  value is a fresh allocation (`make`, `new`, a literal, `&local`), or into
  an array or struct value declared inside the closure — and writes into the
  borrowed slice itself. The **aggregate rule**: a local struct or array
  value's own storage is inside, so `copy(arr[:], b)` and `s.tag[0] = b[0]`
  are clean; but a slice, pointer or map *held in* one of its fields or
  elements is wherever that reference points, so `copy(s.buf, b)` is inside
  only when every value ever stored at `s.buf` — by the initialiser, a
  literal, or an assignment to the field — is fresh (or a borrowed slice),
  and outside after `s.buf = callerSlice`, `arr[0] = out`,
  `q := pholder{p: outp}`, or once `arr[:]` has been taken (the slice can
  write `arr`'s elements);
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
| L1 | a locally constructed `SecureBuffer` / signer / key — `x, err := secmem.NewBuffer(…)` or `var x, err = secmem.NewBuffer(…)` — that is never `Destroy`ed and never handed off (returned or passed on) — add a `defer x.Destroy()` |
| N1 | a secret-named identifier (`password`, `token`, `apiKey`, …) held in a plain `string` rather than a `*secmem.SecureBuffer` |
| — | a borrowing closure the analyzer cannot resolve, a closure passed through a variable that is only sometimes a borrowing method value (both above), and an arena method inside a slot borrow whose arena it cannot identify |

## Suppress a finding

Put `//nolint:secmem-lint` on the reported line — for the deliberate egress
points a secret sometimes needs (persisting a generated key, a test that reads
a value out to assert on it). A bare `//nolint` and golangci-lint's
`//nolint:all` are honoured too, so a line one tool has excused is not failed
by the other:

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
- see into a closure it cannot resolve (call results, method values and
  fields passed as the closure, closure variables assigned more than once,
  other packages), or check a literal passed through a variable that is only
  sometimes a borrowing method value — `-strict` names them;
- flag a write through a local slice, map or pointer whose provenance it
  cannot see — bare, or held in a field or element of a local struct or array
  value: if every value ever stored there is not provably fresh (or a
  borrowed slice), a write through it is reported as **outside**, so an alias
  of outer memory is caught at the cost of a possible false positive on an
  unusual scratch buffer. Not followed, and therefore outside: a reference
  reached through a pointer, slice or map (`p.buf`, `hs[i].buf`, `*pp`), a
  struct copied from another variable (`l := m`), and the fields of a value
  whose address has been taken (`&s`, a slice of it — `arr[:]` is
  `(&arr)[:]`, so whoever holds the slice can write `arr`'s elements — or a
  pointer-receiver method call or method value on `s` — `s.m()`, `f := s.m`,
  `apply(s.m, x)` — since each is `(&s).m`). The remedy for such a false
  positive is to declare the scratch memory inside the closure as a local
  value or an array (`var a [32]byte; copy(a[:], b)` — slicing a byte array
  to write into its own storage is fine), or as a fresh slice held directly
  in a local (`t := make([]byte, n)`) or in a field of a local struct value
  (`s.buf = make([]byte, n)`), not behind a pointer, slice or map
  (`p := &holder{…}`, `ss[0]`, `m["k"]`), in the aggregate that is written
  through, and not to take its address;
- cover reflection or unsafe beyond the shapes listed: `reflect.ValueOf(b)`,
  `unsafe.String` / `SliceData` / `Slice` / `Pointer` are tracked as aliases,
  but a value laundered through further reflection or an `unsafe` pointer
  arithmetic is not;
- flag an interface-typed writer (`io.Writer`, `net.Conn`), a hash
  (`sha256.Sum256(b)`), or a `defer` — a deferred call runs before the closure
  returns, inside the lease;
- reason about another goroutine reading the buffer, about a different slot
  of the same arena borrowed inside a slot borrow, or about receivers written
  as index expressions or call results (`bufs[i]`, `getBuf()`) or reached
  through a method value bound to several receivers, whose identity it
  declines to guess.

It reports where a secret provably leaves the closure in one of the shapes
above — not everywhere one might.
