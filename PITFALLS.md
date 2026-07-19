# Common pitfalls

These are the mistakes that quietly defeat secure-memory handling. Most of
them look fine and compile fine; that is exactly why they are dangerous. The
good news is that the most important one is caught for you at compile time by
[`secmem-lint`](secmem-lint/) — but knowing *why* each is wrong is what keeps
you from reintroducing it in a shape the linter can't see.

Each entry is the mistake, why it defeats the protection, and the correct
form.

## 1. Letting the secret slice escape the borrow

This is the cardinal sin, and the one `secmem-lint` rejects at compile time.

```go
// BAD — the borrowed slice escapes; now there is a heap copy the GC can
// move and never wipe, and the SecureBuffer's protections are moot.
var leaked []byte
buf.WithBytes(func(b []byte) {
    leaked = b            // escape by aliasing
})
use(leaked)              // ... or: return b, or append(dst, b...), or go f(b)
```

```go
// GOOD — do the work inside the closure; nothing secret leaves it.
buf.WithBytes(func(b []byte) {
    use(b)
})
// If you must move bytes out, copy them into ANOTHER SecureBuffer, never a []byte.
```

Why it matters: the entire premise is that the secret exists in exactly one
off-heap location. An escaped slice is a second copy on the Go heap — movable,
scannable, and never wiped. `secmem-lint` flags assignment-out, return,
`append`, and capture-by-goroutine of the borrowed slice; run it in CI.

## 2. Converting the secret to a string

```go
// BAD — string(b) copies the secret onto the heap as an immutable value you
// can never wipe (you must not mutate a Go string).
s := string(b)
```

```go
// GOOD — if you need a string-shaped read, use ExposeString, understand it
// snapshots under the read lock, and keep its lifetime as short as possible;
// prefer staying in []byte inside WithBytes.
str, err := buf.ExposeString()
```

Why it matters: strings are immutable in Go, so a secret-turned-string can
never be zeroed and lingers until the GC reclaims it. `ExposeString` exists
for the cases that truly need it and documents the trade-off; reaching for
`string(b)` yourself is the silent version.

## 3. Printing or logging the secret type the "obvious" way

```go
// This is actually SAFE — Secret/SecureBuffer redact themselves.
log.Printf("token = %v", secret)     // -> token = [REDACTED]
slog.Info("auth", "token", secret)   // -> token=[REDACTED]
```

```go
// BAD — logging the EXPOSED bytes bypasses the redaction entirely.
buf.WithBytes(func(b []byte) {
    log.Printf("token = %s", b)      // prints the real secret
})
```

Why it matters: the redaction lives on the wrapper type, not on the bytes.
The moment you borrow the raw bytes and hand *those* to a formatter, you have
opted out. For defense in depth on everything else your program logs, route
`slog` through [`redact.NewHandler`](redact/) so credential-shaped strings are
sanitized even when they reach the log by another path.

## 4. Forgetting to Destroy (or Destroying at the wrong time)

```go
// BAD — no Destroy; relies on the janitor finalizer, which wipes LATE and
// only if the program keeps running long enough for the GC to notice.
buf, _ := secmem.NewEmptyBuffer(32)
useThenDrop(buf)
```

```go
// GOOD — deterministic teardown.
buf, err := secmem.NewEmptyBuffer(32)
if err != nil { return err }
defer buf.Destroy()

// BETTER for a scoped secret — Scope destroys it for you on every path.
secmem.Scope(32, func(buf *secmem.SecureBuffer) error {
    return useThenDrop(buf)
})
```

Why it matters: `Destroy` is the deterministic wipe. The janitor and
termination-wipe are backstops for the paths you missed, not the plan.
`Destroy` works correctly on sealed and read-only buffers — it restores write
access internally before wiping — so you do not need to `Unseal`/`ReadWrite`
first.

## 5. Mutating a read-only or sealed buffer

```go
// BAD — after ReadOnly(), a write returns ErrReadOnly; after Seal(), any
// access returns ErrSealed. Ignoring the error and assuming the write
// happened corrupts your logic (the buffer is unchanged).
buf.ReadOnly()
buf.SetByteAt(0, 0xFF)               // returns ErrReadOnly; nothing written
```

```go
// GOOD — restore the state you need, and check the error.
if err := buf.ReadWrite(); err != nil { return err }
if err := buf.SetByteAt(0, 0xFF); err != nil { return err }
```

Why it matters: `ReadOnly` and `Seal` are protections you asked for; the
mutating methods refuse rather than silently succeeding (and rather than
faulting on the protected page — see DESIGN.md). Always check the returned
error; a refused mutation that you treat as done is a logic bug.

## 6. Deriving keys into a plain []byte

```go
// BAD — the derived key lands on the heap; you now have to remember to wipe
// it, and probably won't.
key, _ := argon2.IDKey(pw, salt, t, m, p, 32)
```

```go
// GOOD — derive straight into secure memory (secmem-crypto).
key, err := secmem.NewEmptyBuffer(32)
if err != nil { return err }
defer key.Destroy()
if err := secmemcrypto.Argon2DeriveInto(pw, salt, key); err != nil { return err }
```

Why it matters: a KDF's output is as sensitive as the key it produces.
`secmem-crypto`'s `*Into` helpers write the derived material directly into a
`SecureBuffer` so it is never a heap `[]byte` you have to clean up by hand.
See [`examples/password-login`](examples/password-login/) for the full flow.

## 7. Comparing secrets with `==` or `bytes.Equal`

```go
// BAD — early-exit comparison leaks, via timing, how many leading bytes
// matched.
if bytes.Equal(candidate, stored) { ... }
```

```go
// GOOD — constant-time comparison.
ok, err := buf.ConstantTimeEqual(candidate)
```

Why it matters: authentication comparisons on secret material must not reveal
match length through timing. `SecureBuffer.ConstantTimeEqual` (and
`Secret.ConstantTimeEqual`) compare in constant time.

---

Run `go vet ./...` and the `secmem-lint` analyzer in CI. The linter catches
pitfall 1 — the one with no visible symptom and the worst consequence —
before it ever ships.
