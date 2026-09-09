# Common pitfalls

These are the mistakes that quietly defeat secure-memory handling. Most of
them look fine and compile fine; that is exactly why they are dangerous. The
good news is that the common shapes of the most important one are caught for
you at compile time by [`secmem-lint`](secmem-lint/) — but knowing *why* each
is wrong is what keeps you from reintroducing it in a shape the linter can't
see (its README lists exactly which shapes it resolves).

Each entry is the mistake, why it defeats the protection, and the correct
form.

## 1. Letting the secret slice escape the borrow

This is the cardinal sin, and the one `secmem-lint` is built to catch at
compile time.

```go
// BAD — the borrowed slice escapes; now there is a heap copy that is never
// locked and never wiped, and the SecureBuffer's protections are moot.
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
off-heap location. An escaped slice is a second copy on the Go heap —
unlocked, unguarded, scanned by the collector, and never wiped: Go's GC does
not move heap objects, but it does not zero what it frees either, so the
bytes stay in the span until the allocator reuses it. `secmem-lint` flags
assignment-out, return, `append`, `copy` into outer memory, channel sends,
capture-by-goroutine, and the borrowed slice wrapped in a conversion,
composite or closure; it does not follow the slice into a helper you call.
Run it in CI.

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
`slog` through [`redact.NewHandler`](redact/) so credential-shaped strings, and
any attribute whose *key* is credential-shaped (`password`, `token`, `api_key`,
…) whatever its value looks like, are sanitized even when they reach the log
by another path. It is a backstop: a value split from its key across two
attributes, or a secret under an innocent key with no recognizable shape,
still gets through.

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
// it, and probably won't. And the key is the least of it: x/crypto's Argon2
// also leaves its whole working state behind — the 64 MiB matrix, the
// pre-hash one step from the password, per-goroutine scratch on stacks no
// wrapper can reach, and a BLAKE2b digest still holding the raw password.
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

## 8. Handing a token to an HTTP client as a string

```go
// BAD — the token is now a heap string held by the client for the life of
// the process: unlocked, unwiped, in every core dump.
token, _ := buf.ExposeString()
client := api.NewClient(token)
```

```go
// GOOD — inject per request from the SecureBuffer; the string exists for
// one request and the transport drops it as soon as the request completes.
client := &http.Client{Transport: httpauth.NewBearer(buf, nil, "api.example.com")}
```

Why it matters: every SDK takes the token as a `string` and keeps it, which
is pitfall 2 with the longest possible lifetime. `httpauth` bounds the copy to
one request, builds it inside a `Scrub` window, and wipes the scratch it was
assembled from. The per-request string is still a string — that residual is
stated in the package doc, not hidden. Always pass the API's host: the
transport sits below `http.Client`, so the Client's rule of dropping
`Authorization` on a cross-domain redirect does not cover what is injected
here, and with no host filter the credential follows the redirect. The host
filter is scheme-aware: the credential goes out over https only, and a plain
`http://` URL or an https→http redirect to a listed host fails with
`ErrInsecureScheme` rather than sending the token in the clear — opt in per
host with an `http://host` entry, or for all hosts with `AllowInsecureHTTP`.

## 9. Leaving a secret inside a decoded document

```go
// BAD — the password is now a heap string, and the whole response body
// still holds it too; neither can be wiped.
body, _ := io.ReadAll(resp.Body)
var cfg struct {
    DBPassword string `json:"db_password"`
}
json.Unmarshal(body, &cfg)
```

```go
// GOOD — the field's type takes the raw token straight into secure memory,
// and the document itself lives in a buffer, so no copy is left behind.
type secretField struct{ *secmem.SecureBuffer }

func (f *secretField) UnmarshalJSON(raw []byte) error {
    // raw is the quoted token, a sub-slice of the document being decoded.
    if len(raw) < 2 || raw[0] != '"' || bytes.IndexByte(raw, '\\') >= 0 {
        return errors.New("secret must be a plain JSON string")
    }
    buf, err := secmem.NewBuffer(raw[1 : len(raw)-1]) // copies, then wipes its input in place
    f.SecureBuffer = buf
    return err
}

doc, _, err := secmem.NewBufferFromReader(resp.Body, int(resp.ContentLength))
if err != nil { return err }
defer doc.Destroy()
var cfg struct {
    DBPassword secretField `json:"db_password"`
}
if err := doc.WithBytesErr(func(b []byte) error { return json.Unmarshal(b, &cfg) }); err != nil {
    return err
}
defer cfg.DBPassword.Destroy()
```

Why it matters: `Secret` deliberately has no `UnmarshalJSON`, because a
decoder that lands plaintext on the heap would be doing pitfall 2 for you,
invisibly. A field type of your own makes the copy explicit and puts it
where you want it. Two details carry the weight. `json.Unmarshal` hands an
`Unmarshaler` a sub-slice of the input, so when the input is a buffer the
token is read from locked memory and `NewBuffer` wipes that span in place;
`json.NewDecoder` instead reads into an internal buffer you can neither
reach nor wipe, so it is the wrong tool here. And `io.ReadAll` grows by
doubling, leaving the abandoned halves on the heap; read a known length
into a buffer, or into a `[]byte` you own and `SecureWipe` afterwards. What
remains is honest to state: a value with JSON escapes needs an explicit
unescape, which is a heap transient at that call site; and YAML and TOML
decoders copy tokens internally, so a secret in those formats is a residual
to record, or a reason to deliver it through a file or descriptor instead.

## 10. Writing to globals or caches inside a Scrub window

```go
// BAD — the window's stack and registers are erased on the way out; a
// global or a cache entry is reachable by definition, so it is exactly
// what survives.
var lastKey []byte

secmem.Scrub(func() {
    k := deriveOnStack(seed)
    lastKey = append([]byte(nil), k[:]...) // or: cache.Add(id, k[:])
})
```

```go
// GOOD — anything that must outlive the window goes into secure memory
// from inside it; the cache, if there is one, is keyed by public data.
secmem.Scrub(func() {
    k := deriveOnStack(seed)
    _, err = key.CopyIn(k[:], 0)
})
```

Why it matters: `Scrub` wipes the stack band its callback used and clears
the vector registers, and under `GOEXPERIMENT=runtimesecret` the runtime
also erases heap allocated inside the window once nothing refers to it. A
global, a package-level cache, a `sync.Map` or `sync.Pool` entry still
refers to it, by design, and the `runtime/secret` contract says so: erasure
does not extend to globals written by the callback or to goroutines it
starts. The same shape hides inside libraries. `crypto/ed25519`'s FIPS
code caches the private key it was given in a package-level structure no
wipe can reach, which is one reason `secmem-crypto` signs Ed25519 in place
rather than calling it. When a dependency caches what you hand it, either
do not hand it the key, or write the residual down.

---

Run `go vet ./...` and the `secmem-lint` analyzer in CI. The linter catches
the common shapes of pitfall 1 — the one with no visible symptom and the worst
consequence — before they ever ship.
