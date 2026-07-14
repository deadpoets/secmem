# secmem-lint

A [`go/analysis`](https://pkg.go.dev/golang.org/x/tools/go/analysis) linter that
enforces [secmem](https://github.com/deadpoets/secmem)'s borrowing-closure
discipline at **compile time**.

secmem hands a secret's bytes to your code only inside a borrowing closure — the
argument to `SecureBuffer.WithBytes` / `WithBytesErr` (and `WithScalar` /
`WithSeed` / `WithDER` in `secmem-crypto`). That slice is valid **only** for the
duration of the closure and must not be stored, copied into an escaping value,
sent to another goroutine, or otherwise allowed to outlive the call. secmem
documents that rule and proves it for its own code at run time; this analyzer
extends the guarantee to the one place the runtime tests can't reach — **your
code** — so a misuse fails to build instead of leaking a secret to the heap.

It is a standalone module that depends only on `golang.org/x/tools` and imports
neither secmem module, so it never enters your library's dependency graph.

## Install

```sh
go install github.com/deadpoets/secmem/secmem-lint/cmd/secmem-lint@latest
```

## Use

```sh
go vet -vettool=$(command -v secmem-lint) ./...
```

It exits non-zero when it finds anything, so it drops straight into CI or a
pre-commit hook. The exported `Analyzer` can also be embedded in a golangci-lint
module plugin.

## Checks

Default (always on) — the borrowed slice, tracked inside the closure:

| # | Flags |
|---|---|
| E1 | `string(borrowed)` — copies the secret to a heap string |
| E2 | `append(dst, borrowed...)` — spreads it into an escaping slice |
| E3 | `copy`, channel send, goroutine capture, or assignment to a variable declared outside the closure |
| E4 | borrowed bytes passed to a heap-copying or logging stdlib sink (`fmt`, `encoding/json`, `encoding/hex`, `encoding/base64`, `log`, `log/slog`, `crypto/ed25519.Sign`, `crypto/hmac.New`, `bytes`/`slices.Clone`) — the message names a secmem-native alternative where one exists |
| R1 | a secmem access method called on the **same** buffer inside its own closure (the accessors take the buffer lock and are not reentrant) |

Matching is **type-aware**: a check fires only when the method is declared on a
secmem / secmem-crypto type, so an unrelated `WithBytes` elsewhere is untouched.
The decrypt-into pattern (nesting a **different** buffer) is allowed.

Strict (`-strict`, opt-in — heuristic and higher-noise):

| # | Flags |
|---|---|
| L1 | a locally constructed `SecureBuffer` / signer / key that is never `Destroy`ed and never handed off (returned or passed on) — add a `defer x.Destroy()` |
| N1 | a secret-named identifier (`password`, `token`, `apiKey`, …) held in a plain `string` rather than a `*secmem.SecureBuffer` |

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

This is a **high-signal tripwire over direct escapes** of the borrowed
identifier, at the altitude of `go vet` — **not** a proof of non-escape. It does
not follow the slice through a helper function, across assignments it cannot
resolve, or through reflection. It reports where a secret provably leaves the
closure, not everywhere one might.
