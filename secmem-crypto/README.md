# secmem-crypto

Cryptographic operations that keep their key material inside a
[`secmem.SecureBuffer`](https://pkg.go.dev/github.com/deadpoets/secmem#SecureBuffer)
— off the Go heap, in OS-locked pages, wiped on release — for the whole of the
operation, not just on either side of it.

```sh
go get github.com/deadpoets/secmem/secmem-crypto
```

> **Not independently audited.** This module has had no third-party security
> review. Every claim here is self-verified by the test suite that runs in CI,
> and self-verification is not an audit. See
> [SECURITY.md](../SECURITY.md) and, for what the memory guarantees do and do
> not cover, [THREAT-MODEL.md](../THREAT-MODEL.md).

## Why this module exists at all

The standard library is the right answer for almost everything, and where it is,
this module does not replace it. The gap it fills is narrow and specific: Go's
crypto APIs generally want key material as an ordinary `[]byte` or a struct on
the heap. Handing them a secret means copying it out of protected memory, at
which point the GC may move it, a heap dump contains it, and the wipe cannot
reach every copy.

So each function here derives, signs, or decrypts **into or out of** a
`SecureBuffer` directly:

| | |
|---|---|
| `Ed25519Signer` | a `crypto.Signer` whose seed never leaves secure memory |
| `HKDFInto`, `HMACInto` | RFC 5869 / RFC 4231 derivation straight into a buffer |
| `Argon2IDKeyInto`, `Argon2DeriveInto` | RFC 9106 §4 defaults, validated costs |
| `OpenInto`, `SealFrom` | AEAD decrypt into / encrypt from secure memory |
| `X25519Key`, `MLKEM*` | key agreement with the private scalar held in a buffer |
| `GenerateDicewarePassphrase` | assembled in the buffer's own memory, no intermediate string |
| `WipeEd25519Scalar` | reaches `edwards25519.Scalar`'s unexported fields |

## The part that should make you look twice

`ed25519direct.go` implements RFC 8032 signing **in place** rather than calling
`crypto/ed25519.Sign`. Rolling your own Ed25519 is normally the wrong answer and
a reasonable reviewer should stop here, so the reason is stated up front rather
than buried in a file comment:

`crypto/ed25519`'s FIPS-140 code path caches a private key in a package-level
structure keyed by a `weak.Pointer`. That cache is not reachable by any wipe
this library can perform, and on mmap'd memory the interaction **panics**
outright. Calling the stdlib signer with a seed that lives in a `SecureBuffer`
is therefore not merely leaky, it does not work.

The implementation follows RFC 8032 §5.1.6 and is verified against the RFC's own
test vectors, cross-checked signature-for-signature against `crypto/ed25519`
output for identical inputs, and fuzzed through a state-machine lifecycle
harness. It uses `filippo.io/edwards25519` for the group arithmetic — the same
primitive the standard library uses — so what is reimplemented here is the
message-assembly and scalar-handling around it, not the curve maths.

If that trade is not one you want to make, use `crypto/ed25519` with an ordinary
key and accept the heap copy. That is a legitimate choice and this module does
not pretend otherwise.

## Pure Ed25519 only

Ed25519ph and Ed25519ctx requests are **refused**, not silently signed as pure
Ed25519. A signature over the wrong scheme is worse than no signature.

## Versioning

This module is versioned and tagged independently of the core, as
`secmem-crypto/vX.Y.Z`. Its exported API hands back `*secmem.SecureBuffer`
values, so raising its `secmem` floor raises the minimum for every consumer —
which is why a dependency-only change here is a minor bump rather than a patch.

`secmem-crypto/v0.3.0` is **retracted**: it was tagged from a commit predating
its own `go.mod` floor raise and still requires `secmem` v0.2.0. Use v0.3.1 or
later. See [CHANGELOG.md](../CHANGELOG.md).

## Dependencies

`filippo.io/edwards25519` and `golang.org/x/crypto`, plus the core module. Pure
Go, `CGO_ENABLED=0`.
