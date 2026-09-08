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
| `Ed25519Signer` | a `crypto.Signer` whose seed never leaves secure memory; signs in place (see below) |
| `ECDSASigner`, `RSASigner` | `crypto.Signer`s whose durable key lives in a buffer. Each `Sign` re-materialises the key on the heap through the standard library and wipes the transient it can reach; the copies it cannot reach are named in the type docs |
| `AsSSH`, `MarshalOpenSSHPrivateKey`, `MarshalOpenSSHPrivateKeyWithPassphrase`, `…WithPassphraseParams` | an `ssh.Signer` adapter that never offers SHA-1 `ssh-rsa`; Ed25519 export in OpenSSH private-key format, unencrypted or passphrase-protected, assembled and encrypted in place into a buffer. The `Params` form takes the bcrypt cost (ssh-keygen's `-a`), capped where the readers cap it so a written file always opens |
| `ParsePrivateKey`, `ParsePrivateKeyWithPassphrase` | the ingress: an OpenSSH, PKCS#8, SEC 1, or PKCS#1 key file parsed with the base64 decoded into a buffer and the structure read in place, so the seed, scalar, or DER is copied once, into the buffer the signer keeps; the file's public key is checked against the derived one. Passphrase-protected OpenSSH files (bcrypt, aes256-ctr/cbc — what ssh-keygen writes) open through the bcrypt_pbkdf fork below, with the AES round keys wiped by reflection; PKCS#8 PBES2 and legacy PEM encryption are refused |
| `HKDFInto`, `HMACInto` (and `*SHA256Into`) | RFC 5869 / RFC 4231 derivation straight into a buffer |
| `Argon2Into`, `Argon2IDKeyInto`, `Argon2DeriveInto` | Argon2 on an in-tree fork that wipes its whole working state (see below); RFC 9106 K/X inputs, §4 defaults, §5 vectors |
| `Argon2Workspace`, `Argon2Pool` | the same derivation with the working state in a locked, registered buffer, reused across calls; fails closed when the lock budget is too small |
| `BcryptPBKDFInto` | OpenSSH's bcrypt_pbkdf, on the fork below, with its whole working state in a locked buffer; for interoperating with that format, not as a password KDF chosen fresh (it is not memory-hard — use Argon2) |
| `OpenInto`, `SealFrom` | AEAD decrypt into / encrypt from secure memory; `OpenInto` errors rather than succeeding on an AEAD that did not write in place |
| `X25519Key` | key agreement with the private scalar in a buffer; the shared secret comes back in one |
| `MLKEM768Key`, `Encapsulate` | ML-KEM-768 with the 64-byte seed in a buffer; the expanded decapsulation key transits the heap per operation, as the type doc states |
| `GenerateDicewarePassphrase` | assembled in the buffer's own memory, no intermediate string; every draw reads the whole wordlist |
| `WipeEd25519Scalar` | reaches `edwards25519.Scalar`'s unexported fields |

## The parts that should make you look twice

Three pieces of this module do what a security reviewer is right to be
suspicious of: one reimplements a signature scheme, two fork cryptographic
libraries. Each reason is stated here, up front.

### An in-place Ed25519 signer

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

### A fork of `golang.org/x/crypto/argon2`

`internal/argon2/` is a modified copy of x/crypto v0.56.0's Argon2
(BSD-3-Clause; licence and patent grant alongside it, provenance in `NOTICE`,
every change listed in the package doc). Upstream leaves its whole working
state behind — the 64 MiB matrix, the pre-hash H0, a scratch block on each
worker goroutine's stack, and a BLAKE2b digest holding the raw password —
and no wrapper can reach it: `runtime/secret.Do` does not extend to
goroutines the wrapped function spawns. The fork keeps every piece of that
state in one workspace, wipes it before returning, computes the BLAKE2b
steps on the stack, and runs each worker inside its own `Scrub` window.

The output is byte-identical to upstream. That is pinned by the RFC 9106 §5
vectors for all three variants, a differential table and fuzz target against
x/crypto, and an identity test that compares the forked assembly and the
verbatim-copied functions against the resolved x/crypto module, so a
dependency bump that changes them fails CI. The changes were not proposed
upstream: they depend on secmem's wipe and scrub windows, and the upstream
issues asking for K/X and a caller-supplied buffer are closed or on hold.

If you would rather not depend on a fork, `golang.org/x/crypto/argon2` still
works with a `SecureBuffer` output via a copy; what you give up is the wipe
of the working state, which is what the fork exists for.

### A fork of `golang.org/x/crypto/ssh/internal/bcrypt_pbkdf` (and `blowfish`)

`internal/bcryptpbkdf/` is a modified copy of x/crypto v0.56.0's
bcrypt_pbkdf — the KDF that protects OpenSSH private-key files — together
with the Blowfish it is built on (same licence, provenance and change list
as above). Upstream is an internal package nothing can reach, and it leaves
the passphrase in a heap SHA-512 digest, a 4 KiB Blowfish key schedule
derived from it on the heap for every bcrypt step, and the derived key and
IV in a slice the caller cannot wipe. The fork keeps all of that in one
caller-owned workspace — a `SecureBuffer` in this module — re-keys the
schedule in place, hashes with one-shots, and writes into the caller's
slice. Because the fork exists anyway, the algorithm is exposed as
`BcryptPBKDFInto` for callers who need bcrypt_pbkdf itself and would
otherwise have to vendor x/crypto's internal package; its doc says plainly
that Argon2 is the better choice where the format does not dictate this
one. It is about 550 lines; the Feistel round, key schedule and constant
tables are verbatim and identity-tested against the resolved x/crypto, and
the output is pinned by OpenBSD's reference vectors, a differential test
against `x/crypto/blowfish`, and interop both ways with ssh-keygen and
x/crypto/ssh. What the fork cannot fix is the AES key schedule, which
`crypto/aes` allocates itself; that is wiped by reflection through the
type's unexported fields, with a tripwire test and a call that fails closed
when the layout it expects is not there.

## Pure Ed25519 only

Ed25519ph and Ed25519ctx requests are **refused**, not silently signed as pure
Ed25519. A signature over the wrong scheme is worse than no signature.

## What this will not support

Some refusals here are gaps, and some are decisions. They look the same to a
caller unless the library says which is which, so it does: a refusal that will
never become support wraps `ErrRetiredAlgorithm`, and one that is merely
unimplemented does not. Test for it when you need to tell "convert the file"
from "wait for a release".

**Legacy PEM encryption** — the `Proc-Type: 4,ENCRYPTED` / `DEK-Info:` headers
openssl wrote before PKCS#8, and ssh-keygen before the OpenSSH format — is
refused permanently, whatever cipher the `DEK-Info` line names. The key comes
from a single pass of MD5 over the passphrase and an 8-byte salt
(`EVP_BytesToKey`): there is no cost parameter, so an offline guess costs one
MD5, and the ciphertext is unauthenticated CBC, so it is malleable and offers
a padding oracle to anything that reports a decryption failure. Reading such a
file is not a service to whoever holds it — keeping it openable is what lets
it stay unconverted. `ssh-keygen -p -f key` and `openssl pkey -in key -out
key` both rewrite one into a format this package reads, and the error says so.

The same reasoning is why `AsSSH` never offers SHA-1 `ssh-rsa` and why
Ed25519ph and Ed25519ctx are refused above.

What is **not** in this category, and may yet arrive: PKCS#8 PBES2
(PBKDF2/scrypt), `chacha20-poly1305@openssh.com`, and the aes128 and aes192
OpenSSH ciphers. Those need forks that wipe their working state, which is
work, not a judgement.

## Versioning

This module is versioned and tagged independently of the core, as
`secmem-crypto/vX.Y.Z`. Its exported API hands back `*secmem.SecureBuffer`
values, so raising its `secmem` floor raises the minimum for every consumer —
which is why a dependency-only change here is a minor bump rather than a patch.

`secmem-crypto/v0.3.0` is **retracted**: it was tagged from a commit predating
its own `go.mod` floor raise and still requires `secmem` v0.2.0. Use v0.3.1 or
later. See [CHANGELOG.md](../CHANGELOG.md).

## Dependencies

`filippo.io/edwards25519`, `golang.org/x/crypto` and `golang.org/x/sys` (the
CPU-feature check for the Argon2 fork's SSE path), plus the core module. Pure
Go, `CGO_ENABLED=0`. Third-party material embedded under other licences (the
EFF wordlist, the Argon2 and bcrypt_pbkdf forks) is itemised in `NOTICE`.
