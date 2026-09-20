# secmem-crypto

Cryptographic operations on key material held in a
[`secmem.SecureBuffer`](https://pkg.go.dev/github.com/deadpoets/secmem#SecureBuffer)
— off the Go heap, in OS-locked pages, wiped on release. Some of them keep
it there for the whole of the operation; the rest have to hand a copy to a
standard-library primitive that has no in-place API, wipe every copy they
can reach, and name the ones they cannot. Every entry point below carries
its class, and the section [What each signer actually buys
you](#what-each-signer-actually-buys-you) says what that class is worth on
your build. [PROTECTION.md](../PROTECTION.md) summarises both, with the
attacks each level leaves open.

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
`SecureBuffer` directly. The **class** column is the load-bearing part:

- **contained** — no copy of secret material reaches the Go heap at any
  point. Pinned by an allocation proof (`testing.AllocsPerRun == 0`, or a
  memory-profile attribution of every allocation to a non-secret site) or,
  where one heap object is unavoidable, by a tripwire test that it is
  located and wiped before return.
- **runtimesecret-only** — the operation copies the secret through heap
  objects a standard-library primitive allocates. Every such copy this
  module can reach is wiped before return; the ones it cannot are named in
  the type's doc. All of them are allocated inside a `Scrub` window, so on
  linux/amd64 or linux/arm64 built with `GOEXPERIMENT=runtimesecret` the
  runtime erases them — at the first garbage collection after they become
  unreachable, not when the operation returns. That can be two minutes in a
  quiet process, so a key used even once a second has a copy on the heap
  almost all the time; the residue test finds the copies after use on this
  build too, and gone only after collections. On every other build — Windows,
  macOS, Linux without the experiment — those copies are **transient on the
  heap**: reclaimed by the collector, never zeroed, readable in a heap dump or
  a swapped page until reused.

| | | class |
|---|---|---|
| `Ed25519Signer` | a `crypto.Signer` whose seed never leaves secure memory; signs in place (see below). One heap allocation per signature — the signature — for messages up to 4 KiB; a longer message puts its nonce pre-image on the heap, wiped before return | **contained** |
| `ECDSASigner`, `RSASigner` | `crypto.Signer`s whose durable key lives in a buffer. Each `Sign` re-materialises the key on the heap through the standard library and wipes every copy it can reach — the `big.Int` limbs and, for RSA, the standard library's FIPS-form key, by reflection with a tripwire; the copies it cannot reach are listed in the type docs and in the value table below. **Refused on a legacy build** with `ErrHeapTransients` unless the caller passes `AllowHeapTransients()` | **runtimesecret-only** |
| `AsSSH`, `MarshalOpenSSHPrivateKey`, `MarshalOpenSSHPrivateKeyWithPassphrase`, `…WithPassphraseParams` | an `ssh.Signer` adapter that never offers SHA-1 `ssh-rsa`; Ed25519 export in OpenSSH private-key format, unencrypted or passphrase-protected, assembled and encrypted in place into a buffer. The `Params` form takes the bcrypt cost (ssh-keygen's `-a`), capped where the readers cap it so a written file always opens. The passphrase form's one heap object, the AES key schedule, is wiped by reflection with a tripwire. `AsSSH` adds nothing of its own and inherits the class of the signer it wraps | **contained** (export) |
| `ParsePrivateKey`, `ParsePrivateKeyWithPassphrase` | the ingress: an OpenSSH, PKCS#8, SEC 1, or PKCS#1 key file parsed with the base64 decoded into a buffer and the structure read in place, so the seed, scalar, or DER is copied once, into the buffer the signer keeps; an OpenSSH RSA key's missing CRT exponents are computed over stack arrays, not with `math/big`; the file's public key is checked against the derived one. Passphrase-protected OpenSSH files (bcrypt, aes256-ctr/cbc — what ssh-keygen writes) open through the bcrypt_pbkdf fork below, with the AES round keys wiped by reflection; PKCS#8 PBES2 and legacy PEM encryption are refused. The parser is contained; what the `ECDSASigner` and `RSASigner` constructors then do with the scalar or DER is their own class, so an RSA or EC key file is refused on a legacy build without `AllowHeapTransients()`. Ed25519 files never are | **contained** (parser) |
| `HKDFInto`, `HMACInto` (and `*SHA256Into`) | RFC 5869 / RFC 2104 derivation straight into a buffer. Over SHA-2 or SHA-3 it runs in place: two of the standard library's one-shot hash calls per HMAC, whose digest state is a stack local, over a working region — the padded key, the message, the pseudorandom key — that is a stack array in the Scrub window up to about 1 KiB and a locked buffer beyond. The only allocation is the digest instance asked of the caller's constructor to identify the hash. Over any other hash it uses `crypto/hmac` and `x/crypto/hkdf`, whose heap objects hold the key, and is **refused on a legacy build** with `ErrHeapTransients` unless the caller passes `AllowHeapTransients()` | **contained** (SHA-2, SHA-3); **runtimesecret-only** (other hashes) |
| `Argon2Into`, `Argon2IDKeyInto`, `Argon2DeriveInto` | Argon2 on an in-tree fork that wipes its whole working state (see below); RFC 9106 K/X inputs, §4 defaults, §5 vectors. The working set is a heap allocation — pageable and dumpable during the call — that the fork wipes deterministically before returning | **contained** (heap workspace, wiped) |
| `Argon2Workspace`, `Argon2Pool` | the same derivation with the working state in a locked, registered buffer, reused across calls; fails closed when the lock budget is too small | **contained** |
| `BcryptPBKDFInto` | OpenSSH's bcrypt_pbkdf, on the fork below, with its whole working state in a locked buffer; for interoperating with that format, not as a password KDF chosen fresh (it is not memory-hard — use Argon2) | **contained** |
| `OpenInto`, `SealFrom` | AEAD decrypt into / encrypt from secure memory; `OpenInto` errors rather than succeeding on an AEAD that did not write in place. Zero allocations, both directions. They keep the **plaintext** off the heap; the AEAD's key is wherever the caller's `cipher.AEAD` keeps it — on the heap, for as long as that object lives, unless it came from `WithAESGCM` | **contained** (plaintext) |
| `WithAESGCM` | lends AES-GCM built from a key in a buffer to a callback, then wipes every copy of the key schedule — both round-key arrays of the `aes.Block`, their copy inside the GCM object, and its GHASH table — by reflection with a tripwire, on return, error or panic; the layout is checked before the key is expanded. The lent AEAD panics with `ErrAEADOutOfScope` if kept and used after the callback. Build it per use; sealing 1 KiB costs about 2.4 µs against 0.2 µs on a kept AEAD (`BenchmarkAESGCM`), mostly the cache-flushing wipe | **contained** (between uses) |
| `X25519Key` | key agreement with the private scalar in a buffer, used in place: the RFC 7748 ladder (the standard library's own, copied into `internal/x25519` and pinned to the toolchain's source) runs over the borrowed scalar inside a Scrub window and writes the shared secret straight into the buffer it returns. Nothing is allocated beyond that buffer | **contained** |
| `MLKEM768Key` | ML-KEM-768 with the 64-byte seed in a buffer. The expanded decapsulation key — which holds the seed verbatim and the secret polynomial `s` — is wiped by reflection with a tripwire after every expansion; the encapsulation key is computed once at construction; crypto/mlkem's hash states and polynomials stay on the stack in the Scrub window. What remains is the 32-byte message each `Decapsulate` recovers, a heap slice nothing can reach, which gives that ciphertext's shared key. **Refused on a legacy build** with `ErrHeapTransients` unless the caller passes `AllowHeapTransients()` | **contained** (the decapsulation key); **runtimesecret-only** (each decapsulation's shared key) |
| `Encapsulate` | the sender side: the shared key crypto/mlkem returns shares a heap slice with the encryption randomness, which recovers it from the public ciphertext, and the whole slice is wiped; the message and the digest that absorbs it stay on the stack in the Scrub window | **contained** |
| `GenerateDicewarePassphrase` | assembled in the buffer's own memory, no intermediate string; every draw reads the whole wordlist | **contained** |
| `WipeEd25519Scalar` | reaches `edwards25519.Scalar`'s unexported fields | — |

## What each signer actually buys you

The table above says where each entry point stands; this one says what that
is worth, per public type, on the two kinds of build. "Legacy" is any build
without `runtime/secret` — Windows, macOS, and Linux without
`GOEXPERIMENT=runtimesecret` — where the core's `Scrub` wipes a 32 KiB stack
band and the vector registers and nothing erases heap objects.
"runtimesecret" is linux/amd64 or linux/arm64 with the experiment, where
the runtime also erases every heap object allocated inside the window at the
first collection after it becomes unreachable. All counts are for go1.26.

| Type / function | Protected at rest | Per-operation copies, legacy build | Per-operation copies, runtimesecret build | Verdict, legacy | Verdict, runtimesecret |
|---|---|---|---|---|---|
| `Ed25519Signer` | 32-byte seed | none on the heap. Two stack copies of the seed inside `sha512.Sum512` and the scalars, points and nonce pre-image (≤ 4 KiB message) on the stack, all in the Scrub band; the pre-image of a longer message on the heap, wiped | same | The seed is protected for its whole life, and the only heap object a signature makes is the signature. This is the type the headline is true of | same |
| `ECDSASigner` | the scalar (28–66 bytes) | **wiped:** the `big.Int` D limbs. **not wiped:** the scalar's bytes in a fresh `[]byte`, in a `bigmod.Nat`, and in two FIPS-form keys — one dropped after the parse, one kept in `crypto/ecdsa`'s package-level cache until the collector evicts it, one to two GC cycles after `Sign` | the same objects, erased by the runtime at the first collection after they become unreachable; the cached one a collection after its eviction | The at-rest custody is real (the durable copy is locked, guard-paged, wiped on `Destroy`, and covered by `WipeAllSecrets`), but every signature leaves several unwiped copies of the scalar on the heap, one of them for a GC cycle or more. On a legacy build the buffer changes *where* the scalar is at rest, not whether it is in the heap dump of a process that signs | At rest; the copies of the last signatures are on the heap until the next collection, which for a key that signs often means almost always |
| `RSASigner` | the whole DER (1–2 KB) | **wiped:** all the `big.Int` limbs and the FIPS-form key (d, p, q with their Montgomery constants, dP, dQ, qInv). **not wiped:** the parse's `big.Int.Bytes()` copies of D, P, Q and Qinv, `Validate`'s comparison copies, and the signature's modular-arithmetic scratch (Montgomery tables built from p and q). `math/big`'s pooled scratch is not used for two-prime keys | the same, erased at the first collection after they become unreachable | As ECDSA, at a larger scale: the whole private key is rebuilt on the heap per signature and the copies nothing wipes are the size of the key. Same verdict — real at rest, not during use | same as ECDSA |
| `X25519Key` | 32-byte scalar | none on the heap: the clamped scalar and the ladder's field elements on the stack, in the Scrub band; the shared secret written into its buffer | same | contained | contained |
| `MLKEM768Key` | 64-byte seed | **wiped:** the expanded key (seed halves and `s`). **on the stack, in the Scrub band:** the SHA3/SHAKE states, σ and the key-generation polynomials. **not wiped:** the 32-byte message each decapsulation recovers, which gives that ciphertext's shared key | the message erased at the first collection after the call | the decapsulation key contained; each decapsulation's shared key exposed; refused unless opted in | the decapsulation key contained; each shared key exposed until the next collection |
| `Encapsulate` | the shared key it returns | none on the heap: the slice holding the shared key and the encryption randomness is wiped whole; the message and the digest that absorbs it are on the stack, in the Scrub band | same | contained | contained |
| `HKDFInto`, `HMACInto` | the output (the secret is the caller's to hold in a buffer) | SHA-2 / SHA-3: none on the heap — the padded key, the pseudorandom key and the digest states are on the stack in the Scrub band or in a locked buffer. Other hashes: refused unless opted in; then the key XORed into both pads and both digest states, in heap objects | SHA-2 / SHA-3: same. Other hashes: erased once unreachable | contained over SHA-2 and SHA-3 | contained over SHA-2 and SHA-3 |
| `Argon2Into` | output only | a heap workspace holding everything, wiped by the fork before return; dumpable and pageable during the call | same | contained, with a window during the call; use `Argon2Workspace` to close it | same |
| `Argon2Workspace`, `BcryptPBKDFInto`, `OpenInto`, `SealFrom`, the parsers | output / working set in locked memory | none on the heap | none | contained | contained |
| `WithAESGCM` | the AES key | during the callback, the round keys in the `aes.Block` and the GCM object on the heap; after it, none — all wiped before return | same | contained between uses; the schedule is on the heap only while the callback runs | same |

### RSASigner and ECDSASigner on a legacy build

On Windows, macOS or plain Linux, does keeping the durable key in a
`SecureBuffer` buy anything measurable, given the per-operation copies? The
two types share the answer: each rebuilds the private key through the
standard library on every signature.

- **What it buys:** the key at rest is in locked, guard-paged, dump-excluded
  memory; `Destroy` and `WipeAllSecrets` reach it; nothing reaches it by
  accident through a stray reference. A process that loads a key and signs
  rarely — a CA, a release-signing service — spends most of its life in that
  state.
- **What it does not buy:** any process that signs continuously has, at any
  moment, an unwiped copy of the key on the heap from the last
  operation, and for ECDSA a cached copy that lives until the collector runs
  its cleanup. A heap dump taken during or shortly after a signature has the
  key in it, buffer or no buffer.

So on a legacy build both types refuse by default. `NewRSASigner`,
`GenerateRSASigner`, `NewECDSASigner` and `GenerateECDSASigner` return an
error wrapping `ErrHeapTransients`, and so do `ParsePrivateKey` and
`ParsePrivateKeyWithPassphrase` for an RSA or EC key file, and
`NewMLKEM768Key` and `GenerateMLKEM768Key` (below). A caller who
accepts the residual says so where the key is built:

```go
signer, err := secmemcrypto.ParsePrivateKey(file, secmemcrypto.AllowHeapTransients())
```

The refusal is the default so that the choice is visible in the code that
makes it, not discovered later in a heap dump. It is checked before the key
is handed to the standard library, so a refused call makes none of the
copies it exists to prevent, and a buffer passed to a refused constructor
stays the caller's. On a `GOEXPERIMENT=runtimesecret` build nothing is
refused and the option has no effect. Ed25519 and X25519 keys are never
refused on any build, because this module operates on both in place.

When to opt in:

- **Reasonable:** load a key, use it rarely — a signing key for releases.
  The key spends almost all of its life with the locked copy as the only
  copy.
- **Not reasonable:** use it continuously — a TLS listener, a busy SSH agent,
  a token-issuing service. That process has the key on the heap at almost
  every moment, and the option only hides that. Build with the experiment,
  move the key to Ed25519, or keep it in an HSM or KMS.

This gate is permanent. Fixing RSA and ECDSA properly would mean forking the
standard library's `crypto/internal/fips140` signing paths and the `bigmod`
arithmetic under them into this module — thousands of lines where a mistake
leaks the key instead of failing a test — and that trade is not worth making.
[PROTECTION.md](../PROTECTION.md) states the decision and what to do instead.

**ML-KEM is gated too, for a different copy.** `MLKEM768Key`'s decapsulation
key is contained, but each `Decapsulate` leaves the message it recovers on the
heap, and that message gives the ciphertext's shared key — the session key,
not the long-term one. On a legacy build nothing erases it, so the type is
refused the same way, and the same rule for opting in applies with "session
keys" in place of "the key". `Encapsulate`, the sender side, leaves nothing
and is never refused. `HKDFInto` and `HMACInto` are gated per call rather
than per type: over SHA-2 and SHA-3 they run in place and are never refused,
and over any other hash they refuse on a legacy build unless given
`AllowHeapTransients()`.

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

Two other refusals are decisions of the same kind but do not carry the
marker, because there is no file to convert and nothing to wait for: `AsSSH`
never offers SHA-1 `ssh-rsa`, and `Sign` returns a plain error for Ed25519ph
and Ed25519ctx (above). `ErrRetiredAlgorithm` is for input this package
refuses to read; those two are things it refuses to produce.

What is **not** in this category, and may yet arrive: PKCS#8 PBES2
(PBKDF2/scrypt) and `chacha20-poly1305@openssh.com`. Those need forks that
wipe their working state, which is work, not a judgement.

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
