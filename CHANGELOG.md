# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version is `0.x`, the public API may change between minor versions as
the surface settles; breaking changes will be called out here. `1.0.0` will
mark the stability commitment.

## [Unreleased]

> This repo holds three independently versioned Go modules; entries are tagged
> by module. Untagged entries belong to the core `secmem` module.

### Fixed

- **Read-only buffers and arenas no longer fault the process on a mutating
  call.** `ReadOnly()` sets the region to `PROT_READ`, but the mutating methods
  did not check for it, so a `SecureBuffer.CopyIn`, `SetByteAt`, `Truncate`, or
  `ReadFrom` — or an `ArenaSlot.Release`, which wipes the slot — issued after
  `ReadOnly()` wrote to the read-only page and crashed the process with SIGSEGV.
  They now return the new `ErrReadOnly` at the API boundary instead, honoring
  the "misuse returns an error, never crashes" contract. `Release` refuses
  without wiping — the slot stays acquired, and `ReadWrite` then `Release`, or
  `Destroy`, completes the wipe. Surfaced by the new lifecycle fuzzers.
- **Read-only state now survives a `Seal`/`Unseal` cycle on every platform.**
  The Windows seal cipher (`CryptProtectMemory`) encrypts in place, so `Seal()`
  on a read-only `SecureBuffer` failed there while succeeding on Linux. `Seal`
  now lifts the read-only protection for the encrypt and `Unseal` restores it,
  so a read-only buffer sealed for dormancy is still read-only when it wakes —
  the physical page protection always matches the flag.

### Added

- `ErrReadOnly` — the sentinel returned by the mutating methods and
  `ArenaSlot.Release` when the buffer or arena is in the read-only
  (`PROT_READ`) state. Call `ReadWrite` before mutating.
- `FuzzBufferLifecycle` and `FuzzArenaLifecycle` — state-machine fuzzers that
  drive a buffer or arena through arbitrary operation sequences against a
  model, asserting that misuse always returns the right sentinel and never
  panics or faults. They found the read-only faults fixed above.
- `DESIGN.md` — why the layered protections are arranged as they are — and
  `PITFALLS.md` — the common secure-memory mistakes and their correct forms.

## [secmem-lint/v0.1.0] - 2026-07-14

First tagged release of the `secmem-lint` module — a `go/analysis` analyzer
(and `cmd/secmem-lint` vet tool) enforcing secmem's borrowing-closure
discipline at compile time: the slice borrowed from `WithBytes`/`WithBytesErr`
(and `WithScalar`/`WithSeed`/`WithDER` in `secmem-crypto`) must not escape the
closure. Default checks cover `string()` conversion, append-spread, copy /
channel / goroutine / assign-to-outer escape, and dangerous stdlib sinks;
`-strict` adds the same-buffer-reentrancy (R1) and secret-in-plain-string (N1)
checks. Its own module (`golang.org/x/tools` only), so it adds nothing to
either library module's dependency graph.

## [secmem-crypto/v0.1.0] - 2026-07-16

First tagged release of the `secmem-crypto` module. Depends on `secmem`
v0.1.0 — the in-repo `replace` development bridge is gone as of this
release, so the module is consumable outside this checkout.

### Added

- `Ed25519Signer` — a `crypto.Signer`/`crypto.MessageSigner` whose Ed25519 seed
  lives in a `SecureBuffer` for its entire lifetime, with in-place RFC 8032
  signing that bypasses `crypto/ed25519`'s FIPS cache (which panics on
  mmap'd memory). Pure Ed25519 only; Ed25519ph and Ed25519ctx requests are
  refused rather than silently mis-signed. `WithSeed` provides the
  deliberate, documented egress point for generate-then-persist flows.
- `HKDFInto` / `HKDFSHA256Into` — RFC 5869 HKDF deriving directly into a
  `SecureBuffer`, with the full salt/info parameter surface (verified
  against RFC 5869 test cases 1–3) and hash agility.
- `HMACInto` / `HMACSHA256Into` — a raw keyed-HMAC PRF deriving directly into
  a `SecureBuffer`, for domain-separated subkey derivation from an
  already-uniform secret. Distinct from `HKDFInto`: HKDF's Extract step also
  computes an HMAC, but with `secret` and the key argument swapped for its
  own purpose, so the two are not interchangeable — verified against a
  published RFC 4231 test vector and hash-agile beyond SHA-256.
- `GenerateDicewarePassphrase` — a diceware-style passphrase drawn from the
  EFF long wordlist (7776 words, CC BY 3.0 — see `secmem-crypto/NOTICE`)
  via `crypto/rand`, assembled directly inside the returned `SecureBuffer`'s
  own memory with no intermediate heap string at any point. Word selection
  and assembly run inside a `ScrubErr`-guarded region, since which words are
  chosen and in what order is the passphrase, even though each word's text
  is public.
- `Argon2IDKeyInto` / `Argon2DeriveInto` — Argon2id deriving directly into a
  `SecureBuffer`; explicit cost parameters are validated (error, never
  panic), and the defaults follow RFC 9106 §4's second recommended option,
  frozen permanently.
- `WipeEd25519Scalar` — hardened wipe for `edwards25519.Scalar` values,
  whose unexported fields `SecureWipe` cannot reach.
- `OpenInto` / `SealFrom` — AEAD decryption directly into a `SecureBuffer`,
  and encryption straight from one, so an AEAD plaintext never lands on the
  heap as an intermediate. A tampered ciphertext leaves the buffer zeroed;
  the in-place decrypt is measured at zero allocations.
- `X25519Key` — X25519 Diffie-Hellman with the private scalar in a
  `SecureBuffer`; `PublicKey`/`SharedSecret` (returned hardened, low-order
  points rejected)/`WithScalar`/`ConstantTimeEqual`. Verified against
  RFC 7748 vectors.
- `MLKEM768Key` — post-quantum ML-KEM-768 (FIPS 203) decapsulation-key
  custody: 64-byte seed in a `SecureBuffer`, expanded per operation;
  `EncapsulationKeyBytes`/`Decapsulate`/`WithSeed`. `Encapsulate`
  hardens the sender side too, delivering the encapsulating peer's shared
  secret into a `SecureBuffer` instead of the plain heap.
- Fuzz targets (sign-vs-stdlib, HKDF, Argon2 params, AEAD round-trip,
  X25519-vs-stdlib) and benchmarks with allocation reporting across the
  sign, AEAD, DH, and KEM paths.
- `ECDSASigner` — a `crypto.Signer` for P-224/P-256/P-384/P-521 with the raw
  scalar in a `SecureBuffer` between operations. ECDSA is deliberately NOT
  reimplemented (per-signature nonce arithmetic is where implementations
  leak keys); each Sign transiently materializes a stdlib key via
  `ecdsa.ParseRawPrivateKey`, signs, and zeroes the transient's limbs, with
  the residue that can't be reached documented honestly. Deterministic
  RFC 6979 mode (nil `random`) verified against the RFC's test vectors and
  differentially fuzzed byte-identical against stdlib; generation uses
  candidate testing so the scalar is born inside the `SecureBuffer`.
- `RSASigner` — a `crypto.Signer` with the RSA key held as PKCS#1 or PKCS#8
  DER (auto-detected) in a `SecureBuffer`, transiently parsed per operation
  under the same wipe discipline, PKCS#1 v1.5 and PSS via stdlib.
  Signing-only by design (no `crypto.Decrypter`); the per-operation heap
  exposure of the full key is documented rather than downplayed.
- `AsSSH` — adapts any `crypto.Signer` to `golang.org/x/crypto/ssh`. For RSA
  keys the returned signer makes legacy `ssh-rsa` (SHA-1) unreachable on
  every path — negotiation offers only `rsa-sha2-512`/`rsa-sha2-256`,
  explicit requests for `ssh-rsa` error, and plain `Sign` (which x/crypto's
  own restricted signer still routes to SHA-1) is overridden to rsa-sha2-512.
- Runnable examples showing the two most common adoption points for a
  `crypto.Signer`: `ExampleECDSASigner_tlsCertificate` (self-signing an
  `x509.Certificate` and assembling a `tls.Certificate` — what
  `tls.Config.Certificates` expects) and `ExampleAsSSH_hostKey` (wiring an
  adapted signer into `ssh.ServerConfig.AddHostKey`).
- ML-KEM-768 accumulated known-answer test pinning the wrapper's keygen and
  decapsulation byte-for-byte to the standard library's FIPS 203
  implementation (upgrading it from round-trip-only), a published AES-256-GCM
  vector threaded through `SealFrom`/`OpenInto`, a `testing.AllocsPerRun` gate
  enforcing `OpenInto`'s zero-heap-escape, and a proof that `Sign` wipes its
  live transient key (not just the wipe helpers in isolation).

## [0.1.0] - 2026-07-16

First tagged release of the core `secmem` module.

### Added

- `SecureBuffer` — off-heap, page-locked secret storage with borrowing-closure
  access (`WithBytes`/`WithBytesErr`), copy-out/in, sealing, read-only
  protection, and deterministic wipe on `Destroy`.
- `WipeAllSecrets` and `InstallTerminationWipe` — opt-in emergency wiping. The
  library installs **no** signal handler by default (importing it never touches
  process-global signal state); a consumer either calls `WipeAllSecrets` from
  its own shutdown handler or opts into `InstallTerminationWipe`, a cooperative
  termination-signal handler that deregisters only its own channel and never
  resets or ignores other handlers.
- `SecureArena` — a single locked slab of fixed-size slots for many small,
  short-lived secrets at O(1) OS overhead, with ABA-guarded acquire/release.
- `Secret` — a leak-safe value type that renders as `[REDACTED]` through
  `fmt`, `encoding/json`, and `log/slog`.
- `Capabilities` and `Probe` — honest, per-allocation and per-platform
  reporting of which protections are actually in force, with `Warnings()` and a
  one-line `String()`.
- Guard pages and an overflow canary bracketing every allocation; a linear
  over/under-flow faults or is caught on destroy. On Linux this includes the
  `memfd_secret` `MAP_FIXED`-into-a-reservation construction.
- `Scrub` / `ScrubErr` — register, stack, and heap residue erasure via
  `runtime/secret` where available (`GOEXPERIMENT=runtimesecret`), with a
  best-effort stack-frame wipe elsewhere.
- Fail-closed policy on platforms with no lockable off-heap memory:
  constructors return `ErrNoSecureMemory` unless `WithInsecureFallback()` is
  passed.
- Process-hardening helpers: `HardenProcess` (dumpable=0 and no-new-privs on
  Linux; Arbitrary Code Guard and strict handle checks on Windows),
  `DisableCoreDumps`, and `EnsureMemlockLimit`.
- Platform dump/copy hardening applied by the allocator: `MADV_DONTDUMP` /
  `MADV_DONTFORK` / `MADV_NOHUGEPAGE` / `MADV_UNMERGEABLE` on Linux; WER dump
  exclusion and a kernel-keyed sealed-state cipher (`CryptProtectMemory`) on
  Windows.
- `secmem/redact` subpackage — a configurable `Sanitizer` and an `slog.Handler`
  wrapper for boundary-level log scrubbing (credential masking and CWE-117
  injection neutralization). Standard library only.
- `KERNELS.md` — a log of the Linux kernels the suite has been executed on, with
  the guard-fault, `memfd_secret`-isolation, and canary proofs recorded per row.
  Now includes real **arm64** (Ampere Altra) and a spread of amd64 kernels
  (5.10 → 7.x) run on disposable cloud hardware.
- `ENVIRONMENTS.md` — how secmem behaves across root / non-root / rootless and
  constrained `RLIMIT_MEMLOCK`, and why `memfd_secret` availability is a kernel
  `CONFIG_SECRETMEM` property rather than a version guarantee.
- `TESTING.md` — the verification companion to the guarantee matrix: every
  security claim mapped to the test that proves it, or the stated reason it
  cannot be (the fused wipe+munmap, the structural constant-time argument).
- CI now runs the `GOEXPERIMENT=runtimesecret` variant (so the
  register/stack/heap erasure integration tests actually execute) and executes
  the suite on 32-bit x86 rather than only compiling it; a
  `testing.AllocsPerRun` gate enforces no-heap-escape on the borrow/copy/
  compare paths.

### Fixed

- `SecureBuffer`, `SecureArena`, and `ArenaSlot` now redact themselves under
  every formatting and logging path (`fmt`'s `%v`/`%+v`/`%s`/`%x`, `Println`,
  error-wrapping, `log/slog`) — matching `Secret`'s existing behavior. Without
  this, `fmt`'s default struct printer reflected into the guarded region and
  crashed the process with an unrecoverable hardware fault rather than
  printing anything; the crash, not a plaintext leak, was the actual failure
  mode on every path tested. Found in a pre-release audit; regression tests
  cover all three types, both the pointer and (where a value copy is not
  itself a `go vet` copylocks violation) a dereferenced value.

[Unreleased]: https://github.com/deadpoets/secmem/compare/v0.1.0...HEAD
[secmem-lint/v0.1.0]: https://github.com/deadpoets/secmem/releases/tag/secmem-lint%2Fv0.1.0
[secmem-crypto/v0.1.0]: https://github.com/deadpoets/secmem/releases/tag/secmem-crypto%2Fv0.1.0
[0.1.0]: https://github.com/deadpoets/secmem/releases/tag/v0.1.0
