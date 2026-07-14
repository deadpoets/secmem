# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version is `0.x`, the public API may change between minor versions as
the surface settles; breaking changes will be called out here. `1.0.0` will
mark the stability commitment.

## [Unreleased]

> This repo now holds two independently versioned Go modules; entries below
> are tagged by module. Untagged entries belong to the core `secmem` module.

### Added (secmem-crypto — new module, not yet tagged)

- `Ed25519Signer` — a `crypto.Signer`/`crypto.MessageSigner` whose Ed25519 seed
  lives in a `SecureBuffer` for its entire lifetime, with in-place RFC 8032
  signing that bypasses `crypto/ed25519`'s FIPS cache (which panics on
  mmap'd memory). Pure Ed25519 only; Ed25519ph and Ed25519ctx requests are
  refused rather than silently mis-signed. `WithSeed` provides the
  deliberate, documented egress point for generate-then-persist flows.
- `HKDFInto` / `HKDFSHA256Into` — RFC 5869 HKDF deriving directly into a
  `SecureBuffer`, with the full salt/info parameter surface (verified
  against RFC 5869 test cases 1–3) and hash agility.
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

[Unreleased]: https://github.com/deadpoets/secmem/commits/main
