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

## [secmem-crypto/v0.3.2] - 2026-08-16

Retracts `secmem-crypto/v0.3.0`, and documents the module.

The `retract` directive is the supported way to mark a published version
unusable, and unlike a changelog note it reaches the toolchain — `go list -m
-retracted` and `go get` surface it to someone already on v0.3.0. A retraction
only ships in a *later* version, which is what this release is for. No source
change.

Adds `secmem-crypto/README.md`, which puts the reason this module reimplements
RFC 8032 signing above the fold: `crypto/ed25519`'s FIPS-140 path caches the
private key in a structure no wipe can reach, and panics outright on mmap'd
memory. "Rolled their own Ed25519" deserves scrutiny, so the justification
should not be buried in a per-file comment.

## [secmem-crypto/v0.3.1] - 2026-08-16

Dependency-only release: requires `secmem` v0.3.0, so code importing only this
module resolves the v0.3.0 core.

Supersedes `secmem-crypto/v0.3.0`, which was tagged from a commit predating the
`go.mod` change and therefore still requires `secmem` v0.2.0. That tag is left
published: `proxy.golang.org` and `sum.golang.org` are append-only, so
re-pointing it would only make this repository disagree with them.

## [0.3.0] - 2026-08-16

The result of the library's first adversarial audit. Every finding below was
reached from the source rather than reported in the field, so nothing here is
known to have bitten anyone — but two of them are the kind that would never have
announced themselves: a compiler barrier that was not one, and an emergency wipe
that leaked the mappings it wiped.

`ErrWiped`, `Capabilities.FrameScrub`, and `Capabilities.AsyncPreemptSuppressed`
are the only API additions and nothing was removed, so the change is backward
compatible (confirmed by `gorelease`). Behavior changes that the type surface
does not show are listed under **Changed** — read that section before upgrading.

### Fixed

- **The portable wipe's compiler barrier was not a barrier.** `secureWipe` on
  every architecture without wipe assembly — everything except amd64 and arm64
  — zeroed via `subtle.ConstantTimeSelect(1, 0, b[i])`. With a constant selector
  that whole expression folds to a constant `0` at compile time, leaving exactly
  the plain zeroing loop over never-read-again memory that it was written to
  protect from dead-store elimination. Go's compiler does not currently remove
  that loop, so this is a latent hole rather than a known leak, but "does not
  currently" is not a guarantee and the package's entire promise rests on the
  zeros reaching memory. The wipe now takes its zero byte from a package-level
  atomic (not a compile-time constant), reads every byte back into an
  accumulator, and publishes the accumulator to a second atomic, so the stores
  are provably observed. Verified in the GOARCH=386 disassembly: both loops and
  both atomics survive.
- **`WipeAllSecrets` no longer leaks the mappings it wipes.** It deliberately
  leaves regions mapped so a late read returns zeros instead of faulting on
  freed memory — but nothing ever completed the unmap, so the address space and
  the locked pages were held until process exit. Wiped regions are now retained
  separately, and a later explicit `Destroy` — or the GC cleanup once the
  wrapper is unreachable — finishes the reclaim. That is safe where the
  emergency path is not: both run with no accessor in flight.
- **One slow borrow no longer holds the whole emergency wipe hostage.** Wiping a
  region takes its exclusive lock, so a buffer parked inside a `WithBytes`
  callback cannot be wiped until that callback returns — correct, since zeroing
  memory a callback is reading is a data race. But the single blocking pass
  meant one slow borrow delayed every *other* secret in the process, in registry
  map order. The wipe now runs a non-blocking pass first and blocks only on what
  is left, so a stuck borrow delays only its own buffer.
- **A `Destroy` racing the emergency wipe no longer strands the mapping.** The
  blocking wipe pass removed a region from the registry *before* taking its
  lock, leaving a window in which the key was in neither the live set nor the
  wiped set. A `Destroy` already queued on that same lock reached the janitor
  inside that window, found nothing to free, reported success, and never
  unmapped; the retain that landed afterwards then filed the region where
  nothing collects it. The GC-cleanup path was worse, since its cleanup is
  stopped and never runs again. The lock is now held across the whole take /
  wipe / retain sequence. Reached by the exact API pair `WipeAllSecrets`
  documents as safe to use concurrently.
- **`memfd_secret` mappings now apply `MADV_DONTFORK`, and report whether it
  took.** The L4 mapping is `MAP_SHARED`, so a forked child did not inherit a
  copy-on-write snapshot of the secret pages — it shared the live ones. `noFork`
  was reported `false` without anything having been attempted. It is now
  attempted and the outcome reported honestly per allocation.
- **windows/386 did not compile.** The WER dump-exclusion size bound was written
  `int(^uint32(0))`, whose constant overflows `int` on a 32-bit word. Widened to
  `uint64`, and the cross-compile matrix gained the windows/386 row that would
  have caught it — nothing else in it is both Windows and 32-bit.

### Added

- `ErrWiped` — returned by every mutating method after `WipeAllSecrets` has
  emergency-wiped the object, and by `SecureArena.Acquire`. Previously those
  calls succeeded, which let a process that kept running write a *fresh* secret
  into a region the emergency wipe had already reported as handled. Reads still
  work and return the zeros. It wraps `ErrDestroyed`, so existing
  `errors.Is(err, ErrDestroyed)` checks keep working unchanged; test for
  `ErrWiped` only to tell "the process emergency-wiped this" apart from "the
  owner destroyed this".
- **Asynchronous-preemption suppression inside `Scrub` windows (Linux).** Go's
  non-cooperative preemption is signal-delivered, and `runtime.asyncPreempt`
  saves the entire user register file — general purpose and vector — onto the
  goroutine stack at an arbitrary instruction boundary. Land one inside a cipher
  round and a copy of live key material is written to the stack at an offset
  nothing chose and nothing tracks. `Scrub` now blocks SIGURG for the duration
  of its window, so that spill cannot happen. Cooperative preemption is
  untouched, so the collector still reaches the goroutine through ordinary calls
  — but a window whose callback contains an unbounded loop with no function
  calls offers no cooperative preemption point either and will stall `suspendG`;
  keep callbacks short and call-bearing, which the borrowing contract already
  asks for. Unavailable on Windows (preemption there rewrites thread context
  rather than delivering a signal, and nothing in userspace can mask that) and
  on Darwin (no `PthreadSigmask` in `x/sys/unix`).
- **arm64 scrub-frame assembly.** `Scrub`'s stack-band burn was amd64-only and
  silently did nothing elsewhere; arm64 now has a real implementation.
- `Capabilities.FrameScrub` and `Capabilities.AsyncPreemptSuppressed` — report
  whether the two mechanisms above are real on the running platform rather than
  leaving callers to infer it. Both feed `Warnings()`.
- **THREAT-MODEL.md gains a stack-residue section** enumerating what `Scrub`
  reaches, what it does not, and — stated separately — which of the gaps are
  constraints of the Go runtime or the OS rather than defects. KERNELS.md and
  TESTING.md record the verified kernels and the contention measurements behind
  the lock rework.

### Changed

- **`SecureArena` per-slot bookkeeping dropped from 90 to 16 bytes** — measured
  at 4096 × 32-byte slots, where the Go-heap index went from 1.88× the locked
  slab it describes to 0.34×. For a type whose stated purpose is hundreds of
  short-lived per-session keys, the metadata previously cost nearly twice the
  secrets. Three changes got there: `slotMeta` now carries one `atomic.Uint64`
  generation that encodes liveness in its low bit (even = free, odd = live)
  instead of a separate flag padded to a cache line; the free list is an
  intrusive `int32` link inside `slotMeta` rather than a separate `[]int`; and
  the canary zones are a fixed-size descriptor regenerated on demand rather than
  a materialized `[][2]int` costing 16 bytes per slot.
- **The arena borrow path is now lock-free.** Slot liveness is one atomic load
  and compare against the handle's generation, with no mutex on the read side.
- **`SecureArena.Acquire` and `LiveCount` are O(1)**, not a scan over every
  slot. A consequence worth knowing: after any `Release`, `Acquire` hands out
  the most recently freed slot rather than the lowest free index. A fresh arena
  still hands out 0, 1, 2, … Nothing documented the old order, but code that
  depended on it will observe the change.
- **`NewArena` now rejects `count > math.MaxInt32`** with an error, rather than
  overflowing the intrusive free link quietly.
- **The buffer read-write lock has an atomic read fast path.** The read side
  sits under every `SecureBuffer` access and every `ArenaSlot` borrow, and it
  previously took a mutex in both directions. Measured, that was ~85% of the
  cost of an arena borrow at 16 cores, and aggregate throughput *fell* as cores
  were added — goroutines borrowing entirely disjoint secrets were serializing
  on it. Readers now enroll with a single atomic add and take no mutex unless a
  writer is involved. Writers stay on the mutex-and-cond slow path, so every
  blocking state remains durably blocked under `testing/synctest`. Writer
  preference is unchanged.
- **`WipeAllSecrets` documents that it can block**, which it always could. A
  borrowing callback that never returns blocks it forever; the alternative would
  be zeroing memory a callback is actively reading. The two-pass wipe contains
  the cost to the offending buffer. If your shutdown path must be bounded, run
  it in its own goroutine and exit on a timer — the first pass will have done
  its work regardless.
- **`EnsureMemlockLimit` documents that it disarms an implicit guard.** A
  bounded `RLIMIT_MEMLOCK` is incidentally what stops an oversized `NewArena`
  from killing the process: `NewArena` requests its locked slab before its
  Go-heap slot index precisely because a refused slab returns an error while a
  refused heap allocation is `runtime.throw`, which no `defer` and no `recover`
  survives. Raising the budget raises that ceiling with it; raising it to
  unlimited removes it. If you raise it and then size arenas from something
  outside your control, bound the count yourself.
- **The `RLIMIT_MEMLOCK` guidance is now measured rather than folklore.** The
  ceiling is `RLIMIT_MEMLOCK / pagesize` buffers exactly, and current
  systemd-based distributions default it to 8 MiB — 2048 buffers at 4 KiB
  pages, measured on stock Ubuntu 26.04/amd64 and Armbian/arm64 — not the
  historical 64 KiB kernel default that allowed about a dozen. Read the runtime
  limit rather than designing against either number.

## [secmem-crypto/v0.2.0] - 2026-07-19

Dependency-only release. `secmem-crypto` now requires `secmem` v0.2.0, so code
that imports only this module picks up the read-only crash fix below — v0.1.0
of this module pins `secmem` v0.1.0 and would otherwise keep resolving the
faulting core.

No `secmem-crypto` source change: the only additions since
`secmem-crypto/v0.1.0` are the `FuzzSignerLifecycle` state-machine fuzzer and
its seed corpus, both test-only. It is a **minor** bump rather than a patch
because this module's exported API hands back `*secmem.SecureBuffer` values,
so raising its `secmem` floor to v0.2.0 raises the minimum for every consumer
too — a dependency-graph change they should opt into deliberately
(`gorelease` classifies it the same way).

## [0.2.0] - 2026-07-19

A bug-fix release for the core `secmem` module, and the reason to upgrade
promptly: v0.1.0 could **crash the process** on a documented API sequence.
`ErrReadOnly` is the only API addition, so the change is backward compatible
(confirmed by `gorelease`).

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

[Unreleased]: https://github.com/deadpoets/secmem/compare/v0.3.0...HEAD
[secmem-crypto/v0.3.2]: https://github.com/deadpoets/secmem/releases/tag/secmem-crypto%2Fv0.3.2
[secmem-crypto/v0.3.1]: https://github.com/deadpoets/secmem/releases/tag/secmem-crypto%2Fv0.3.1
[secmem-crypto/v0.3.0]: https://github.com/deadpoets/secmem/releases/tag/secmem-crypto%2Fv0.3.0
[0.3.0]: https://github.com/deadpoets/secmem/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/deadpoets/secmem/compare/v0.1.0...v0.2.0
[secmem-crypto/v0.2.0]: https://github.com/deadpoets/secmem/releases/tag/secmem-crypto%2Fv0.2.0
[secmem-lint/v0.1.0]: https://github.com/deadpoets/secmem/releases/tag/secmem-lint%2Fv0.1.0
[secmem-crypto/v0.1.0]: https://github.com/deadpoets/secmem/releases/tag/secmem-crypto%2Fv0.1.0
[0.1.0]: https://github.com/deadpoets/secmem/releases/tag/v0.1.0
