# How secmem's claims are tested

This is the verification companion to the guarantee matrix in
[README.md](README.md) and the godoc: for every security claim secmem makes,
this document names the test that proves it — or states plainly why it cannot
be proven and what stands in for a proof. A claim with no entry here is a claim
without a test, and this file is meant to make that visible.

The same #1 rule applies as everywhere else in the project: a claim tested only
by a comment is not tested. Where a property is genuinely unobservable from Go,
that is said outright rather than dressed up.

## How the suite runs

- **`-race` on every supported execution target** — Linux amd64, Linux arm64
  (native runner), macOS, Windows. The concurrency and destroy-during-use
  tests are meaningful only under the race detector, so it is the default, not
  an option.
- **`GOEXPERIMENT=runtimesecret` variant** (Linux amd64 + arm64) — runs the
  build-tag-gated integration tests for the register/stack/heap erasure layer,
  which are otherwise dark in automation.
- **Executed on 32-bit x86** (`GOARCH=386`), not merely compiled — the wipe
  helpers manipulate `big.Word` limbs whose width differs on 386. Runs without
  `-race` (the detector needs 64-bit), which is also where the allocation gates
  run, since allocation counts are not meaningful under race instrumentation.
- **Cross-compiled** for linux/arm64, darwin/arm64, darwin/amd64, windows/arm64
  (build + test-binary compile) so the whole matrix at least builds.
- **Fuzz seed corpora** run as ordinary tests in CI; active fuzzing
  (`-fuzztime`) is a local/manual step via the Makefile.

## Core memory hardening

| Claim | How it is proven | Test |
|---|---|---|
| Secret bytes live off the Go GC heap | Structural (mmap / VirtualAlloc, never `make`); reported per allocation | `Capabilities.OffHeap`, `capabilities_test.go` |
| Pages are locked out of swap | Kernel's own `lo` (locked) flag read from `/proc/self/smaps` | `madvise_linux_test.go` |
| `memfd_secret` pages are unreadable via `/proc/<pid>/mem` | Reads the buffer's address range through `/proc/self/mem`, requires the read to **fail**, with a control read of ordinary heap that must **succeed** | `memfd_isolation_linux_test.go` |
| `Destroy` deterministically zeroes the secret | A slab slot is written `0xFF`, released (running the production wipe on the mapped region), re-acquired, and read back as zero | `securearena_test.go` (`TestArena_ReleaseWipesSlot`) |
| The wipe is exact and not compiler-elided | Assembly (`REP STOSB` / `DC CIVAC`) is inherently un-elidable; the generic fallback uses `subtle.ConstantTimeSelect`; the readback tests above would fail if a store were dropped | `wipe_unaligned_test.go`, `wipe_arm64.s`/`wipe_amd64.s`, `wipe_generic.go` |
| Guard pages trap a linear over/under-flow | Deliberately reads one byte past each edge under `SetPanicOnFault`, requires a fault; in-region bytes must not fault | `guard_canary_test.go` |
| An in-mapping overflow too small to reach a guard is caught | Corrupts the canary slack, requires `ErrCanaryViolation` on Destroy/Release | `guard_canary_test.go`, `securearena_test.go` |
| Registers/stack are scrubbed after a `Scrub` closure | Plants markers down the stack, runs `Scrub`, reads the abandoned frames back as zero | `scrub_amd64_test.go` (amd64); `runtimesecret` integration in `securebuf_scrub_test.go`, `secretdo_active_test.go` |
| Constructors fail closed, never panic | Bad/overflow inputs on every constructor; `RLIMIT_MEMLOCK=0` with `CAP_IPC_LOCK` dropped; unsupported-platform stub | `negative_test.go`, `negative_mlock_linux_test.go`, `mlock_stub_test.go` |
| Borrow/copy/compare paths do not allocate (no heap escape) | `testing.AllocsPerRun` gate asserts 0 allocs on `WithBytes`/`ByteAt`/`CopyOut`/`CopyIn`/`ConstantTimeEqual`/… | `alloc_test.go` |
| A sealed buffer holds ciphertext at rest (Windows) | Peeks the raw mapping while sealed and asserts the plaintext is absent (and not all-zero) | `sealcipher_windows_test.go` |
| `Secret` / `redact` never emit the plaintext | Formatting/marshalling/slog routed through `any` so the verb can't be folded; adversarial and fuzzed inputs | `secret_test.go`, `negative_test.go`, `redact/*_test.go` |

## secmem-crypto: correctness and secret hygiene

| Claim | How it is proven | Test |
|---|---|---|
| Ed25519 matches RFC 8032 | All 5 official vectors, byte-identical differential vs `crypto/ed25519`, differential fuzz, and an S < L malleability check | `ed25519direct_test.go`, `fuzz_test.go` |
| ECDSA deterministic mode matches RFC 6979 | Six appendix vectors (P-256/384/521, SHA-256), byte-identical differential vs `crypto/ecdsa`, differential fuzz | `ecdsa_test.go`, `fuzz_block3_test.go` |
| X25519 matches RFC 7748 | §6.1 vectors both directions, differential fuzz vs `curve25519`, low-order-point rejection | `x25519_test.go`, `fuzz_block2_test.go` |
| HKDF matches RFC 5869 | Test cases 1–3 (SHA-256), differential vs `x/crypto/hkdf`, hash agility | `kdf_test.go` |
| Argon2id is the standard parameter profile | The `x/crypto/argon2` reference KAT (see note below re: RFC 9106) | `kdf_test.go` |
| **ML-KEM-768 conforms to FIPS 203** | Accumulated known-answer test: 100 deterministic keygen/encap/decap rounds through `MLKEM768Key`, folded into a SHAKE128 digest compared to the NIST-anchored value `crypto/mlkem` validates against | `kat_test.go` |
| The AEAD wrapper preserves the cipher contract | A published AES-256-GCM vector threaded through `SealFrom` and `OpenInto` byte-for-byte | `kat_test.go`, `aead_test.go` |
| `OpenInto` lands plaintext in the buffer with no heap intermediate | `testing.AllocsPerRun` gate asserts 0 allocs | `alloc_test.go` |
| Sign wipes the transient key it materializes | The wipe var is wrapped to alias the live transient's limb arrays during `Sign`; they are asserted zero afterward, and a `fired` guard fails if the deferred wipe is ever dropped | `livewipe_test.go`, `wipehelpers_block3_test.go` |
| Every borrow path is safe when sealed/destroyed/nil | Each type's borrow methods return `ErrSealed`/`ErrDestroyed` and recover after `Unseal` | `sealed_block2_test.go`, `sealed_block3_test.go` |
| Concurrent Sign is safe | 8×25 concurrent signs and Sign-vs-Destroy races under `-race` | `ed25519_test.go`, `ecdsa_test.go`, `rsa_test.go` |
| Legacy `ssh-rsa` (SHA-1) is unreachable | Every signing path of an `AsSSH` RSA signer is asserted to offer/use only rsa-sha2 | `ssh_test.go` |

## Deliberately not proven — and why

Honesty requires naming the properties that are asserted structurally or by a
stand-in rather than measured directly.

- **A `SecureBuffer`'s own post-`Destroy` zero-readback does not exist, by
  design.** `Destroy` wipes and then unmaps the region as one step, so there is
  no moment at which the freed region is both zeroed and still readable —
  reading it afterward is a use-after-munmap, not a test. The deterministic
  zeroization proof therefore lives on the `SecureArena` slot path
  (`TestArena_ReleaseWipesSlot`), where a released slot is wiped and can be
  legitimately re-acquired and read back, exercising the same production wipe
  routine. This is a stand-in chosen because it is *possible*, not a gap.
- **The wipe's cache-line flush is reported, not independently asserted.**
  Whether the zeros were flushed to DRAM versus left in cache
  (`Capabilities.FlushedWipe`) is not observable from Go. The flush is
  structural — architecture assembly emits `CLFLUSH`/`CLFLUSHOPT` or
  `DC CIVAC` — and the field reports which path ran; there is no test that
  inspects cache state, because Go cannot.
- **Constant-time comparison is structural, not timing-measured.**
  `ConstantTimeEqual` (buffer and `Secret`) delegates to
  `crypto/subtle.ConstantTimeCompare`; correctness of the boolean result is
  tested, but the timing property is argued from construction, not measured.
  Statistical timing tests (dudect/ctgrind-style) are deliberately out of
  scope: they are flaky in CI and prove little that the use of `crypto/subtle`
  does not already establish.
- **`mlock` preventing swap is confirmed by the kernel's locked flag, not by
  forcing a swap.** Proving eviction-resistance directly would require
  exhausting RAM to force swapping; the `lo` flag in `/proc/self/smaps` is the
  kernel's own record that the pages are locked, which is the check
  `madvise_linux_test.go` makes.
- **secmem is not a FIPS 140-validated module.** The crypto known-answer tests
  anchor to the same RFC / NIST-derived vectors a validation would use
  (RFC 8032/6979/7748/5869, the FIPS 203 accumulated digest), and the
  zeroization discipline mirrors the FIPS "zeroization of CSPs" requirement,
  but no CMVP validation has been performed and none is claimed.
- **Argon2id is pinned to the reference-implementation KAT, not RFC 9106's
  headline vector.** That vector sets a secret key and associated data which
  `golang.org/x/crypto/argon2` does not expose, so it cannot be reproduced
  through this API; the pinned value is the parameter profile shared by the
  reference CLI and the mainstream bindings.
