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
| A **separate process** cannot extract a `SecureBuffer` | A victim subprocess holds the secret only in a `memfd_secret` buffer and a twin control marker on the heap; its parent scans the victim's whole address space via both `/proc/<pid>/mem` **and** `process_vm_readv(2)` — the control marker is recovered every time, the secret never. Skips (never fails) when `memfd_secret` or ptrace is unavailable. The root/`CAP_SYS_PTRACE` and `gcore` core-dump variants are recorded as manual runs in [KERNELS.md](KERNELS.md) | `extraction_linux_test.go` |
| `Destroy` deterministically zeroes the secret | A slab slot is written `0xFF`, released (running the production wipe on the mapped region), re-acquired, and read back as zero | `securearena_test.go` (`TestArena_ReleaseWipesSlot`) |
| The wipe is exact and not compiler-elided | Assembly (`REP STOSB` / `DC CIVAC`) is inherently un-elidable. The generic fallback takes its zero byte from a package-level atomic (so the stored value is not a compile-time constant), reads every byte back into an accumulator, and publishes the accumulator to a second atomic, so the stores are provably observed; `//go:noinline` stops a caller re-deriving what the body cannot. Confirmed in the GOARCH=386 disassembly — both loops and both atomics survive. The readback tests above would fail if a store were dropped | `wipe_unaligned_test.go`, `wipe_arm64.s`/`wipe_amd64.s`, `wipe_generic.go` |
| Guard pages trap a linear over/under-flow | Deliberately reads one byte past each edge under `SetPanicOnFault`, requires a fault; in-region bytes must not fault | `guard_canary_test.go` |
| An in-mapping overflow too small to reach a guard is caught | Corrupts the canary slack, requires `ErrCanaryViolation` on Destroy/Release | `guard_canary_test.go`, `securearena_test.go` |
| No two live `ArenaSlot` handles ever address the same slot | Walks the intrusive free list directly after every acquire/release and asserts it terminates, revisits nothing, and agrees with the parity-encoded generations and the live counter; plus a concurrent double-`Release` stress that must not splice an index onto the list twice. The drain loop is bounded on purpose — a list cycle would otherwise hang the suite instead of reporting it | `securearena_freelist_test.go` |
| An arena's Go-heap bookkeeping stays smaller than its locked slab | Arithmetic pin: per-slot `slotMeta` must be under `canaryLen+1`, the locked cost of the smallest legal slot. This is what makes `NewArena`'s slab-first allocation order protective — the allocation that can `throw` must be the smaller one | `securearena_test.go` (`TestArena_HeapMetadataStaysUnderLockedSlab`) |
| `Scrub` erases the stack residue of a shallow call tree | Plants markers down the stack, runs `Scrub`, reads the abandoned frames back through a raw `uintptr` and requires zero. Covers both architectures with real frame assembly — amd64 and arm64 | `scrub_frame_test.go` (`TestScrub_ScrubsShallowCallTree`); `runtimesecret` integration in `securebuf_scrub_test.go`, `secretdo_active_test.go` |
| A `Scrub` window blocks the preemption signal, so `asyncPreempt` cannot spill the register file into it | Reads `SigBlk` for the **calling thread** from `/proc/thread-self/status` — the kernel's own record — inside the window, and requires SIGURG and SIGPROF set there and the mask exactly restored after. Asserts the goroutine did not migrate (`LockOSThread`), and that a nested window restores the outer mask rather than unblocking | `scrub_window_linux_test.go` |
| Blocking that signal does not make a window unpreemptible | Eight concurrent windows against a deliberately GC-heavy workload must all complete; a window the collector could not suspend would hang rather than fail quietly | `scrub_window_linux_test.go` (`TestScrub_ConcurrentWindowsUnderGCPressure`) |
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
| **ML-KEM-768 keygen and decap agree with the standard library's FIPS 203 implementation** | Accumulated known-answer test: 100 deterministic rounds — keygen and both decapsulations through `MLKEM768Key`, encapsulation via the stdlib derandomized test helper — folded into a SHAKE128 digest matched byte-for-byte to `crypto/mlkem`'s own accumulated value. Conformance to the reference implementation (itself NIST-validated), not an independent NIST vector; a wrapper plumbing regression breaks the digest | `kat_test.go` |
| The AEAD wrapper preserves the cipher contract | A published AES-256-GCM vector threaded through `SealFrom` and `OpenInto` byte-for-byte | `kat_test.go`, `aead_test.go` |
| `OpenInto` lands plaintext in the buffer with no heap intermediate | `testing.AllocsPerRun` gate asserts 0 allocs | `alloc_test.go` |
| Sign wipes the exported limbs of the transient key it materializes | The wipe var is wrapped to alias the live transient's `big.Int` limbs during `Sign`; they are asserted zero afterward, and a `fired` guard fails if the deferred wipe is ever dropped. The stdlib FIPS-form copy and modular-arithmetic scratch are unreachable — see the note below | `livewipe_test.go`, `wipehelpers_block3_test.go` |
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
- **The stack residue `Scrub` cannot reach is argued, not measured.** The frame
  wipe is proven to zero the band it reserves (above), and the preemption block
  is proven against the kernel's own record of the mask. Three residue sources
  remain unobservable from Go and are documented rather than tested: a GC
  stack-shrink that frees `fn`'s segment before the deferred wipe runs
  (`shrinkstack` is asynchronous and runtime-owned), the CPU registers at
  `Scrub`'s return (the ABI reloads them around any call that would clear them,
  so a Go-level register scrub cannot be verified to have reached anything), and
  the `ucontext` the kernel writes to the signal stack on a synchronous fault.
  The first is closed by `GOEXPERIMENT=runtimesecret`, which has runtime
  cooperation; the other two are constraints of Go and of the OS. All three are
  enumerated in the stack-residue section of [THREAT-MODEL.md](THREAT-MODEL.md).
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
- **The transient signing key is wiped only where it is reachable.** `Sign`
  zeroes the exported `big.Int` limbs of the ECDSA/RSA key it materializes
  (proven in `livewipe_test.go`), but the standard library also builds an
  internal FIPS-form copy and modular-arithmetic scratch that no exported API
  exposes; those are erased on `GOEXPERIMENT=runtimesecret` builds and
  otherwise reclaimed by the GC, not explicitly zeroed. This is the documented
  cost of not reimplementing ECDSA/RSA, stated in the signer type docs.
- **secmem is not a FIPS 140-validated module.** The crypto known-answer tests
  anchor to the published RFC vectors a validation would use
  (RFC 8032/6979/7748/5869) and, for ML-KEM-768, to byte-for-byte agreement
  with the standard library's FIPS 203 implementation; the zeroization
  discipline mirrors the FIPS "zeroization of CSPs" requirement. No CMVP
  validation has been performed and none is claimed.
- **Argon2id is pinned to the reference-implementation KAT, not RFC 9106's
  headline vector.** That vector sets a secret key and associated data which
  `golang.org/x/crypto/argon2` does not expose, so it cannot be reproduced
  through this API; the pinned value is the parameter profile shared by the
  reference CLI and the mainstream bindings.

## Benchmarks: what they are for, and how to report them

secmem's benchmarks are not a performance claim and are not a comparison
against other libraries. They exist for one purpose: **to show that the
hardened path is cheap enough that nobody is tempted to route around it.** A
secure-memory API that is slow in the hot path gets bypassed "just for this
one case", and the bypass is the vulnerability. So the number that matters is
never the absolute ns/op — it is the *cost of the guarantee* relative to the
unhardened thing a caller would otherwise write.

### The cost model the benchmarks are shaped around

Three regimes, and they differ by orders of magnitude:

| Regime | Bound by | Benchmarks |
|---|---|---|
| Allocation / teardown | syscalls — `mmap`, `mprotect`, `mlock`, 4× `madvise`, `munlock`, `munmap` | `BenchmarkNewBuffer`, `BenchmarkNewEmptyBuffer`, `BenchmarkNewDestroy`, `BenchmarkScope` |
| Wipe | memory bandwidth, plus the cache-flush loop | `BenchmarkSecureWipeSlice`, `BenchmarkSecureWipe_4K`, `BenchmarkSecureWipe_64K` |
| Borrow / access | a handful of atomic operations | `BenchmarkWithBytesErr`, `BenchmarkByteAt`, `BenchmarkCopyOut`, `BenchmarkBufferRWLock_*` |
| Contention | one shared cache line — never a lock, never the data | `BenchmarkArenaBorrowParallel`, `BenchmarkArenaChurnParallel`, `BenchmarkBufferRWLock_RLockUnlock_Parallel` (run with `-cpu 1,2,4,8,16`) |

The design guidance falls straight out of that ordering: **allocate once,
borrow often.** A caller who allocates per operation pays syscall cost per
operation; that is what `SecureArena` exists to amortize
(`BenchmarkArenaAcquireRelease`), and why its free list is O(1).

### What the contention benchmarks found

They exist because a premise had gone unmeasured for the life of the type.
`slotMeta` carried 48 bytes per slot of cache-line padding "to avoid false
sharing between concurrent slot operations", and a note about a future
lock-free upgrade — while every arena benchmark was single-goroutine. Nothing
had ever established that concurrent slot operations contend, or where.

`BenchmarkArenaBorrowParallel` is the experiment that settles it: each goroutine
holds its **own** slot for the whole run and only borrows it, so no two
goroutines share a secret, a slot, or a free-list node. Perfect scaling is the
null hypothesis, and any departure is attributable to the one thing that is
shared.

Measured on an Intel Core Ultra 7 265KF, Windows, `-count=10`, **clocks not
pinned** (so treat the ratios as the finding and the absolute nanoseconds as
indicative — see rule 3 below):

- The borrow path does **not** scale. Per-operation cost rose roughly sixfold
  from 1 to 16 cores, i.e. aggregate throughput *fell* as cores were added.
- `BenchmarkArenaBorrowSerial` stayed flat across the same `-cpu` values,
  confirming the cause is contention rather than core count or frequency.
- `BenchmarkBufferRWLock_RLockUnlock_Parallel` reproduces the same curve on its
  own and accounted for roughly **85%** of the contended borrow cost at 16
  cores. The remainder is the arena's `alloc` mutex and the liveness check.

Two conclusions worth keeping:

1. The lock primitive dominated, and it was mutex-based **by design** — `sync.Cond`
   is what makes every blocking state durably blocked under `testing/synctest`
   (see `buflock.go`). The measurement did not overturn that trade; it showed
   the trade was drawn in the wrong place. Blocking must go through `sync.Cond`
   for synctest to observe it — but a fast path that *succeeds* never blocks,
   so nothing requires the mutex on the success path. That distinction is what
   the fix exploits.
2. Cache-line padding on the slot metadata targeted nothing at all — every
   *write* to `slots[…]` is serialized under `alloc`, so write-write ping-pong
   cannot occur — and a lock-free redesign of that metadata alone would have
   targeted the smaller ~15%.

### What fixing it changed, measured

Both hot-path mutexes are gone. `bufferRWLock`'s read side became one atomic
`Add` in each direction, biased negative while a writer is active or waiting so
a single `Add` both tests for writers and enrolls the reader; everything that
blocks still blocks in `cond.Wait`, so the four synctest tests pass unchanged
and writer preference, `tryLock`'s refusal contract, and the drain-before-`munmap`
guarantee are intact (`buflock.go` carries the full missed-wakeup argument, and
`TestBufferRWLock_ExclusionStress` hammers it on real threads). The arena's
liveness check stopped taking `alloc` by folding liveness into the generation's
parity — even = free, odd = live — so one atomic load answers released,
recycled, and live at once, with the ABA guard tightened rather than weakened.

Same box, same method, before → after:

- Uncontended borrow: 30.4 → 12.6 ns. Contended at 16 cores: 180.9 → 47.8 ns.
- The **shape** is the real result: per-op cost used to grow monotonically with
  cores (29.7 / 49.8 / 89.9 / 171.7 / 180.9 ns across 1/2/4/8/16); it now steps
  once at 2 cores and holds flat (11.6 / 42.6 / 43.6 / 50.3 / 47.8 ns). The
  step is the cache-line transfer on the shared reader count — the physics of
  any centralized counter, roughly 4× the uncontended cost here — not lock
  convoying, which is what the monotonic growth was.
- The lock primitive alone: 22.5 → 11.8 ns uncontended; 152.9 → 31.4 ns
  contended at 16.
- Churn (`Acquire`+`Release`) moved 444 → 399 ns at 16 cores and remains
  serialized on `alloc` **by design** — lifecycle mutates the free list. That is
  the pattern "allocate once, borrow often" already steers away from.

The guidance softens but stands: for true linear scaling, **shard**. Separate
arenas share no counter and no metadata lines. What sharding buys now is escape
from one bouncing cache line rather than from a serializing mutex.

`secmem-crypto`'s signer benchmarks are deliberately paired with a stdlib
counterpart (`BenchmarkECDSASignerSignP256` next to
`BenchmarkECDSAStdlibSignP256`, and the same for RSA) because the delta *is*
the finding: it prices the per-signature re-parse that keeps the key off the
heap between operations. Report the pair, never the hardened number alone.

### Reporting rules

1. **A number without its machine is noise.** Always record CPU, kernel, and —
   critically — the CPU frequency governor and thermal state. `benchstat` over
   `-count=10` or more, not a single run.
2. **Never compare across machines.** Nothing in this repo's benchmark output
   is meaningful as a cross-box comparison, and the boxes the correctness
   suite runs on have deliberately different clock policies.
3. **Pin the clocks, or say you did not.** On DVFS-aggressive parts an
   unpinned run measures the governor, not the code.
4. **State the memlock budget.** Allocation benchmarks that exceed
   `RLIMIT_MEMLOCK` measure the failure path instead. `BenchmarkArenaAcquireRelease`
   raises it via `EnsureMemlockLimit` and skips per size when refused, which is
   the pattern to copy rather than a `b.Fatalf`.

### Not yet collected

**No arm64 benchmark numbers are recorded.** The arm64 hardware available for
this work is a Jetson Orin Nano whose clocks must be pinned for any number to
mean anything, and pinning them requires coordinating exclusive use of a box
that is another project's measurement instrument. Correctness ran there and is
recorded in [KERNELS.md](KERNELS.md); performance did not, and an unpinned
figure is worse than no figure because it looks authoritative. This section is
the placeholder, deliberately empty of numbers, until a pinned run happens.
