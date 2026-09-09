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
  which are otherwise dark in automation, including the Argon2 fork's proof
  that every worker goroutine's segment runs inside a real `secret.Do` window.
- **Executed on 32-bit x86** (`GOARCH=386`), not merely compiled — the wipe
  helpers manipulate `big.Word` limbs whose width differs on 386. Runs without
  `-race` (the detector needs 64-bit).
- **The no-heap-escape gates run where the deployed code runs.** The
  `testing.AllocsPerRun` gates are `//go:build !race`, so the race jobs skip
  them; dedicated `test-noescape` jobs run them on linux/amd64 and
  linux/arm64 (where `OpenInto`'s GCM path is assembly), and the 386 job runs
  them on the generic path.
- **No test skips silently.** Every test step runs `go test -json` through
  `internal/skipaudit`, which prints each skipped test with the reason its
  `t.Skip` gave and fails the job on any skip that is not on that lane's
  allowlist (`.github/skip-allowlist/<lane>.txt`, one reason per entry). A
  skip is a proof that stopped running; whether that is the environment or
  the claim is decided in a reviewed diff to the allowlist, not in a log
  nobody reads. The Windows list was measured; the Linux and macOS lists were
  derived from the `t.Skip` sites and the hosted runners' documented
  capabilities, and the first red run corrects them. The `memfd_secret`
  isolation and extraction proofs are deliberately **not** allowlisted on
  Linux, where `ubuntu-latest` has the feature live. Re-exec'd children
  propagate their skips to the parent (`childSkipReason`) so a child that
  proved nothing is not reported as a pass.
- **Locked-workspace tests cannot skip silently.** A step on each execution
  runner re-runs the Argon2 workspace, pool, vector-register-clear and
  upstream-identity tests verbosely and fails on any `--- SKIP`; on Linux it
  first raises `RLIMIT_MEMLOCK` with `prlimit`, because the hosted runners'
  hard limit is below the 64 MiB the package-default workspace needs.
- **The isolation proofs also run as root** (`test-root-linux`). The test
  binary is built unprivileged and executed under `sudo`, where the
  extraction test treats every environmental skip as a failure — root has
  nothing to be refused — and asserts that root's `/proc/<pid>/mem` read of
  the victim's secret page is refused while its read of the control page
  succeeds. The KSM opt-out proof, whose `PR_SET_MEMORY_MERGE` needs
  `CAP_SYS_RESOURCE`, runs there too. The lane's allowlist is empty.
- **`secmem-crypto` and `secmem-lint` are built and tested against their
  released dependencies** (`released-deps`): `GOWORK=off`, no `go.work`, so
  a change that needs core API newer than the tag in `go.mod` fails on the
  PR rather than for the first consumer. Every other job resolves the core
  from the sibling tree.
- **Cross-compiled** for linux/arm64, darwin/arm64, darwin/amd64, windows/arm64
  and windows/386 (build + vet + test-binary compile) so the whole matrix at
  least builds. The platforms with no secure-memory API — freebsd/amd64,
  openbsd/amd64, wasip1/wasm, which take the LOUD heap stub — are
  compile-checked the same way and **never executed** anywhere in CI; that is
  what the README's "other" column means by compile-checked.
- **Fuzz seed corpora** run as ordinary tests in CI on every PR. Active,
  coverage-guided fuzzing runs nightly (`fuzz.yml`): every `Fuzz*` target in
  every package of the core and `secmem-crypto` modules, three minutes each by
  default, with any new failing input uploaded as an artifact so a finding
  survives the runner. The Makefile's `fuzz` target is the local equivalent.
- **CodeQL** runs on every push and PR.
- **The guard-page fault proofs run out-of-process.** Recovering a hardware
  fault in-process with `debug.SetPanicOnFault` trips a Go runtime bug on
  windows/amd64 with AMX-capable CPUs
  ([golang/go#81238](https://github.com/golang/go/issues/81238)), so each
  probe re-execs the test binary, announces the address it will read, and
  lets the runtime kill the child. A "must fault" case is proven only by the
  runtime's own `unexpected fault address` report naming that address plus
  its throw exit status; any other death is inconclusive, and two control
  cases (a plain exit, a nil-dereference panic) pin that. Test harness only;
  no library path recovers faults. Details in [`WINDOWS.md`](WINDOWS.md).

## Core memory hardening

| Claim | How it is proven | Test |
|---|---|---|
| Secret bytes live off the Go GC heap | Structural (mmap / VirtualAlloc, never `make`); reported per allocation | `Capabilities.OffHeap`, `capabilities_test.go` |
| Pages are locked out of swap | Kernel's own `lo` (locked) flag read from `/proc/self/smaps` on **both** tiers — the anon+mlock area and the `memfd_secret` mapping (secretmem sets `VM_LOCKED` itself) | `madvise_linux_test.go` |
| Excluded from core dumps, not inherited across fork, no THP collapse (Linux) | The kernel's `VmFlags` for the secret area must carry `dd` (`VM_DONTDUMP`), `dc` (`VM_DONTCOPY`) and `nh` (`VM_NOHUGEPAGE`), on both tiers. The rule for a missing flag: if `Capabilities` claims the protection, missing is a **failure**; if it does not, the test re-issues the advice to obtain the kernel's refusal and skips with that reason — and if the kernel then accepts it, the allocator's own call was dropped, which fails. Every skip is a named subtest the CI audit sees | `madvise_linux_test.go` |
| No KSM deduplication of secret pages | `MADV_UNMERGEABLE` only clears `VM_MERGEABLE`, which a fresh mapping never has, so a plain process cannot show anything. A child opts the whole process into KSM with `PR_SET_MEMORY_MERGE` (Linux 6.4+), confirms with a control mapping that the kernel now marks new mappings `mg`, and requires the secret area to lack it. Needs `CAP_SYS_RESOURCE`: skips with `EPERM` unprivileged and runs in the root lane | `madvise_linux_test.go` (`TestMadvise_UnmergeableInForce`) |
| `memfd_secret` pages are unreadable via `/proc/<pid>/mem` | Reads the buffer's address range through `/proc/self/mem`, requires the read to **fail**, with a control read of ordinary heap that must **succeed** | `memfd_isolation_linux_test.go` |
| A **separate process** cannot extract a `SecureBuffer` — including root | A victim subprocess holds the secret only in a `memfd_secret` buffer and a twin control marker on the heap; its parent scans the victim's whole address space via both `/proc/<pid>/mem` **and** `process_vm_readv(2)` — the control marker is recovered every time, the secret never, and a direct read of the secret page must be refused outright. Unprivileged, it skips (never fails) when `memfd_secret` or ptrace is unavailable; as root (`euid 0`) every such condition is a **failure**, and the `process_vm_readv` control must succeed. CI runs it both ways (`test` and `test-root-linux`). The `gcore` core-dump variant remains a manual run recorded in [KERNELS.md](KERNELS.md) | `extraction_linux_test.go` |
| `Destroy` deterministically zeroes the secret | A slab slot is written `0xFF`, released (running the production wipe on the mapped region), re-acquired, and read back as zero | `securearena_test.go` (`TestArena_ReleaseWipesSlot`) |
| The region wipe holds for arbitrary sizes and contents | Fuzzed, over the three wipes whose target stays mapped: `Truncate`'s tail read back through the slice's full capacity with the head intact; `WipeAllSecrets` read back over the whole secret area, canary slack included; and every arena slot filled, released, re-acquired and read as zero. An allocation refusal skips loudly, never returns silently | `wipe_fuzz_test.go` (`FuzzWipe_RegionReadsBackZero`) |
| The wipe is exact and not compiler-elided | Assembly (`REP STOSB` / `DC CIVAC`) is inherently un-elidable. The generic fallback takes its zero byte from a package-level atomic (so the stored value is not a compile-time constant), reads every byte back into an accumulator, and publishes the accumulator to a second atomic, so the stores are provably observed; `//go:noinline` stops a caller re-deriving what the body cannot. Confirmed in the GOARCH=386 disassembly — both loops and both atomics survive. The readback tests above would fail if a store were dropped | `wipe_unaligned_test.go`, `wipe_arm64.s`/`wipe_amd64.s`, `wipe_generic.go` |
| Guard pages trap a linear over/under-flow | Reads one byte past each edge in a re-exec'd child and requires the runtime's fault report at that address; in-region bytes must not fault (clean child exit) | `guard_canary_test.go`, `fault_probe_test.go` |
| An in-mapping overflow too small to reach a guard is caught | Corrupts the canary slack, requires `ErrCanaryViolation` on Destroy/Release | `guard_canary_test.go`, `securearena_test.go` |
| No two live `ArenaSlot` handles ever address the same slot | Walks the intrusive free list directly after every acquire/release and asserts it terminates, revisits nothing, and agrees with the parity-encoded generations and the live counter; plus a concurrent double-`Release` stress that must not splice an index onto the list twice. The drain loop is bounded on purpose — a list cycle would otherwise hang the suite instead of reporting it | `securearena_freelist_test.go` |
| An arena's Go-heap bookkeeping stays smaller than its locked slab | Arithmetic pin: per-slot `slotMeta` must be under `canaryLen+1`, the locked cost of the smallest legal slot. This is what makes `NewArena`'s slab-first allocation order protective — the allocation that can `throw` must be the smaller one | `securearena_test.go` (`TestArena_HeapMetadataStaysUnderLockedSlab`) |
| `Scrub` erases the stack residue of a shallow call tree | Plants markers down the stack, runs `Scrub`, reads the abandoned frames back through a raw `uintptr` and requires zero. Covers both architectures with real frame assembly — amd64 and arm64 | `scrub_frame_test.go` (`TestScrub_ScrubsShallowCallTree`); `runtimesecret` integration in `securebuf_scrub_test.go`, `secretdo_active_test.go` |
| A `Scrub` window blocks the preemption signal, so `asyncPreempt` cannot spill the register file into it | Reads `SigBlk` for the **calling thread** from `/proc/thread-self/status` — the kernel's own record — inside the window, and requires SIGURG and SIGPROF set there and the mask exactly restored after. Asserts the goroutine did not migrate (`LockOSThread`), and that a nested window restores the outer mask rather than unblocking | `scrub_window_linux_test.go` |
| `Scrub` clears the vector registers on the thread that ran `fn`, and the clear reaches what `fn` left | A test-only assembly probe (`internal/regprobe`) plants a non-zero pattern in X0–X14 (Z16–Z31 under AVX-512; V0–V31 on arm64) inside a window and reads the file back after it: all zero after `Scrub`, `ScrubErr`, and a panicking `fn`. A control runs the window's exact exit sequence **without** the clear and requires the pattern to survive — a zero there is a failure, not a skip, because it would mean the residue had become unobservable and the clear unprovable. A panicking control measures the 16 bytes the runtime's unwinder writes after the clear, and the subject must be zero outside that footprint. The control is a hand-written copy of `Scrub`'s body (the two cannot share a helper: nothing may run between `fn`'s return and the clear), so a source-level pin parses both and requires the control's statements to equal `Scrub`'s less the nil guard and the deferred clear — shown to fail on an injected extra call | `scrub_vecclear_test.go`, `scrub_vecclear_amd64_test.go`, `scrub_vecclear_arm64_test.go`, `scrub_vecclear_control_pin_test.go` |
| Blocking that signal does not make a window unpreemptible | Eight concurrent windows against a deliberately GC-heavy workload must all complete; a window the collector could not suspend would hang rather than fail quietly | `scrub_window_linux_test.go` (`TestScrub_ConcurrentWindowsUnderGCPressure`) |
| Constructors fail closed, never panic | Bad/overflow inputs on every constructor; `RLIMIT_MEMLOCK=0` with `CAP_IPC_LOCK` dropped; unsupported-platform stub | `negative_test.go`, `negative_mlock_linux_test.go`, `mlock_stub_test.go` |
| Constructors wipe the caller's input on failure, not only on success | An allocation that is forced to fail must leave the input slice zeroed | `securebuf_test.go` (`TestNewBuffer_WipesInputOnFailure`), `secret_test.go` (`TestNewSecret_CopiesAndWipesInput`) |
| A reversed `ConstantTimeEqual` cannot deadlock | The two read locks are shown to be taken in `LockOrder` order regardless of argument order, under a forced interleaving | `secret_test.go` (`TestSecret_ConstantTimeEqual_AcquiresInKeyOrder`), `securebuf_lockorder_test.go` |
| The emergency wipe never zeroes a buffer whose lock it does not hold | A registration re-handed the same base address after a destroy-during-wait is refused rather than wiped | `registry_emergency_test.go` (`TestWipeInPlace_RefusesAliasedRegistration`) |
| The termination wipe ends the process, and stays armed when it does not | Where the signal cannot be re-raised the exit status equals the un-intercepted one (`STATUS_CONTROL_C_EXIT` on Windows, checked against a real console Ctrl-C); a handler that leaves the process running re-arms for the next signal | `terminationwipe_exit_test.go`, `terminationwipe_rearm_*_test.go` |
| Borrow/copy/compare paths do not allocate (no heap escape) | `testing.AllocsPerRun` gate asserts 0 allocs on `WithBytes`/`ByteAt`/`CopyOut`/`CopyIn`/`ConstantTimeEqual`/… | `alloc_test.go` |
| A sealed buffer holds ciphertext at rest (Windows) | Peeks the raw mapping while sealed and asserts the plaintext is absent (and not all-zero) | `sealcipher_windows_test.go` |
| `HardenProcess` puts Arbitrary Code Guard and strict handle checks in force (Windows) | Read back through `GetProcessMitigationPolicy` in a re-exec'd child (ACG is irreversible): both policies must be clear before `hardenProcess` and `ProhibitDynamicCode`, `RaiseExceptionOnInvalidHandleReference` and `HandleExceptionsPermanentlyEnabled` set after — the kernel's record of the process, not the setter's return value | `harden_windows_test.go` (`TestHardenProcess_Windows`) |
| The secret area is registered for WER dump exclusion (Windows) | WER's own bookkeeping, the only readback that exists: `WerUnregisterExcludedMemoryBlock` returns `S_OK` for a block it holds and `ERROR_NOT_FOUND` for one it does not; a never-registered control page pins the distinction, the secret area must read as registered, and the registration is restored afterwards. This proves the registration, not that a dump would honour it — see below | `harden_windows_test.go` (`TestWERExclusion_RegisteredWithWER`) |
| `Secret` / `redact` never emit the plaintext | Formatting/marshalling/slog routed through `any` so the verb can't be folded; adversarial and fuzzed inputs | `secret_test.go`, `negative_test.go`, `redact/*_test.go` |

## secmem-crypto: correctness and secret hygiene

| Claim | How it is proven | Test |
|---|---|---|
| Ed25519 matches RFC 8032 | All 5 official vectors, byte-identical differential vs `crypto/ed25519`, differential fuzz, and an S < L malleability check | `ed25519direct_test.go`, `fuzz_test.go` |
| ECDSA deterministic mode matches RFC 6979 | Six appendix vectors (P-256/384/521, SHA-256), byte-identical differential vs `crypto/ecdsa`, differential fuzz | `ecdsa_test.go`, `fuzz_block3_test.go` |
| X25519 matches RFC 7748 | §6.1 vectors both directions, differential fuzz vs `curve25519`, low-order-point rejection | `x25519_test.go`, `fuzz_block2_test.go` |
| HKDF matches RFC 5869 | Test cases 1–3 (SHA-256), differential vs `x/crypto/hkdf`, hash agility | `kdf_test.go` |
| Argon2 is the standard function | RFC 9106 §5 vectors for Argon2d/i/id (K and X set), the `x/crypto/argon2` reference KAT, and a differential table plus fuzz target against `x/crypto` | `secmem-crypto/argon2_public_test.go`, `secmem-crypto/kdf_test.go`, `secmem-crypto/internal/argon2/argon2_test.go` |
| Argon2's working state is wiped | The test owns the workspace and asserts every region is non-zero after the derivation (control) and zero after the wipe, and that the named views tile the region exactly | `secmem-crypto/internal/argon2/wipe_test.go` |
| The core's vector-register clear reaches what `secmem-crypto`'s windows leave | The fork's own clear is gone; these tests show the clear at the end of the `Scrub` window covers it. Argon2: the SSE blamka run bare must leave block state visible in X0–X15 (control; a zero is a failure, not a skip), the same step inside a worker-shaped `Scrub` window and a whole `Derive` must leave the file all zero. The passphrase path: `opensshCrypt` (SHA-512 and AES-NI) run bare must leave residue, run inside the `ScrubErr` window its callers use must leave none. Pinned to one thread for the whole sequence; the dump is a test-only assembly probe (`secmem-crypto/internal/regprobe`) | `secmem-crypto/internal/argon2/scrubclear_amd64_test.go`, `secmem-crypto/vecclear_amd64_test.go` |
| Each Argon2 worker's segment runs inside a `runtime/secret` window | Under `GOEXPERIMENT=runtimesecret` a test hook (nil in production) asks the runtime from inside every segment whether it is in `secret.Do`, with a plain-goroutine control that must answer no | `secmem-crypto/internal/argon2/runtimesecret_test.go` (`TestWorkersRunInsideSecretDo`) |
| A locked Argon2 workspace derives the same bytes, in either lock order, and is zero between uses | `Argon2Workspace.Derive` against `Argon2Into` and `x/crypto` with the output buffer registered before and after the workspace; the region read back after a derivation; a pool shared by eight goroutines; Derive after Destroy errors. These tests skip when the lock budget cannot hold the workspace, so CI re-runs them verbosely and fails on a skip (see above) | `secmem-crypto/argon2_workspace_test.go` |
| The Argon2 fork matches its upstream where it claims to | `blamka_amd64.s` byte-identical and the verbatim functions text-identical to the resolved `golang.org/x/crypto` | `secmem-crypto/internal/argon2/upstream_identity_test.go` |
| bcrypt_pbkdf is the standard function | OpenBSD's reference vectors (upstream's own), a differential test of the forked Blowfish schedule against `x/crypto/blowfish`, and end to end: files a real ssh-keygen and x/crypto/ssh encrypted open here, and files encrypted here open with x/crypto/ssh and with ssh-keygen itself (run when installed) | `secmem-crypto/internal/bcryptpbkdf/bcrypt_pbkdf_test.go`, `blowfish_test.go`, `secmem-crypto/parse_encrypted_test.go`, `secmem-crypto/marshal_openssh_test.go` |
| bcrypt_pbkdf's working state is wiped | The test owns the workspace and asserts every region non-zero after a derivation (control) and zero after the wipe, that the named views tile the struct exactly, and that the passphrase never enters the salt reserve | `secmem-crypto/internal/bcryptpbkdf/wipe_test.go` |
| `BcryptPBKDFInto` is bcrypt_pbkdf, through the exported entry point | OpenBSD's reference vectors run through the public function (which is what fixes the argument order and the rule that `out.Len()` is the key length), plus an independent interoperability pin: for four ssh-keygen fixtures the salt and rounds are read from the file, the 48-byte key and IV derived here, and the private block decrypted with `crypto/aes` and `cipher.NewCTR` alone — the format's duplicated check integers must match, and a control at `rounds+1` must fail to open the same file. Also pinned: that the output length is an input, not a truncation (a 32-byte derivation is not a prefix of a 64-byte one) | `secmem-crypto/bcrypt_pbkdf_test.go` |
| `BcryptPBKDFInto` allocates nothing on the heap | The same memory-profile attribution as the parse and marshal proofs, at rate 1, with no allowance for an AES block because this path has none: any object owned by `bcrypt_pbkdf.go`, or by the scratch helper in `openssh_wire.go` it shares with the passphrase paths, fails the test. Shown to fail against a planted escaping allocation | `secmem-crypto/parse_proof_encrypted_test.go` |
| A chosen bcrypt cost is written and honoured | The count the caller asks for is read back out of the marshalled file's header — which separates "the parameter was used" from "the parameter was accepted and ignored", as a round-trip through this package alone cannot — and the file is then opened by this package, by `x/crypto/ssh`, and by a real ssh-keygen at costs either side of the default | `secmem-crypto/marshal_rounds_test.go` |
| This package never writes an OpenSSH file its readers would refuse | The write cap is anchored to `x/crypto/ssh`'s own maximum, not to itself: x/crypto is handed a header claiming 2^30 rounds, which it refuses before running the KDF in an error naming the maximum it enforces, and that number must equal `MaxOpenSSHKDFRounds`. Drift in either direction fails instantly. This package's own gate is then pinned at the same boundary by patching a header to each side of it and making the private block an odd length, so the parse stops at the check immediately after the rounds gate: `ErrUnsupportedKey` means the gate fired, `errMalformed` means the file got past it. Neither test pays for a derivation at the cap, which would cost about half a minute per CI job to prove the same thing less precisely | `secmem-crypto/marshal_rounds_test.go` |
| Legacy PEM encryption stays refused, and says so as a decision | Both entry points are given `Proc-Type` / `DEK-Info` files across the DES, 3DES and AES `DEK-Info` ciphers; each refusal must wrap `ErrRetiredAlgorithm` alongside its usual sentinel, and each — the plain entry point as much as the passphrase one — must name the command that converts the file. The complementary test is what gives the marker meaning: everything refused as merely unimplemented — `chacha20-poly1305@openssh.com`, aes128/192, an unknown KDF, PKCS#8 PBES2 — must **not** wrap it, so the marker cannot decay into a synonym for `ErrUnsupportedKey` | `secmem-crypto/retired_test.go` |
| The bcrypt_pbkdf fork matches its upstream where it claims to | `const.go` byte-identical below the package clause, the verbatim functions text-identical, and the golden vectors identical to the resolved `golang.org/x/crypto` | `secmem-crypto/internal/bcryptpbkdf/upstream_identity_test.go` |
| The private-key parser puts nothing secret on the heap | Memory profiler at rate 1 over every unencrypted encoding; any allocation owned by the parser's files outside the allowlist (core buffer bookkeeping, cryptobyte's OID slices) fails; shown to fail on an injected `bytes.Clone` of the seed | `secmem-crypto/parse_proof_test.go` |
| The passphrase paths put nothing on the heap but the AES Block | The same proof over the encrypted parse and both marshal forms, with the AES packages and crypto/rand's reader bookkeeping allowlisted. During development it caught CTR scratch escaping through the `cipher.Block` interface, per-call reflection, and a cipher name boxed by an error formatter | `secmem-crypto/parse_proof_encrypted_test.go` |
| The reflection-based AES round-key wipe cannot silently no-op | Tripwire: both fields resolve to non-zero 240-byte schedules, the wipe succeeds, and the cipher no longer computes AES afterwards (an oracle independent of reflection); an unresolvable layout is an error the parse and marshal paths fail on rather than ignore | `secmem-crypto/aeswipe_test.go`, `parse_encrypted_test.go`, `marshal_openssh_test.go` |
| The hand-written CTR and CBC match `crypto/cipher` | Differential over empty, partial, exact and long inputs, in place, with a counter that carries across all 16 bytes; the scratch is zero afterwards | `secmem-crypto/openssh_cipher_test.go` |
| The in-place PEM writer matches `encoding/pem` | Decode the output with `pem.Decode`, re-encode with `pem.EncodeToMemory`, compare bytes, at comment lengths on both sides of a 48-byte line boundary | `secmem-crypto/marshal_openssh_test.go` |
| **ML-KEM-768 keygen and decap agree with the standard library's FIPS 203 implementation** | Accumulated known-answer test: 100 deterministic rounds — keygen and both decapsulations through `MLKEM768Key`, encapsulation via the stdlib derandomized test helper — folded into a SHAKE128 digest matched byte-for-byte to `crypto/mlkem`'s own accumulated value. Conformance to the reference implementation (itself NIST-validated), not an independent NIST vector; a wrapper plumbing regression breaks the digest | `kat_test.go` |
| The AEAD wrapper preserves the cipher contract | A published AES-256-GCM vector threaded through `SealFrom` and `OpenInto` byte-for-byte | `kat_test.go`, `aead_test.go` |
| `OpenInto` lands plaintext in the buffer with no heap intermediate | `testing.AllocsPerRun` gate asserts 0 allocs | `alloc_test.go` |
| `OpenInto` fails loud when the AEAD did not write in place | An AEAD stub that returns a fresh slice makes the call error, with the stray heap plaintext wiped, instead of reporting success over an unwritten buffer | `aead_openinto_test.go` (`TestOpenInto_RejectsAEADThatDoesNotWriteInPlace`) |
| The reflection-based ECDH scalar wipe cannot silently no-op | A tripwire fails the suite if the standard library renames the field the wipe resolves, and an unresolvable field is reported as an error rather than ignored | `rsa_wipe_tripwire_test.go` |
| Diceware word selection is not a secret-dependent memory access | Every draw is shown to read every wordlist entry regardless of the index chosen, and the result matches a direct index for every entry | `passphrase_ct_test.go` |
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
  inspects cache state, because Go cannot. The README's "asm + cache flush"
  cell therefore means: the zeros are read back (above), the flush is not.
- **The WER dump exclusion is reported by the registration call, not
  verified by a dump.** The only oracle independent of the registration
  would be a real WER dump of the process with the pages missing, and a
  test cannot crash itself into WER and read the file back. What is tested
  (`TestWERExclusion_RegisteredWithWER`) is WER's own record that the block
  is registered; whether a dump honours it is Windows' contract, not
  measured here. The README's Windows "excluded from crash dumps" cell says
  the same.
- **The stack residue `Scrub` cannot reach is argued, not measured.** The frame
  wipe is proven to zero the band it reserves (above), and the preemption block
  is proven against the kernel's own record of the mask, and the vector-register
  clear is proven by planting a pattern and reading the registers back (above).
  Three residue sources remain unobservable from Go and are documented rather
  than tested: a GC stack-shrink that frees `fn`'s segment before the deferred
  wipe runs (`shrinkstack` is asynchronous and runtime-owned), the
  general-purpose registers at `Scrub`'s return (the ABI reloads them around any
  call that would clear them, so a Go-level clear of *those* cannot be verified
  to have reached anything — which is exactly why the vector clear ships with a
  proof and a general-purpose one does not exist), and the `ucontext` the kernel
  writes to the signal stack on a synchronous fault. The first is closed by
  `GOEXPERIMENT=runtimesecret`, which has runtime cooperation; the other two are
  constraints of Go and of the OS. All three are enumerated in the
  stack-residue section of [THREAT-MODEL.md](THREAT-MODEL.md).
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
- **`memfd_secret`'s close-on-exec flag is asserted structurally, not
  observed.** The descriptor exists only between the `memfd_secret` call and
  the `MAP_FIXED` that maps it, and is closed before the constructor returns,
  so no test can inspect the flag from outside; the `EINVAL` fallback that
  sets it with `fcntl` is likewise unexercised on the kernels the suite has
  run on. The flag is passed at creation in `mlock_linux.go`, and that is the
  extent of the evidence.
- **That `HKDFInto`'s Extract step runs inside its scrub window is a code
  property, not a measured one.** The v0.4.0 fix moved the `hkdf.New` call
  under `secmem.ScrubErr`; nothing observes from outside which code ran
  inside the window, so the ordering is reviewed, not tested.
- **Argon2 is pinned to RFC 9106's §5 vectors and to `x/crypto`.** The RFC
  vectors set a secret key and associated data, which `Argon2Into` exposes
  (`golang.org/x/crypto/argon2` does not); the in-tree fork is additionally
  checked byte-for-byte against `x/crypto` on the no-K/no-X profile the
  mainstream bindings share, by a fixed table and a differential fuzz target.

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
