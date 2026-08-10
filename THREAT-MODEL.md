# secmem threat model

This document states plainly what secmem does **not** protect against. The
per-platform matrix of what it *does* provide is in [README.md](README.md) and,
authoritatively, in the godoc; this is the other half of the honesty contract.

## What secmem is for

secmem reduces the window and the surface in which a secret is exposed in
process memory:

- It keeps secret bytes off the Go GC heap (so they are not scanned, moved, or
  copied by the collector), locked out of swap, and — on 64-bit Linux
  (amd64/arm64) with `memfd_secret` — hidden from other readers of process
  memory.
- It wipes them deterministically on `Destroy`, with an architecture-specific
  routine the compiler cannot elide.
- It makes accidental exposure harder: `Secret` redacts itself through `fmt` /
  `json` / `slog`, guard pages trap linear overflows, and the `redact`
  subpackage scrubs log text.

## What secmem does NOT protect against — on any platform

State these plainly; do not let the guarantees above be read as more than they
are.

- **Cold-boot and full-RAM capture.** If an attacker images all of physical
  memory (freeze-and-dump, DMA, a hypervisor snapshot), any software scheme is
  defeated, because the keys needed to use the secret are captured alongside
  it. The answer to this threat is hardware memory encryption (Intel TME, AMD
  SME/SEV) or a secure enclave — not a userspace library. secmem does **not**
  encrypt secrets at rest in RAM under a rotating key, and does not claim to.

- **A privileged (root / kernel) adversary.** On platforms without
  `memfd_secret` — i.e. everywhere except 64-bit Linux (amd64/arm64) ≥ 5.14
  with `CONFIG_SECRETMEM` — `mlock` and `VirtualLock` stop swapping but do
  **not** stop a sufficiently privileged process, a debugger, or the kernel
  from reading the pages. Where `memfd_secret` *is* live it removes the pages
  from the kernel's direct map and defeats the **passive** reads a privileged
  attacker or a crash dump relies on — `/proc/<pid>/mem`, `ptrace`,
  `process_vm_readv`, core dumps — which is exactly the bound the extraction
  proofs in [KERNELS.md](KERNELS.md) establish. It does **not** stop an
  adversary who can execute code in the kernel itself (a loaded module, a
  lockdown-off kernel): ring-0 code can still walk the owning process's page
  tables to the physical pages. The isolation is against readers of process
  memory, not against a compromised kernel.

- **Other bus masters on a unified-memory SoC.** `mlock` and `VirtualLock`
  constrain the *CPU's* view: they keep pages off the swap device and resident.
  They say nothing about the other engines on a UMA part — the integrated GPU,
  NPU/DLA, ISP, DSP, video codec — which sit on the same physical DRAM with no
  separate VRAM to be confined to. Whether such an engine can reach a locked
  secret page is a property of the SoC's SMMU/IOMMU configuration and the
  vendor's driver stack, not of anything secmem does or can check. This is the
  normal case, not an exotic one: Tegra, Apple Silicon, Snapdragon, AMD APUs,
  and essentially every ARM SBC are unified-memory designs.

  `memfd_secret` is the only mechanism in the library that would narrow this,
  and only partly — it removes pages from the kernel's *direct map*, which is a
  CPU-side mapping, not a device-side one. Worse, the platforms where this
  matters most are disproportionately the ones where `memfd_secret` is
  unavailable: it requires the kernel to be able to split the linear map at
  page granularity, which several vendor SoC kernels disable (measured on a
  Jetson Orin Nano — see [KERNELS.md](KERNELS.md)). Read `Capabilities` and
  assume nothing.

  If your adversary model includes hostile or buggy code driving an on-die
  accelerator, a userspace memory library is not the control you want.

- **Secrets you copy out of the borrowing closure.** The moment plaintext lands
  in a `string`, an escaping `[]byte`, or a value logged with `%v`, it is
  outside secmem's control and subject to normal GC lifetime. Keep work inside
  `WithBytes`/`WithBytesErr`; do not retain the borrowed slice.

- **The in-use window.** A secret that is actively being used (a signing key
  mid-operation) is plaintext in memory for that time, by necessity. Protection
  is proportional to dormancy; `Seal` the buffer when it is not in use.

- **Code executing inside the process.** Nothing here defends against an
  attacker who already runs code in your address space — such code can call the
  same access methods you can. secmem raises the bar against passive exposure
  (swap, dumps, adjacent overflows, stray logs), not against in-process code
  execution.

- **An oversized allocation can kill the process — availability, not
  confidentiality.** Go has no recoverable out-of-memory. When the OS refuses a
  heap allocation the runtime calls `throw`: no deferred function runs, nothing
  `recover`s it, and `WipeAllSecrets` is never reached. A library cannot make
  `make()` return an error, so the only lever is not attempting the allocation.
  secmem's containers therefore request their **locked** memory first — that one
  fails by returning an error — and keep their Go-heap bookkeeping strictly
  smaller than it, so a request too large for the machine is refused cleanly
  instead of fatally. The residue is bounded rather than eliminated: a count is
  fatal only in the band where the slab fits and the bookkeeping does not, which
  is `1 + heap/locked` wide in count — under a factor of two for every arena
  shape, because the per-slot heap cost is held below the per-slot locked cost.
  Reaching that band needs an unbounded `RLIMIT_MEMLOCK`: raise the limit to
  unlimited, as many container images do, and a large enough
  `NewArena` count can still reach the fatal path. Nothing is disclosed when it
  does — the pages were locked, excluded from dumps, and Go does not write a
  core by default — so this is a denial-of-service bound on sizes taken from an
  untrusted source, not a leak. Bound them yourself, and see
  `EnsureMemlockLimit`, which raises the ceiling this guard rests on.

- **GC timing of `runtime/secret` heap erasure.** When `Scrub` runs under
  `GOEXPERIMENT=runtimesecret`, heap allocations made inside it are erased once
  the collector observes them unreachable — best-effort timing, never a
  synchronous guarantee. Do not cite it as a compliance control.

## Stack residue: what `Scrub` reaches, and what it does not

A `SecureBuffer` governs where a secret *lives*. It says nothing about the
copies a computation makes of it — register spills, round keys, scalar
temporaries — which land on the goroutine stack. `Scrub` exists for that band.
It is the part of the library most easily over-read, so its exact reach is set
out here rather than left to the godoc.

### Why the stack specifically

Go's garbage collector is **non-moving for heap objects**: a `[]byte` on the
heap keeps one address for its whole life, so there is no hidden second copy of
it to hunt down. The goroutine *stack* is the exception — the runtime copies it
at moments your code does not choose:

- **Growth.** A goroutine starts on 8 KiB. When a call needs more, `morestack`
  allocates a larger stack, copies the old one into it, and frees the old
  segment. Whatever was on that segment stays there, unwiped, until the runtime
  reuses the memory for something else.
- **Shrinking.** While scanning a goroutine, the collector may move it to a
  smaller stack (`shrinkstack`) — another copy, another abandoned segment.
- **Asynchronous preemption.** The runtime sends the thread SIGURG, and the
  handler, `runtime.asyncPreempt`, saves *all user registers* onto that
  goroutine's stack before entering the scheduler. That is the entire register
  file, general-purpose and vector, spilled at an instruction boundary nothing
  chose. One landing mid-cipher-round writes live key material to the stack at
  an offset nothing tracks.

### What Scrub does about it

On entry it calls a 32 KiB assembly frame wipe, and defers a second call to the
same routine. The entry call is not redundant: it forces any stack growth to
happen *before* `fn` writes a secret, so the deferred wipe is guaranteed to run
on the stack the residue is actually on rather than on a fresh copy of it.
Reported as `Capabilities.FrameScrub` — real assembly on amd64 and arm64, a
no-op stub elsewhere.

On Linux the window additionally blocks SIGURG and SIGPROF for its duration,
under `runtime.LockOSThread` (a signal mask is a per-thread property, and an
unpinned goroutine can migrate to a thread where the mask was never set). That
removes the asynchronous register dump rather than trying to erase it after the
fact. Reported as `Capabilities.AsyncPreemptSuppressed`.

Blocking the preemption signal does **not** stall the collector: `suspendG` sets
the cooperative request (`gp.preempt`, `gp.stackguard0 = stackPreempt`) *before*
it signals, so any ordinary function call inside the window still yields. The
one shape that would hang is an unbounded loop containing no function calls at
all. Keep `fn` short and call-bearing, which the borrowing contract already asks
of it.

### What remains, and which parts are constraints rather than defects

Bounded by design, and tunable in principle:

- **A call tree deeper than the 32 KiB band** — the tail below it survives.
- **A stack relocation triggered *inside* `fn`**, if `fn` exceeds the reserved
  headroom; the deferred wipe then cleans the new stack, not the abandoned one.

Constraints of the Go runtime, not defects in this library:

- **A GC stack-shrink between `fn`'s return and the deferred wipe.**
  `shrinkstack` is asynchronous, runtime-owned, and unreachable from Go; if it
  frees `fn`'s segment first, the wipe runs on the copy. Only the
  `runtime/secret` path (`Capabilities.RegisterScrub`, i.e.
  `GOEXPERIMENT=runtimesecret`) closes this, because it has runtime cooperation.
- **Cooperative preemption is unaffected.** A long window can still be
  descheduled at a call boundary and have its stack scanned, and possibly
  copied. Suppressing the signal removes the arbitrary-instruction register
  dump, not every stack copy.
- **The registers themselves at `Scrub`'s return.** A Go-level "clear the
  registers" step cannot be trusted, because the ABI reloads registers around
  the very call that would do the clearing. An unverifiable scrub is worse than
  none, so the legacy path does not pretend to one; `runtime/secret` does it
  properly, with the runtime's cooperation.

Constraints of the OS:

- **A synchronous fault inside the window.** A SIGSEGV or SIGBUS makes the
  kernel write a full `ucontext` — the complete register set — to the signal
  stack. This is identical in C and is not addressable from userspace.
- **Windows cannot suppress preemption at all.** It does not deliver a signal;
  it calls `SuspendThread` and rewrites the thread context with
  `SetThreadContext`. Nothing in userspace masks that.

A deliberate omission, stated as one rather than dressed up as a platform limit:

- **Darwin has `pthread_sigmask`, but `golang.org/x/sys/unix` exposes no
  binding for it.** Reaching past that to a raw syscall would assert a security
  property on a platform this project has no execution coverage for. It stays
  unsupported, and `Capabilities` reports it as unsupported.

## Platform-specific limits

- **`MADV_DONTDUMP` / `MADV_DONTFORK` are best-effort on Linux.** A kernel that
  does not support a flag simply does not apply it; the outcome is reported in
  `Capabilities`, never silently assumed.

- **Windows dump exclusion covers WER dumps only.**
  `WerRegisterExcludedMemoryBlock` keeps the secret out of Windows Error
  Reporting crash dumps; a debugger-driven `MiniDumpWriteDump` by another
  process still captures the pages. For a dormant secret, `Seal` additionally
  encrypts the contents with a kernel-held key (`CryptProtectMemory`), so a
  dump taken while sealed contains ciphertext — but the key is in kernel RAM,
  so this is dump hardening, not cold-boot protection.

- **The guard pages and canary are a bug-catcher, not a confidentiality
  control.** They turn an accidental adjacent over/under-flow into a fault or a
  reported violation. They do nothing against an attacker who can already read
  the mapping.

- **The insecure fallback is exactly that.** `WithInsecureFallback()` places
  secrets on the unprotected Go heap on platforms with no lockable off-heap
  memory. `Capabilities.Insecure` is then true, `Warnings()` leads with the
  exposure, and a one-time warning is logged. Use it only when you have
  accepted the risk.

## Post-quantum posture

The `secmem-crypto` module ships `MLKEM768Key`, at-rest custody for an
ML-KEM-768 (FIPS 203) decapsulation secret. Be precise about what that is
and is not.

- **It is memory hardening applied to a post-quantum key, not a
  post-quantum protocol.** `MLKEM768Key` keeps the 64-byte KEM seed off the
  GC heap for its lifetime and expands it per operation; it does not perform
  key agreement, negotiate parameters, or make a surrounding protocol
  quantum-resistant on its own. The expanded decapsulation key transiently
  touches the heap during each operation — `crypto/mlkem` exposes no in-place
  path — so the seed is hardened at rest and the expansion is not. The type's
  godoc states this inline.

- **The urgent PQ threat is a transport concern secmem does not own.**
  "Harvest now, decrypt later" — recording ciphertext today to break with a
  future quantum computer — is defeated at the key-exchange layer, and Go's
  `crypto/tls` has defaulted to the `X25519MLKEM768` hybrid there (as its top
  preference) since Go 1.24. secmem-crypto hardens where a long-lived KEM
  secret *lives*; it is not a substitute for a post-quantum handshake.

- **Post-quantum signatures (ML-DSA / FIPS 204) are deferred, deliberately.**
  The Go standard library does not yet ship `crypto/mldsa` (as of Go 1.26),
  and secmem-crypto will not vendor a third-party PQ implementation — the
  same discipline that governs the rest of the module: work around the
  standard library only where it is broken for off-heap keys, never merely to
  add an algorithm. A hardened ML-DSA signer follows if and when the standard
  library ships the primitive.

## Composition

secmem is a byte/secret container with a hardened lifecycle; it is not a
RAM-encryption vault. For the cold-boot axis it does not cover, it composes
with a rotating-key in-RAM scheme rather than replacing one. Use the right tool
for the threat you actually face, and read `Capabilities` at startup so you
know which protections your build and platform actually provide.
