# secmem design

This document explains *why* secmem is built the way it is. It is the
companion to [THREAT-MODEL.md](THREAT-MODEL.md) (which says what is and
isn't defended) and [TESTING.md](TESTING.md) (which says how each claim is
proven). Here the question is: given the threat model, why these mechanisms,
in this arrangement, and what does each layer buy?

The organizing idea is that there is no single defense. A secret in memory
is exposed to swap, to crash dumps, to other processes reading your address
space, to the garbage collector copying it, to overflows in unrelated code,
and to its own persistence after you're done with it. Each of those is a
different mechanism, so secmem is a *stack* of independent protections, each
one closing a specific hole, arranged so that the failure of one does not
open another. What follows walks the stack from the allocation outward.

## Why the memory lives off the Go heap

Every other decision depends on this one. A `[]byte` from `make` lives on
the Go heap, and the garbage collector is free to *move* it (copying the
bytes to a new location and leaving the old copy as un-zeroed garbage until
it is reused) and to *scan* it. You cannot pin it, you cannot reliably wipe
it (you might be wiping a stale copy), and you cannot apply page-level
protections to it because you do not own the page — the runtime does.

secmem therefore allocates secret memory with `mmap` (Unix) or
`VirtualAlloc` (Windows), entirely outside the Go heap. The GC never scans,
moves, or copies it. This is what makes wiping meaningful (there is exactly
one copy, at an address that never changes) and what makes every
page-protection mechanism below even possible. It is also why the public
API never hands out the backing slice by value: the borrowing methods
(`WithBytes`, `WithBytesErr`) lend it inside a closure, and the linter
(`secmem-lint`) statically rejects code that lets that slice escape — a heap
copy of the secret would defeat the entire premise, so the one way to create
one is a compile-time error rather than a runtime hope.

The cost is that constructing secure memory is a syscall, not a bump
allocation, and that on platforms with no lockable off-heap memory secmem
*refuses to run* rather than silently placing secrets on the heap — a caller
who accepts that exposure has to say so explicitly with
`WithInsecureFallback`. Refusing by default is the honest posture: a
security library that quietly degrades is worse than one that stops.

## Why the pages are locked (mlock / VirtualLock / memfd_secret)

Off-heap memory can still be swapped to disk by the kernel, and a swapped
page is a plaintext secret written to persistent storage, outliving the
process and often surviving a reboot. `mlock` (Unix) and `VirtualLock`
(Windows) pin the pages in RAM so they are never written to swap.

On Linux, where it is available, secmem prefers `memfd_secret` (kernel
5.14+). This is stronger than mlock in kind, not degree: the pages are
removed from the kernel's direct map, which means they are excluded from
swap *and* are unreadable through `/proc/<pid>/mem`, ptrace, and process
core dumps — even by the same user, even by root without defeating kernel
protections first. mlock keeps the secret off disk; `memfd_secret` also
hides it from other views of your own process's memory. Because it can fail
per-allocation (config-dependent), secmem probes for it and reports through
`Capabilities` exactly what a given allocation got, rather than assuming.

## Why guard pages, and why they are PROT_NONE

Each secret allocation is bracketed by two guard pages —
`[ guard | secret pages | guard ]` — that are `PROT_NONE`: address space
with no backing frames, that faults on any access. They exist because the
most common way secret memory leaks is not an attack on the secret directly
but a *buffer overflow in adjacent code* that reads or writes past its
bounds and wanders into the secret. A `PROT_NONE` guard turns "silently read
the neighbouring secret" into "immediate, attributable SIGSEGV." The guards
are never wiped, never locked, never re-protected — touching them at all is a
bug — so the region code keeps a strict distinction between "the memory you
protect" (the inner secret pages) and "the memory you unmap" (the whole
reservation including guards).

## Why a canary as well as guard pages

Guard pages only catch an overflow that reaches a page boundary. An overflow
that stays *within* the mapping — writing a few bytes past the secret but
still inside the secret's own pages — would not hit a guard. So the slack
between the secret and the trailing guard holds a random canary, verified at
`Destroy`/`Release`. A modified canary means some code in this process wrote
past the end of a buffer: `ErrCanaryViolation`, reported but never fatal —
the wipe and unmap always complete. This is a memory-safety assertion, a bug
report about *your* process, complementing the guard pages' coverage of the
larger overshoots.

## Why Seal / Unseal exists on top of locking

mlock and `memfd_secret` protect the secret while the process is behaving.
They do nothing about a read primitive *inside* the process — a
use-after-free, an out-of-bounds read gadget, a logging bug — that discloses
whatever memory it can reach. `Seal` addresses the long tail of idle time:
it sets the secret region to `PROT_NONE`, so while sealed a stray read
anywhere in the process *faults* on the secret instead of disclosing it, and
on Windows it additionally encrypts the contents (`CryptProtectMemory`) so a
dump taken during the sealed window contains ciphertext.

The design intent is the "dormant-key pattern": a long-lived secret (an SSH
agent's key, a service's signing key) spends almost all of its life sealed,
and is unsealed only for the microseconds of an actual use, under a lock,
then resealed — including on error paths. The
[`hardened-ssh-agent`](examples/hardened-ssh-agent/) example is this pattern
carrying a real workload. Seal is explicitly *not* a defense against code
executing in the process (it can call `Unseal` itself) or cold-boot capture
(the kernel's own key is in RAM too); it shrinks the window in which a
disclosure bug can reach a plaintext secret from "always" to "the moment of
use."

### Why ReadOnly is a flag *and* a page protection

`ReadOnly` sets the region to `PROT_READ`, so a stray *write* through a
retained pointer faults rather than corrupting the secret. But a write
through the library's own mutating methods (`CopyIn`, `SetByteAt`,
`Truncate`, `ReadFrom`) would also hit that `PROT_READ` page and fault the
process — which contradicts the library's rule that *misuse returns an
error, never crashes*. So read-only is tracked as a struct flag as well: the
mutating methods check it and return `ErrReadOnly` at the API boundary, and
the page protection is the backstop for raw-pointer writes that bypass the
methods. Two layers for one property, because they cover different bypasses.

Because the flag is the source of truth, it is preserved across a seal cycle:
`Seal` lifts the `PROT_READ` protection for the moment it must write (the
Windows seal cipher encrypts in place), and `Unseal` re-applies it — so a
read-only buffer that spends hours sealed is still read-only when it wakes,
and the physical page protection always matches the flag.

This split was added after `FuzzBufferLifecycle` drove the buffer through
arbitrary operation sequences and found that the page protection existed but
the flag did not, so a mutating method wrote to `PROT_READ` and *faulted*
instead of refusing. The same gap hid two siblings the first patch missed:
`ReadFrom` had the identical fault (the fuzzer's own opcode set had omitted
it), and `Seal`-while-read-only failed on Windows. All three are now pinned
by the fuzzer and the named regression tests in
[`securebuf_readonly_test.go`](securebuf_readonly_test.go).

## Why the wipe is architecture assembly with a cache flush

Zeroing a secret in Go is deceptively hard: a plain loop that writes zeros
and never reads them back is "dead" by the compiler's analysis and can be
optimized away entirely, leaving the secret intact. secmem's wipe is
hand-written assembly (amd64/arm64) using non-temporal or explicitly
barriered stores that the compiler cannot elide, followed by a cache-line
flush (`CLFLUSH`/`CLFLUSHOPT` on amd64, `DC CIVAC` on arm64) so the zeros
are pushed out of cache to main memory rather than lingering in a dirty line
that a later attacker-controlled read might observe. On platforms without
the assembly path, the wipe falls back to a barriered store loop — still
correct against elision, just without the flush — and `Capabilities`
reports `FlushedWipe: false` so the caller knows which they got. The wipe
runs on `Destroy`, and again from the janitor's paths as a backstop.

## Why there is a janitor, and a termination-wipe

A secret that is not wiped when the program ends persists in RAM until those
pages are recycled, which may be long after exit and across process
boundaries. secmem registers every secure allocation with an internal
"janitor" so that (a) a buffer dropped without `Destroy` is still wiped via
a `runtime.AddCleanup` finalizer, and (b) `InstallTerminationWipe` can wipe
all registered buffers from a signal handler if the process is killed by
SIGINT/SIGTERM before orderly shutdown. Explicit `Destroy` remains the
correct path — the janitor is the backstop for the paths where it didn't
happen, so a crash or a forgotten cleanup degrades to "wiped late" rather
than "not wiped." The wipe path always makes the region writable first (a
sealed or read-only region must be `mprotect`-ed back to RW before it can be
zeroed), which is why `Destroy` works correctly on sealed and read-only
buffers without the caller having to restore them.

## Why redaction is a separate, always-on layer

The channel through which in-memory secrets most often actually escape is
not an attacker reading RAM — it is the program logging the wrong variable.
So `Secret` and `SecureBuffer` implement every interface that `fmt`,
`encoding/json`, and `log/slog` dispatch on (`Stringer`, `GoStringer`,
`TextMarshaler`, `json.Marshaler`, `slog.LogValuer`) and return a fixed
`[REDACTED]` sentinel from all of them — so the default, laziest thing a
developer can do (`log.Printf("%v", secret)`) is already safe. `MarshalJSON`
deliberately *redacts* rather than *erroring*: a caller who ignores the
error still cannot leak. The separate [`redact`](redact/) package extends
this to arbitrary log output with a `slog.Handler` that sanitizes
credential-shaped and high-entropy strings, so even a future logging bug on
a plain string is filtered. Types that secmem does *not* implement an
encoder for (e.g. `gob`) are safe by construction: the plaintext is not held
in any exported, reflection-reachable field.

## Why the platform story is explicit rather than uniform

secmem could present a single uniform API that silently does less on weaker
platforms. It deliberately does not. The guarantees genuinely differ —
`memfd_secret` is Linux-only, the cache-flush wipe is amd64/arm64 only,
Windows substitutes `CryptProtectMemory` sealing and WER dump exclusion for
the Linux allocation-time protections — and hiding that difference would be
the security-theatre failure mode this library exists to avoid. So
`Capabilities` / `Probe()` reports, per allocation, exactly which
protections took effect, `Warnings()` names what is missing, and the honest
platform matrix in the [README](README.md) is part of the contract. A
reviewer should be able to see precisely what a given deployment gets, and
the code makes that inspectable rather than asking for trust.

## The stack, in one view

```
                         defends against            mechanism
  ────────────────────── ────────────────────────── ──────────────────────────
  off the Go heap        GC move/scan/copy, no-pin   mmap / VirtualAlloc
  page locking           swap-to-disk                mlock / VirtualLock
  kernel isolation       /proc/pid/mem, ptrace,      memfd_secret (Linux 5.14+)
                         core dumps
  dump exclusion         crash/WER dumps             MADV_DONTDUMP / WER exclude
  guard pages            overflow into the secret    PROT_NONE brackets
  canary                 intra-mapping overflow      random slack + verify
  Seal (idle)            in-process read primitives  PROT_NONE + CryptProtectMem
  ReadOnly               stray writes                PROT_READ + API flag
  wipe                   remanence in RAM/cache      asm zero + cache flush
  janitor + term-wipe    unwiped-on-exit/crash       finalizer + signal handler
  redaction              logging the secret          Stringer/Marshaler sentinels
  refuse-by-default      silent heap fallback        ErrNoSecureMemory
  static borrow check    heap copy of the secret     secmem-lint (compile-time)
```

Each row is independent: defeating one does not defeat its neighbours, and
each degrades to a reported weaker state rather than a silent one. That
arrangement — many small, honest, independently-verified guarantees rather
than one big claim — is the whole design.
