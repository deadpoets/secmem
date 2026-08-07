# Linux kernel verification log

secmem's most security-critical code path — `memfd_secret` mapped `MAP_FIXED`
into a pre-reserved `PROT_NONE` guard range — depends on kernel behavior that
no API stability promise covers beyond the syscall itself. This log records
every kernel the suite has actually been **executed** on, so the guarantee
matrix cites evidence, not assumption.

## What a row means

A row is recorded only when the complete gauntlet ran on real hardware or a
real VM (never cross-compiled-and-assumed), against the released library code:
both library modules under `-race`, the `GOEXPERIMENT=runtimesecret` variant,
the no-heap-escape gates, and `-asan`. **Proofs n/3** counts the executed
security proofs beyond unit tests:

1. **guard-fault** — reading one byte past either edge of the secret area
   hardware-faults ([guard_canary_test.go](guard_canary_test.go))
2. **memfd-isolation** — after `MAP_FIXED` placement the secret is unreadable
   via `/proc/self/mem` while a control read of ordinary heap succeeds
   ([memfd_isolation_linux_test.go](memfd_isolation_linux_test.go)); only
   countable where secretmem is live — on fallback kernels it skips loudly
   and the row shows 2/3
3. **canary** — an in-mapping overflow is detected on Destroy/Release
   ([guard_canary_test.go](guard_canary_test.go))

**secretmem** = whether `memfd_secret(2)` was live (`CONFIG_SECRETMEM=y`, not
blocked by lockdown) — i.e. the L4 path itself was exercised, not only the
mmap+mlock (L3) fallback, whose guards and canaries every row verifies.

## v0.2.0 — verified kernels

Validated against `f7fdf4e`, the library tree v0.2.0 tags; the only later
commits are docs-only (this file and the changelog), so the run reflects
exactly the shipped code. Every row ran the full gauntlet — core,
`secmem-crypto`, and `secmem-lint` under `-race`, `GOEXPERIMENT=runtimesecret`,
the no-heap-escape gates, and `-asan` — plus the three counted proofs.

| Date | Kernel | Arch | Environment | secretmem | Result |
|---|---|---|---|---|---|
| 2026-07-19 | 7.0.0-1009-azure | amd64 | Local Hyper-V VM, Ubuntu 26.04, Intel Core Ultra 7 265KF | live | PASS · 3/3 |
| 2026-07-19 | 6.18.35-rockchip64 | arm64 | Libre Computer Renegade, RK3328 4× Cortex-A53 (in-order), Armbian | live | PASS · 3/3 |
| 2026-07-19 | 6.17.0-1011-oracle | arm64 | OCI Ampere A1.Flex (Neoverse N1, out-of-order), Ubuntu 24.04 | live | PASS · 3/3 |

The read-only fix this release centers on is exercised where it matters: the
concurrent protection-transition stress races `ReadOnly`/`Seal` against
mutators, and it passes under `-race` on the **in-order** Cortex-A53 as well as
on amd64's stronger TSO ordering — the arm64 weak memory model being where a
protection-state race would actually surface.

## v0.1.0 — verified kernels

Tags `v0.1.0` (commit `2faf99c`) and `secmem-crypto/v0.1.0` (commit `06960fb`);
the core library tree is byte-identical at both commits — the intervening
commits touch only CI, the changelog, and `secmem-crypto`'s `go.mod` — so the
run reflects exactly the shipped code.

| Date | Kernel | Arch | Environment | secretmem | Result |
|---|---|---|---|---|---|
| 2026-07-17 | 6.17.0-1011-oracle | arm64 | OCI Ampere A1.Flex (Neoverse N1, out-of-order), Ubuntu 24.04 | live | PASS · 3/3 |
| 2026-07-17 | 6.18.35-rockchip64 | arm64 | Libre Computer Renegade, RK3328 4× Cortex-A53 (in-order), Armbian | live | PASS · 3/3 |
| 2026-07-17 | 7.0.0-1009-azure | amd64 | Local Hyper-V VM, Ubuntu 26.04, Intel Core Ultra 7 265KF | live | PASS · 3/3 |

All three rows ran the full gauntlet — core and `secmem-crypto` under `-race`,
`GOEXPERIMENT=runtimesecret`, the no-heap-escape gates, and `-asan`, plus the
three proofs — against the released library code. The two arm64 rows now span
the microarchitecture range: an out-of-order server core (Ampere Neoverse N1)
and an in-order mobile core (Cortex-A53), so the weak-memory-model `-race` /
`-asan` paths and the arm64 `DC CIVAC` wipe are exercised both where the core
reorders aggressively and where it issues in program order. One amd64-only,
legacy-path
stack-scrub test (`TestScrub_ScrubsShallowCallTree`) is excluded under `-asan`:
the sanitizer's frame redzones move the raw-`uintptr`-observed local out of the
fixed band the wipe assembly clears, so the read and the wipe stop aliasing —
an instrumentation artifact, not a wipe failure (it passes on every non-asan
build and under `-race`; the production `runtimesecret` path never compiles
it). The wipe itself is unchanged from the tag.

## Pre-release validation (2026-07-11 → 07-13, summarized)

Twelve rows — the full table is in this file's git history — covered amd64
kernels 5.10 → 7.0.8 plus a custom 7.1.3 mainline build (Hetzner cx23 across
Debian 11/12, Rocky 9, Ubuntu 24.04, Fedora 44; WSL2; a local Hyper-V VM) and
arm64 6.8 → 6.17 on OCI Ampere A1.Flex (Ubuntu 22.04/24.04, Oracle Linux 9/10
UEK). All PASS. The durable finding: **`secretmem` availability is a
kernel-config property, not a version.** Debian 12 (6.1) and Rocky 9 (5.14)
ship without `CONFIG_SECRETMEM`; Oracle Linux 9's UEK 6.12 has it live while
OL10's same-version UEK reports fallback. Kernel version alone never
guarantees the L4 path — the library reports the truth per allocation.

## arm64: `CONFIG_SECRETMEM=y` is not enough — `can_set_direct_map()` gates it

The pre-release finding above ("availability is a kernel-config property, not a
version") has a sharper form on arm64, measured 2026-08-06 on an **NVIDIA
Jetson Orin Nano (Tegra 234, Cortex-A78AE, kernel 6.8.12-1021-tegra)**:

| Fact | Value |
|---|---|
| `CONFIG_SECRETMEM` | **`y`** |
| `CONFIG_ARCH_HAS_SET_DIRECT_MAP` | `y` |
| `CONFIG_RODATA_FULL_DEFAULT_ENABLED` | **not set** |
| `CONFIG_DEBUG_PAGEALLOC` / `CONFIG_KFENCE` | not set |
| `rodata=` on cmdline | absent |
| `memfd_secret(2)` | **`ENOSYS`** |

`memfd_secret` works by removing pages from the kernel's linear map, so it
needs that map to be splittable at page granularity. On arm64
`can_set_direct_map()` is true only when `rodata_full` is on, or
`DEBUG_PAGEALLOC` is on, or KFENCE needs it. This kernel has none of the three,
so secretmem disables itself at init and the syscall reports `ENOSYS` **even
though `CONFIG_SECRETMEM=y`** — the config symbol everyone greps for is present
and the feature is still inert.

The practical consequences:

- **Do not infer the L4 path from `CONFIG_SECRETMEM`, or from `uname -r`.**
  6.8.12 is comfortably past 5.14 and the symbol is compiled in; the path is
  still unavailable. Only the syscall's own answer settles it, which is what
  `Probe()` and `SecureBuffer.Capabilities()` report.
- **Vendor SoC kernels are the likely place to hit this.** Turning off
  `rodata_full` buys larger block mappings in the linear map; a vendor tuning
  for boot time and TLB pressure may well take that trade without considering
  secretmem. Stock Armbian (6.18.35, RK3328) and Ubuntu 26.04 (7.0.0, amd64)
  both had it live.
- **It compounds with unified memory.** The SoCs most likely to ship such a
  kernel are also the ones sharing DRAM with an iGPU/NPU — see the UMA bullet
  in [THREAT-MODEL.md](THREAT-MODEL.md). The platform that most needs the
  strongest tier is the one least likely to have it.

## Cross-architecture run — 2026-08-06

Three boxes, chosen so `RLIMIT_MEMLOCK` and architecture vary independently
rather than together. Correctness only; no benchmark numbers were taken (see
[TESTING.md](TESTING.md) for why they would not have been meaningful here).

| Box | Arch · kernel | `RLIMIT_MEMLOCK` | secretmem | Suite | `-race` |
|---|---|---|---|---|---|
| Jetson Orin Nano (Tegra 234, Cortex-A78AE) | arm64 · 6.8.12-1021-tegra | 943 MiB | **fallback** (see above) | PASS | PASS |
| Libre Renegade (RK3328, Cortex-A53) | arm64 · 6.18.35-rockchip64 | 8 MiB | live | PASS | not run (git server; kept idle) |
| Hyper-V guest, Ubuntu 26.04 | amd64 · 7.0.0-1010-azure | 8 MiB | live | PASS | PASS |

What the design isolates, stated as the comparison it came from:

- **Same arch, 118× different limit** (Renegade vs Jetson): 2048 buffers vs
  >3000 and still going. The buffer ceiling is not architectural.
- **Same limit, different arch** (Renegade vs the amd64 guest): byte-identical
  results — 2048 buffers, `ENOMEM`, full budget returned.
- **Limit as a controlled variable within one box** (Jetson, lowered
  in-process): 8 MiB → exactly 2048, 1 MiB → exactly 256, same hardware and
  binary. Stronger than either cross-box pair, since nothing else moves.

The ceiling is exactly `RLIMIT_MEMLOCK / pagesize`, with no other term, and it
holds across both allocation tiers — the Jetson reaches it through mmap+mlock,
the Renegade through memfd_secret. Behaviour at the ceiling was clean on all
three: a real `ENOMEM` from `mlock`, no panic, `VmLck` rising by exactly one
page per buffer (so no silent fallback to unlocked pages), nothing left
half-locked by the failing allocation, and the entire budget returned to the
baseline after `Destroy`.

Kernel-recorded VMA flags were checked against `Capabilities` on all three
rather than trusting that `madvise` returned 0: `lo` (VM_LOCKED), `dd`
(VM_DONTDUMP) and `dc` (VM_DONTCOPY) were present and matched every claim, on
both the memfd and the anonymous constructor. `MADV_DONTFORK` is confirmed to
take effect on a **secretmem** VMA on 6.18.35/arm64 and 7.0.0/amd64.

Cache geometry, which the wipe's 64-byte flush stride depends on: every data
and unified cache level reported a 64-byte line on all three boxes
(Cortex-A78AE, Cortex-A53, x86_64). That assumption is now asserted by
[wipe_cacheline_linux_test.go](wipe_cacheline_linux_test.go) rather than
carried silently.

## Out-of-process extraction battery

Executed pre-release on amd64 (kernel `7.0.0-1009-azure`) and arm64
(`6.17.0-1011-oracle`, Ampere): a separate attacker process scanned a victim's
entire readable address space via `/proc/<pid>/mem` — first unprivileged (as
the victim's parent under `ptrace_scope=1`), then as **root with
`CAP_SYS_PTRACE`** — and a full `gcore` core dump was searched. The victim
held a 32-byte marker resident only in a `SecureBuffer` plus an
identically-shaped control marker on the ordinary Go heap, both computed at
runtime (never literals in the binary). In every attempt, on both
architectures, the `/secretmem` region raised `EIO` and the secret was
recovered **zero** times across ~74 MiB of readable memory (and was absent
from the 77 MiB core), while the heap control marker was recovered every
time. Root fared no better than unprivileged — `memfd_secret` pages are
removed from the kernel's direct map, not permission-gated. This bounds the
claim precisely: it covers passive memory reads via `/proc/<pid>/mem` and
core dumps. The unprivileged half is the committed regression test
([extraction_linux_test.go](extraction_linux_test.go), scanning via both
`/proc/<pid>/mem` and `process_vm_readv(2)`) and executes inside every row
above, including the v0.1.0 rows.

## Reproducing a run

The suite compiles to one self-contained binary; the target machine needs no
Go toolchain:

```sh
GOOS=linux GOARCH=amd64 go test -c -o secmem.test .   # or GOARCH=arm64
./secmem.test -test.count=1                           # full suite
./secmem.test -test.count=1 -test.v \
  -test.run 'TestGuardPages|TestCanary|TestMemfdIsolation|TestAllocMemfdSecret'
```

The isolation test skips loudly (with the reason) when secretmem is not live
on the target kernel — a skip is recorded as "fallback", never as a pass.
