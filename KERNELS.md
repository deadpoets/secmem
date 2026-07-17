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

## v0.1.0 — verified kernels

Tags `v0.1.0` + `secmem-crypto/v0.1.0` (tree `06960fb`), exactly as shipped.

| Date | Kernel | Arch | Environment | secretmem | Result |
|---|---|---|---|---|---|
| 2026-07-17 | 6.17.0-1011-oracle | arm64 | OCI Ampere A1.Flex, Ubuntu 24.04 | live | PASS · 3/3 |
| 2026-07-17 | 7.0.0-1009-azure | amd64 | Local Hyper-V VM, Ubuntu 26.04, Intel Core Ultra 7 265KF | live | PASS · 3/3 |

Both rows ran the full gauntlet — core and `secmem-crypto` under `-race`,
`GOEXPERIMENT=runtimesecret`, the no-heap-escape gates, and `-asan`, plus the
three proofs — against the released library code. One amd64-only, legacy-path
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
