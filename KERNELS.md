# Linux kernel verification log

secmem's most security-critical code path — `memfd_secret` mapped `MAP_FIXED`
into a pre-reserved `PROT_NONE` guard range — depends on kernel behavior that
is not covered by any API stability promise beyond the syscall itself. This
log records every kernel the full test suite has actually been **executed**
on, so the guarantee matrix cites evidence, not assumption.

## What a row means

A row is recorded only when the complete suite ran on real hardware or a real
VM (never cross-compiled-and-assumed). Columns:

- **secretmem** — whether `memfd_secret(2)` was live (`CONFIG_SECRETMEM=y`,
  not blocked by lockdown), i.e. the L4 path itself was exercised, not the
  mmap+mlock fallback. "fallback" rows still verify guards, canaries, and the
  L3 path.
- **Proofs** — the three executed security proofs, beyond unit tests:
  - *guard-fault*: reading one byte past either edge of the secret area
    hardware-faults ([guard_canary_test.go](guard_canary_test.go))
  - *memfd-isolation*: after `MAP_FIXED` placement, reading the secret via
    `/proc/self/mem` fails while a control read of ordinary heap succeeds
    ([memfd_isolation_linux_test.go](memfd_isolation_linux_test.go))
  - *canary*: an in-mapping overflow is detected on Destroy/Release
    ([guard_canary_test.go](guard_canary_test.go))

## Verified kernels

| Date | Kernel | Arch | Environment | secretmem | Suite | Proofs |
|---|---|---|---|---|---|---|
| 2026-07-12 | 6.17.0-1011-oracle | **arm64** | Oracle Cloud Ampere A1.Flex, Ubuntu 24.04 — **real aarch64 silicon** | live | PASS | guard-fault ✓ · memfd-isolation ✓ · canary ✓ |
| 2026-07-12 | 6.12.0-204.92.4.2.el9uek.aarch64 | **arm64** | Oracle Cloud Ampere A1.Flex, Oracle Linux 9 (UEK) | live | PASS | guard-fault ✓ · memfd-isolation ✓ · canary ✓ |
| 2026-07-12 | 6.8.0-1049-oracle | **arm64** | Oracle Cloud Ampere A1.Flex, Ubuntu 22.04 | live | PASS | guard-fault ✓ · memfd-isolation ✓ · canary ✓ |
| 2026-07-12 | 6.12.0-204.92.4.2.el10uek.aarch64 | **arm64** | Oracle Cloud Ampere A1.Flex, Oracle Linux 10 (UEK) | fallback | PASS | guard-fault ✓ · memfd-isolation skip · canary ✓ |
| 2026-07-11 | 7.0.8-200.fc44 | amd64 | Hetzner Cloud cx23, Fedora 44 | live | PASS | guard-fault ✓ · memfd-isolation ✓ · canary ✓ |
| 2026-07-11 | 6.8.0-117-generic | amd64 | Hetzner Cloud cx23, Ubuntu 24.04 | live | PASS | guard-fault ✓ · memfd-isolation ✓ · canary ✓ |
| 2026-07-11 | 6.1.0-47-amd64 | amd64 | Hetzner Cloud cx23, Debian 12 | fallback | PASS | guard-fault ✓ · memfd-isolation skip · canary ✓ |
| 2026-07-11 | 5.14.0-611.el9 | amd64 | Hetzner Cloud cx23, Rocky 9 | fallback | PASS | guard-fault ✓ · memfd-isolation skip · canary ✓ |
| 2026-07-11 | 5.10.0-43-amd64 | amd64 | Hetzner Cloud cx23, Debian 11 | fallback | PASS | guard-fault ✓ · memfd-isolation skip · canary ✓ |
| 2026-07-11 | 7.1.3 (mainline, `CONFIG_SECRETMEM=y`) | amd64 | WSL2 custom kernel, Ubuntu 26.04 on Windows 11 | live | PASS | guard-fault ✓ · memfd-isolation ✓ · canary ✓ |
| 2026-07-11 | 6.18.26.1-microsoft-standard-WSL2 | amd64 | WSL2 Ubuntu 26.04 on Windows 11 | live | PASS | guard-fault ✓ · memfd-isolation ✓ · canary ✓ |
| 2026-07-13 | 7.0.0-1009-azure | amd64 | Local Hyper-V VM (Ubuntu 26.04 LTS) on Windows 11, Intel Core Ultra 7 265KF | live | PASS | guard-fault ✓ · memfd-isolation ✓ · canary ✓ |

The cloud rows were executed on real, disposable hardware provisioned per-run
(the arm64 rows on Ampere Altra), then torn down. Three things they establish:

- **arm64 is now exercised on real silicon, across four kernels.** The
  `memfd_secret` L4 path, the `MAP_FIXED`-into-a-reservation construction, the
  guard-page fault, the `/proc/self/mem` isolation proof, and the arm64 wipe
  assembly all pass on aarch64 — the one claim this log previously could not
  back with evidence.
- **`secretmem` availability is a kernel-config property, not just a
  version — and it can regress between releases of the same distro family.**
  Debian 12 (6.1) and Rocky 9 (5.14) are ≥ 5.14 yet ship **without**
  `CONFIG_SECRETMEM`. More strikingly, **Oracle Linux 9's UEK (6.12) has it
  live, while Oracle Linux 10's UEK (also 6.12) reports fallback** — same
  vendor, same kernel version, one release apart, opposite result. Kernel
  version alone never guarantees the L4 path; the library reports the truth
  per allocation, every time.
- **No cloud vendor's arm64 catalog currently offers a 7.x kernel** (checked
  against Oracle's live image list, July 2026) — the arm64 rows top out at
  6.17 for now. amd64 already has a 7.x row (Fedora 44, `secretmem` live);
  the arm64 code paths are proven identical to the amd64 ones on 6.x, so this
  is a coverage gap to close opportunistically, not an open risk.

## Out-of-process extraction (amd64 kernel 7.0.0-azure · arm64 kernel 6.17.0-oracle)

Beyond the in-process suite, that row carried an external-attacker battery. The
unprivileged half is now a committed regression test — `extraction_linux_test.go`
launches a victim subprocess and, as its parent, scans the whole address space
via both `/proc/<pid>/mem` and `process_vm_readv(2)` — so it runs in CI on every
push; the root and core-dump variants below were run by hand on this kernel. A
separate attacker process scanned a victim's entire readable address space via
`/proc/<pid>/mem` — first unprivileged (as the victim's parent, permitted under
`ptrace_scope=1`), then as **root with `CAP_SYS_PTRACE`** — and a full `gcore`
core dump was taken and searched. The
victim held one 32-byte marker resident only in a `SecureBuffer` (the
`memfd_secret` region, which appears in `/proc/<pid>/maps` as `/secretmem`) and
an identically-shaped control marker on the ordinary Go heap; both markers were
computed at runtime, never written as literals, so neither sits in the binary's
read-only data.

In all three attempts the `/secretmem` region raised `EIO` on read and the
secret marker was recovered **zero** times — across ~74 MiB of readable memory,
and absent from the 77 MiB core — while the heap control marker was recovered
every time. The privilege level made no difference: reading the region fails
for root exactly as it does for an unprivileged parent, because `memfd_secret`
pages are removed from the kernel's direct map, not merely permission-gated.
This bounds the claim precisely — it covers passive memory reads via
`/proc/<pid>/mem` and core dumps, the paths an attacker or a shipped crash dump
would actually take.

The same battery was then confirmed on **arm64** (Oracle Cloud Ampere A1.Flex,
kernel `6.17.0-1011-oracle`, `secretmem` live): the committed extraction test
passes plain and under `-race`, and the unprivileged / root-`CAP_SYS_PTRACE` /
`gcore` attacks all hold identically — `/secretmem` raises `EIO` and the secret
is recovered zero times across ~74 MiB, on aarch64's weaker memory model as on
amd64. The full suite (`-race`, `runtimesecret`, `-asan`), the concurrency
stress harness (borrow-vs-Destroy, double-free, arena ABA under `-race` and
`-asan`), and the crypto module all pass there too, exercising the arm64 wipe
assembly (`DC CIVAC`).

## Reproducing a run

The suite compiles to one self-contained binary; the target machine needs no
Go toolchain:

```sh
GOOS=linux GOARCH=amd64 go test -c -o secmem.test .   # or GOARCH=arm64
./secmem.test -test.count=1                       # full suite
./secmem.test -test.count=1 -test.v \
  -test.run 'TestGuardPages|TestCanary|TestMemfdIsolation|TestAllocMemfdSecret'
```

The isolation test skips loudly (with the reason) when secretmem is not live
on the target kernel — a skip is recorded as "fallback", never as a pass.
