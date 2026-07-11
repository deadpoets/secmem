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
| 2026-07-11 | 7.1.3 (mainline, `CONFIG_SECRETMEM=y`) | amd64 | WSL2 custom kernel, Ubuntu 26.04 on Windows 11 | live | PASS | guard-fault ✓ · memfd-isolation ✓ · canary ✓ |
| 2026-07-11 | 6.18.26.1-microsoft-standard-WSL2 | amd64 | WSL2 Ubuntu 26.04 on Windows 11 | live | PASS | guard-fault ✓ · memfd-isolation ✓ · canary ✓ |

## Reproducing a run

The suite compiles to one self-contained binary; the target machine needs no
Go toolchain:

```sh
GOOS=linux GOARCH=amd64 go test -c -o secmem.test .
./secmem.test -test.count=1                       # full suite
./secmem.test -test.count=1 -test.v \
  -test.run 'TestGuardPages|TestCanary|TestMemfdIsolation|TestAllocMemfdSecret'
```

The isolation test skips loudly (with the reason) when secretmem is not live
on the target kernel — a skip is recorded as "fallback", never as a pass.
