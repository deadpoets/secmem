# Windows verification log

secmem's Windows path (`VirtualAlloc`/`VirtualLock`, `WerRegisterExcludedMemoryBlock`,
`CryptProtectMemory`-backed `Seal`, ACG + strict-handle process hardening) has
no kernel-version axis the way Linux does, so this log tracks **edition**
instead — Server vs. client, and which client builds — following the same
rule as [`KERNELS.md`](KERNELS.md): a row is recorded only when the full
suite ran on real hardware or a real VM, never cross-compiled-and-assumed.

## Verified

| Date | Edition | Build | Arch | Environment | Suite | Proofs |
|---|---|---|---|---|---|---|
| 2026-07-12 | Windows 11 Pro (Insider Preview) | 10.0.26220 | amd64 | Real workstation hardware | PASS | guard-fault ✓ · canary ✓ · WER exclusion ✓ · seal/`CryptProtectMemory` ✓ · process hardening ✓ |
| (every CI run) | Windows Server 2022 | GitHub-hosted runner | amd64 | `windows-latest` GitHub Actions VM | PASS | full suite via `go test -race`, run on every push/PR |

CI's `test (windows-latest)` job **executes** the suite on a real (if
virtualized) Windows Server VM — it is not a cross-compile-only check, unlike
the `windows/arm64` row in `cross-compile`, which only builds and
test-compiles (no arm64 Windows runner exists to execute on).

## Not yet verified

- **Windows 10** — no run recorded yet. Server 2022 and Windows 11 share a
  kernel lineage close enough that the core `mlock`/guard-page/wipe paths are
  not expected to differ, but `WerRegisterExcludedMemoryBlock` behavior, ACG
  enforcement, and `CryptProtectMemory`'s backing key store have varied by
  edition and build historically — this is a disclosed gap, not an assumed-fine.
- **Windows Server vs. Windows client, for the hardening-specific APIs
  specifically** (ACG, strict handle policy) — CI covers Server 2022, the row
  above covers Windows 11 Pro client; a Windows 10 client run would close the
  remaining edition gap.

## Reproducing a run

Same self-contained binary as the Linux flow:

```sh
GOOS=windows GOARCH=amd64 go test -c -o secmem-windows.test .
secmem-windows.test.exe -test.count=1                       # full suite
secmem-windows.test.exe -test.count=1 -test.v ^
  -test.run "TestGuardPages|TestCanary|TestHardenProcess_Windows|TestSealCipher|TestWERExclusion"
```

Or, with a Go toolchain on the target machine:

```sh
go test -race -count=1 ./...
go test -run TestReportEnvironment -v .   # prints Probe()/Capabilities for that machine
```
