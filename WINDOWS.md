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
| (every CI run) | Windows Server 2025 | GitHub-hosted runner (`windows-2025-vs2026`) | amd64 | `windows-latest` GitHub Actions VM | PASS | full suite via `go test -race`, run on every push/PR |

CI's `test (windows-latest)` job **executes** the suite on a real (if
virtualized) Windows Server VM — it is not a cross-compile-only check, unlike
the `windows/arm64` row in `cross-compile`, which only builds and
test-compiles (no arm64 Windows runner exists to execute on). A scheduled
workflow (`soak-windows.yml`) repeats the same `go test -race ./...`
invocation on `windows-latest` many times a day, to sample rare
non-deterministic failures that one run per PR would miss.

## Behaviour that differs from Linux

The guarantee matrix in [README.md](README.md) has the per-protection view;
these are the operational differences a Windows deployment has to plan for.

- **The lock budget is the working set, not an rlimit.** `VirtualLock` is
  bounded by the process minimum working-set size (minus a small kernel
  overhead), and the default is small: on a stock Windows 11 workstation a
  1 MiB `SecureBuffer` was refused until the budget was raised. Call
  `EnsureMemlockLimit` once at startup, before the first allocation; on
  Windows it raises the minimum working set (`SetProcessWorkingSetSizeEx`)
  and returns what was achieved. Anything sized in MiB — an
  `Argon2Workspace` at the package default is 64 MiB — needs this.
- **The termination wipe exits the process itself.** Windows cannot
  re-raise a console signal (`os.Process.Signal` supports only `os.Kill`, and
  the console event has already been consumed), so after wiping,
  `InstallTerminationWipe` exits with `0xC000013A` (`STATUS_CONTROL_C_EXIT`)
  — the status an un-intercepted Ctrl-C produces, pinned by
  `TestForcedExitStatus_MatchesUninterceptedSignal`, so no parent or CI step
  can tell a wrapped process from an unwrapped one. `InstallTerminationWipeNoExit`
  leaves the process running and stays armed, so every later Ctrl-C or
  Ctrl-Break wipes again.
- **Dump exclusion covers WER only.** `WerRegisterExcludedMemoryBlock` keeps
  the pages out of Windows Error Reporting dumps; a debugger-driven
  `MiniDumpWriteDump` still captures them. There is no process-wide
  equivalent of `RLIMIT_CORE=0`, so `DisableCoreDumps` returns
  `errors.ErrUnsupported` here. For a dormant secret, `Seal` encrypts the
  contents in place with `CryptProtectMemory`, so a dump taken while sealed
  holds ciphertext; `Seal` fails closed (stays sealed) if the cipher rollback
  on a protection failure also fails.
- **Asynchronous preemption cannot be suppressed.** The runtime preempts by
  `SuspendThread` and `SetThreadContext`, which nothing in userspace masks.
  `Scrub` still runs the frame wipe (`Capabilities.FrameScrub`), but
  `AsyncPreemptSuppressed` is false, and `GOEXPERIMENT=runtimesecret` is
  Linux-only, so the register and heap erasure tier is unavailable.

## Not yet verified

- **Windows 10** — no run recorded yet. Server 2025 and Windows 11 share a
  kernel lineage close enough that the core `VirtualLock`/guard-page/wipe paths are
  not expected to differ, but `WerRegisterExcludedMemoryBlock` behavior, ACG
  enforcement, and `CryptProtectMemory`'s backing key store have varied by
  edition and build historically — this is a disclosed gap, not an assumed-fine.
- **Windows Server vs. Windows client, for the hardening-specific APIs
  specifically** (ACG, strict handle policy) — CI covers Server 2025, the row
  above covers Windows 11 Pro client; a Windows 10 client run would close the
  remaining edition gap.
- **windows/arm64** — build and test-binary compile only (the `cross-compile`
  job); nothing has executed there. The arm64 wipe and frame-scrub assembly
  carry no OS constraint, so the same routines that run on linux/arm64 are
  what a windows/arm64 build gets, but that is an inference, not a run.

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
