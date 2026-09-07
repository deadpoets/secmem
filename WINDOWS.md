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
| (every CI run) | Windows Server 2025 | GitHub-hosted runner (`windows-2025-vs2026`) | amd64 | `windows-latest` GitHub Actions VM | PASS † | full suite via `go test -race`, run on every push/PR |

† On the pool's AMX-capable hosts the job can die of a Go runtime bug that
secmem's fault proofs trigger; see [the section below](#go-runtime-fault-recovery-bug-golanggo81238).
A re-run on another host passes. No assertion in the suite has failed on
Windows.

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

## Go runtime fault-recovery bug (golang/go#81238)

**What it is.** A bug in the Go runtime on windows/amd64, not in secmem:
[golang/go#81238](https://github.com/golang/go/issues/81238). Windows
delivers a hardware exception on the faulting goroutine's own stack, and the
runtime reserves a fixed 4 KiB below every goroutine stack for that frame.
On CPUs with AMX (Intel Xeon Emerald Rapids and Granite Rapids; models 8573C
and 6973P-C in the GitHub-hosted pool) the kernel's frame carries the AMX
register state and is about 11.7 KiB, so a fault taken with less than about
13 KiB of headroom below the stack pointer overruns the bottom of the stack
into whatever heap object sits beneath it. If the fault is *recovered* — a
`debug.SetPanicOnFault` panic, or any recovered runtime fault such as a nil
dereference — the process continues with a corrupted heap and dies later in
an unrelated frame: `fatal error: stack not a power of 2`,
`acquireSudog: found s.elem != nil in cache`, `reportZombies`. An
unrecovered fault crashes the process anyway, so the corruption matters only
where faults are recovered.

**How it reached this project.** The `test (windows-latest)` job died twice
(2026-08-17 and 2026-08-19) with those messages, in innocuous frames. The
suite's guard-page proofs take thousands of deliberate,
`SetPanicOnFault`-recovered faults per run, which is exactly the path above.
Measured across 1,600 fresh `windows-latest` VMs with a standalone
reproducer containing no secmem code: 117 of 226 jobs on the two AMX models
crashed, 0 of 1,374 on every other CPU in the pool (EPYC 7763/9V74/9V45, Xeon
8370C), on go1.26.6 through go1.27.0, with and without `-race`, with
`GOMAXPROCS=1`, and with `GODEBUG=asyncpreemptoff=1`. In a 200-job run of the
suite itself, one job crashed, on an AMX host. A physical workstation (Core
Ultra 7 265KF, 1.7 KiB exception context) and a Hyper-V Server 2025 guest on
it never reproduce it. The full-dump analysis and the CPU table are posted on
the upstream issue.

**Upstream status at the time of writing.** The issue is open.
[CL 824724](https://go.dev/cl/824724) (merged 2026-08-31) turns some overruns
into a deterministic throw but does not catch this one; the reporter showed
the reproducer still corrupts under it. [CL 828724](https://go.dev/cl/828724),
sent by this project's maintainer on 2026-09-07, sizes the reserve from the
host's actual exception-context length at startup and is under review. Check
the issue for the current state rather than this paragraph.

**What it means for secmem users.** secmem's library code never takes a
deliberate fault and never arms `SetPanicOnFault`, so the library adds no
fault-recovery path of its own; the bug is reachable by any Go program that
recovers a fault on an AMX host. Two things are still worth knowing. First,
secmem's guard pages and `Seal` deliberately turn a stray access into a
fault, so an application that arms `SetPanicOnFault` itself and then touches
a guard page or a sealed buffer on an AMX Windows host takes the affected
path — that is the runtime bug behaving as described, not an additional
exposure created by secmem, but it is where such a program would meet it.
Second, the `-race` Windows CI job in this repository can still die of the
bug when it lands on an AMX host; a re-run that lands elsewhere passes. That
is a crash of the test process, not a suite failure, and the log shows the
runtime messages above rather than a failing assertion.

**Status of the mitigation.** The fix on secmem's side is to run the
guard-page proofs out-of-process, so a probe's fault and any collateral
damage die in a child that does nothing else. That change exists on the
`fix/isolate-fault-proofs` branch (0 crashes in 250 CI-shaped runs, 28 of
them on AMX hosts) and is **not yet merged**; on `main` the proofs still
fault in-process. Until it lands, the daily `soak-windows.yml` keeps sampling
the same job.

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
