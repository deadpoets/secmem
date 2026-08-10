# secmem

[![Go Reference](https://pkg.go.dev/badge/github.com/deadpoets/secmem.svg)](https://pkg.go.dev/github.com/deadpoets/secmem)
[![CI](https://github.com/deadpoets/secmem/actions/workflows/ci.yml/badge.svg)](https://github.com/deadpoets/secmem/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/deadpoets/secmem)](https://goreportcard.com/report/github.com/deadpoets/secmem)

Harden secrets in memory — keep private keys, tokens, and passwords off the Go
garbage-collected heap, in OS-locked pages excluded from swap and, where the
platform allows, from core dumps and from other processes. Bytes are wiped on
release by an architecture-specific routine and reached only through a
borrowing closure, so the plaintext never outlives its use.

Pure Go (`CGO_ENABLED=0`), depending only on `golang.org/x/sys`.

> Built as internal tooling for a set of the author's own projects, then
> extracted and generalized. Governance is BDFL: bug fixes, hardening, and
> speedups-without-regression are all welcome.

## Honesty first

Every guarantee is stated per platform, together with what it does **not**
protect against. A security library that overstates its guarantees is worse
than none. So:

- A protection that cannot be provided on a platform is **reported** through
  [`Capabilities`](https://pkg.go.dev/github.com/deadpoets/secmem#Capabilities),
  never silently skipped. Call
  [`Probe`](https://pkg.go.dev/github.com/deadpoets/secmem#Probe) once at
  startup to see what is in force.
- A platform with no lockable off-heap memory **fails loudly**
  (`ErrNoSecureMemory`) rather than degrading to unprotected heap — unless you
  opt in explicitly with `WithInsecureFallback()`.
- Every claim below is exercised by a test. The guard pages actually fault; the
  `memfd_secret` isolation is checked against `/proc/self/mem`; the wipe,
  redaction, and no-panic promises are fuzzed. See [`KERNELS.md`](KERNELS.md)
  for the kernels the suite has been executed on.

## Install

```sh
go get github.com/deadpoets/secmem
```

## Quick start

```go
buf, err := secmem.NewBuffer(rawKey) // rawKey is wiped after the copy
if err != nil {
    return err
}
defer buf.Destroy() // always defer immediately

err = buf.WithBytesErr(func(borrowed []byte) error {
    // borrowed is valid ONLY inside this closure — never store it.
    return sign(borrowed, msg)
})
```

For values you hold and might log, wrap them in a
[`Secret`](https://pkg.go.dev/github.com/deadpoets/secmem#Secret): it renders as
`[REDACTED]` through `fmt`, `encoding/json`, and `log/slog`. For scrubbing
free-form log text, the [`redact`](https://pkg.go.dev/github.com/deadpoets/secmem/redact)
subpackage provides a `slog.Handler` wrapper.

## The platform guarantee matrix

`✓` enforced · `⚠` best-effort (failure is reported, not fatal) · `✗` not
provided · **LOUD** opt-in only. This table is the threat model's spine; see
[THREAT-MODEL.md](THREAT-MODEL.md) for what none of it protects against.

| Protection | linux/amd64·arm64 (≥5.14, secretmem live †) | linux (older / 32-bit / secretmem inert) | darwin | windows | other |
|---|---|---|---|---|---|
| Off the Go heap | ✓ memfd_secret | ✓ mmap | ✓ mmap | ✓ VirtualAlloc | **LOUD** heap only |
| No swap (locked) | ✓ | ✓ mlock | ✓ mlock | ✓ VirtualLock | ✗ |
| Kernel isolation (invisible to root / ptrace / `/proc/<pid>/mem`) | ✓ memfd_secret | ✗ (falls to mlock) | ✗ | ✗ | ✗ |
| Excluded from crash dumps | ⚠ MADV_DONTDUMP | ⚠ MADV_DONTDUMP | ✗ | ⚠ WER exclusion | ✗ |
| Not inherited across fork | ⚠ MADV_DONTFORK | ⚠ MADV_DONTFORK | ✗ | n/a | ✗ |
| No THP/KSM secret copies | ✓ madvise | ✓ madvise | n/a | n/a | ✗ |
| Guaranteed wipe on destroy | ✓ asm + cache flush | ✓ (amd64/arm64 asm; else ⚠ constant-time) | ✓ asm | ✓ asm (amd64) | ⚠ constant-time store |
| Guard pages + overflow canary | ✓ | ✓ | ✓ | ✓ | ✗ (heap fallback) |
| Stack-frame scrub inside [`Scrub`](https://pkg.go.dev/github.com/deadpoets/secmem#Scrub) | ✓ asm | ✓ asm on amd64/arm64; ✗ stub elsewhere | ✓ asm | ✓ asm (amd64/arm64) | ✗ stub |
| No async register dump into the window (preemption signal blocked) | ✓ SIGURG+SIGPROF | ✓ SIGURG+SIGPROF | ✗ no `pthread_sigmask` binding | ✗ unmaskable (`SetThreadContext`) | ✗ |
| Register + heap scrub ([`Scrub`](https://pkg.go.dev/github.com/deadpoets/secmem#Scrub)) | ✓ with `GOEXPERIMENT=runtimesecret` | ✓ if set (amd64/arm64) | ✗ | ✗ | ✗ |
| Encrypted while sealed ([`Seal`](https://pkg.go.dev/github.com/deadpoets/secmem#SecureBuffer.Seal)) | ✗ | ✗ | ✗ | ✓ CryptProtectMemory | ✗ |
| Process hardening ([`HardenProcess`](https://pkg.go.dev/github.com/deadpoets/secmem#HardenProcess)) | ✓ dumpable=0, no-new-privs | ✓ | ✗ | ✓ ACG + strict handles | ✗ |
| Fails loudly, never silently degrades | ✓ | ✓ | ✓ | ✓ | ✓ (**LOUD** opt-in) |

The suite has been executed on real **linux/amd64 and linux/arm64** hardware,
spanning kernels 5.10 through 7.x (see [`KERNELS.md`](KERNELS.md)). On arm64
(Ampere Altra), the `memfd_secret` L4 path, the guard-page fault, the
`/proc/self/mem` isolation proof, and the architecture-specific wipe assembly
all pass.

The three `Scrub` rows are separate because they degrade separately, and the
middle one is the newest: on Linux the window blocks Go's preemption signal for
its duration, so `runtime.asyncPreempt` cannot spill the whole register file
onto the stack partway through a cipher round. What that reaches — and the
residue that is a constraint of the Go runtime or the OS rather than something
this library can fix — is set out in
[THREAT-MODEL.md](THREAT-MODEL.md#stack-residue-what-scrub-reaches-and-what-it-does-not).
The stack-frame scrub is asserted by planting markers down the stack and reading
the abandoned frames back as zero, on linux/amd64 and linux/arm64; the signal
block is asserted against the kernel's own `SigBlk` for the calling thread, on
linux/arm64 (Tegra 234, kernel 6.8.12; RK3328, kernel 6.18.35) and linux/amd64
(kernel 7.0.0).

† Whether `memfd_secret` is live is **not** decided by the kernel version, and
not even by `CONFIG_SECRETMEM` alone. It needs the kernel to be able to split
the linear map at page granularity; on arm64 that means `rodata=full` (or
`DEBUG_PAGEALLOC`, or KFENCE). A measured counter-example: an NVIDIA Jetson
Orin Nano on kernel 6.8.12 ships `CONFIG_SECRETMEM=y` and still returns
`ENOSYS`, because `CONFIG_RODATA_FULL_DEFAULT_ENABLED` is off — see
[`KERNELS.md`](KERNELS.md). Where it is inert, secmem reports "fallback" and
uses `mmap`+`mlock`, honestly, per allocation. Read
[`Capabilities`](https://pkg.go.dev/github.com/deadpoets/secmem#SecureBuffer.Capabilities)
at runtime; do not infer the tier from a config symbol or a `uname`.

On a unified-memory SoC (Tegra, Apple Silicon, AMD APUs, most ARM SBCs) note
also that locking a page constrains the CPU's view of it, not an on-die
GPU/NPU sharing the same DRAM — see [`THREAT-MODEL.md`](THREAT-MODEL.md).

Guard pages and the canary are a **memory-safety bug-catcher, not a
confidentiality control** — they trap an accidental over/under-flow, and do
nothing against a privileged reader of process memory (that is
`memfd_secret`'s job). The Windows sealed-state cipher raises the bar against
memory dumps of a dormant secret; it is not cold-boot protection. Both are
detailed in the godoc and the threat model.

## Modules

- **`secmem`** (this module) — `SecureBuffer`, `SecureArena`, `Secret`,
  `Capabilities`/`Probe`, `Scrub`, and the process-hardening helpers. Depends
  only on `golang.org/x/sys`.
- **`secmem/redact`** — `Sanitizer` and an `slog.Handler` for boundary-level
  log scrubbing. Standard library only.

## Documentation

Full API docs, per-symbol runnable `Example`s, and per-symbol guarantees are on
[pkg.go.dev](https://pkg.go.dev/github.com/deadpoets/secmem). For end-to-end
programs, [`examples/`](examples/) holds a password register/login flow and a
working, hardened SSH agent — each composing the library under real I/O,
concurrency, and shutdown. Start with the
package overview, then [`THREAT-MODEL.md`](THREAT-MODEL.md) for the limits,
[`TESTING.md`](TESTING.md) for how each claim is proven (or why it can't be),
[`ENVIRONMENTS.md`](ENVIRONMENTS.md) for behavior under root / non-root /
containers, [`KERNELS.md`](KERNELS.md) for the Linux kernels the suite has run
on, and [`WINDOWS.md`](WINDOWS.md) for Windows editions/builds.

## Contributing

Bug fixes, hardening, and speedups-without-regression are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md) for the workflow (every PR, including the
maintainer's, goes through review and CI). Found a vulnerability? See
[SECURITY.md](SECURITY.md) — please don't file it as a public issue.
Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
