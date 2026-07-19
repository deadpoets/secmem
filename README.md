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

| Protection | linux/amd64·arm64 (≥5.14) | linux (older / 32-bit) | darwin | windows | other |
|---|---|---|---|---|---|
| Off the Go heap | ✓ memfd_secret | ✓ mmap | ✓ mmap | ✓ VirtualAlloc | **LOUD** heap only |
| No swap (locked) | ✓ | ✓ mlock | ✓ mlock | ✓ VirtualLock | ✗ |
| Kernel isolation (invisible to root / ptrace / `/proc/<pid>/mem`) | ✓ memfd_secret | ✗ (falls to mlock) | ✗ | ✗ | ✗ |
| Excluded from crash dumps | ⚠ MADV_DONTDUMP | ⚠ MADV_DONTDUMP | ✗ | ⚠ WER exclusion | ✗ |
| Not inherited across fork | ⚠ MADV_DONTFORK | ⚠ MADV_DONTFORK | ✗ | n/a | ✗ |
| No THP/KSM secret copies | ✓ madvise | ✓ madvise | n/a | n/a | ✗ |
| Guaranteed wipe on destroy | ✓ asm + cache flush | ✓ (amd64/arm64 asm; else ⚠ constant-time) | ✓ asm | ✓ asm (amd64) | ⚠ constant-time store |
| Guard pages + overflow canary | ✓ | ✓ | ✓ | ✓ | ✗ (heap fallback) |
| Register + stack + heap scrub ([`Scrub`](https://pkg.go.dev/github.com/deadpoets/secmem#Scrub)) | ✓ with `GOEXPERIMENT=runtimesecret` | ✓ if set (amd64/arm64); else frame-scrub | frame-scrub only | frame-scrub only | frame-scrub / ✗ |
| Encrypted while sealed ([`Seal`](https://pkg.go.dev/github.com/deadpoets/secmem#SecureBuffer.Seal)) | ✗ | ✗ | ✗ | ✓ CryptProtectMemory | ✗ |
| Process hardening ([`HardenProcess`](https://pkg.go.dev/github.com/deadpoets/secmem#HardenProcess)) | ✓ dumpable=0, no-new-privs | ✓ | ✗ | ✓ ACG + strict handles | ✗ |
| Fails loudly, never silently degrades | ✓ | ✓ | ✓ | ✓ | ✓ (**LOUD** opt-in) |

The suite has been executed on real **linux/amd64 and linux/arm64** hardware,
spanning kernels 5.10 through 7.x (see [`KERNELS.md`](KERNELS.md)). On arm64
(Ampere Altra), the `memfd_secret` L4 path, the guard-page fault, the
`/proc/self/mem` isolation proof, and the architecture-specific wipe assembly
all pass. Whether `memfd_secret` is live depends on the kernel's
`CONFIG_SECRETMEM`, not the version alone — where it is absent, secmem reports
"fallback" and uses `mmap`+`mlock`, honestly, per allocation.

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

Full API docs, runnable examples, and per-symbol guarantees are on
[pkg.go.dev](https://pkg.go.dev/github.com/deadpoets/secmem). Start with the
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
