# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version is `0.x`, the public API may change between minor versions as
the surface settles; breaking changes will be called out here. `1.0.0` will
mark the stability commitment.

## [Unreleased]

### Added

- `SecureBuffer` — off-heap, page-locked secret storage with borrowing-closure
  access (`WithBytes`/`WithBytesErr`), copy-out/in, sealing, read-only
  protection, deterministic wipe on `Destroy`, and an emergency signal-wipe
  registry.
- `SecureArena` — a single locked slab of fixed-size slots for many small,
  short-lived secrets at O(1) OS overhead, with ABA-guarded acquire/release.
- `Secret` — a leak-safe value type that renders as `[REDACTED]` through
  `fmt`, `encoding/json`, and `log/slog`.
- `Capabilities` and `Probe` — honest, per-allocation and per-platform
  reporting of which protections are actually in force, with `Warnings()` and a
  one-line `String()`.
- Guard pages and an overflow canary bracketing every allocation; a linear
  over/under-flow faults or is caught on destroy. On Linux this includes the
  `memfd_secret` `MAP_FIXED`-into-a-reservation construction.
- `Scrub` / `ScrubErr` — register, stack, and heap residue erasure via
  `runtime/secret` where available (`GOEXPERIMENT=runtimesecret`), with a
  best-effort stack-frame wipe elsewhere.
- Fail-closed policy on platforms with no lockable off-heap memory:
  constructors return `ErrNoSecureMemory` unless `WithInsecureFallback()` is
  passed.
- Process-hardening helpers: `HardenProcess` (dumpable=0 and no-new-privs on
  Linux; Arbitrary Code Guard and strict handle checks on Windows),
  `DisableCoreDumps`, and `SetMemlockLimit`.
- Platform dump/copy hardening applied by the allocator: `MADV_DONTDUMP` /
  `MADV_DONTFORK` / `MADV_NOHUGEPAGE` / `MADV_UNMERGEABLE` on Linux; WER dump
  exclusion and a kernel-keyed sealed-state cipher (`CryptProtectMemory`) on
  Windows.
- `secmem/redact` subpackage — a configurable `Sanitizer` and an `slog.Handler`
  wrapper for boundary-level log scrubbing (credential masking and CWE-117
  injection neutralization). Standard library only.
- `KERNELS.md` — a log of the Linux kernels the suite has been executed on, with
  the guard-fault, `memfd_secret`-isolation, and canary proofs recorded per row.
  Now includes real **arm64** (Ampere Altra) and a spread of amd64 kernels
  (5.10 → 7.x) run on disposable cloud hardware.
- `ENVIRONMENTS.md` — how secmem behaves across root / non-root / rootless and
  constrained `RLIMIT_MEMLOCK`, and why `memfd_secret` availability is a kernel
  `CONFIG_SECRETMEM` property rather than a version guarantee.

[Unreleased]: https://github.com/deadpoets/secmem/commits/main
