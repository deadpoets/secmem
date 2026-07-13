# secmem across runtime environments

Whether secmem can protect a secret depends on three things about the
environment it runs in: the process **privilege** (does it hold
`CAP_IPC_LOCK`?), the **`RLIMIT_MEMLOCK`** budget, and the kernel's
**`CONFIG_SECRETMEM`**. This document records how secmem behaves across those
axes, and — per the honesty contract — marks what was measured on real hardware
versus what is reasoned from it.

The one invariant across every environment: **secmem never silently degrades.**
If it cannot obtain locked, off-heap memory it returns `ErrNoSecureMemory`
rather than placing a secret on unprotected pages — unless you explicitly opt in
with `WithInsecureFallback()`.

## Check your own environment

secmem reports exactly what it provides where it runs. At startup:

```go
caps := secmem.Probe()
log.Print(caps.String())
for _, w := range caps.Warnings() {
    log.Print("secmem: ", w)
}
```

Or from the test binary, with no code:

```sh
go test -run TestReportEnvironment -v
```

## Privilege and the memlock budget — measured

Verified on real hardware across amd64 (kernels 5.10 → 7.0.8) and arm64 (Ampere
Altra, kernels 6.8 → 6.17, four distros), running the identical binary in three
privilege contexts:

| Context | Outcome | Why |
|---|---|---|
| **root** (or any `CAP_IPC_LOCK` holder) | allocation **succeeds** | `CAP_IPC_LOCK` bypasses `RLIMIT_MEMLOCK` entirely, so `mlock` (and `memfd_secret`) always succeed. |
| **non-root**, allocation within `RLIMIT_MEMLOCK` | allocation **succeeds** | small secrets fit the default per-user memlock budget. |
| **non-root**, allocation exceeds `RLIMIT_MEMLOCK` (e.g. `ulimit -l 0`) | **fails closed** (`ErrNoSecureMemory`) | the pages cannot be locked, so secmem refuses rather than leave the secret swappable. |

The takeaway that matters for deployment: the fail-closed path is only reachable
by an **unprivileged process with a memlock budget smaller than the secret**. A
root process can always lock memory, so under root the question is never "will it
fail closed" but "are the *other* protections (kernel isolation, dump exclusion)
in force" — which `Probe` answers.

## Containers

- **Root containers** (the common default): the container "root" holds
  `CAP_IPC_LOCK`, so `mlock` always works and the fail-closed path is not
  reachable — there is nothing to fail. Protections are in force; check `Probe`
  for `memfd_secret` and dump-exclusion status.

- **Rootless containers** (rootless podman/docker): the process is unprivileged,
  and `RLIMIT_MEMLOCK` is whatever the runtime sets — frequently low. A secret
  larger than that budget will **fail closed**. This follows directly from the
  measured non-root behavior above (a rootless container is exactly "unprivileged
  process with a constrained memlock budget"), though it has not yet been run
  inside a container runtime end-to-end. Remedies: raise the limit
  (`--ulimit memlock=…`), call `EnsureMemlockLimit` early, or accept the loud
  failure as the signal it is.

- **Seccomp**: `memfd_secret(2)` is an ordinary syscall that default Docker and
  podman seccomp profiles generally permit, but a hardened profile could block
  it. If blocked, secmem falls through to the `mmap`+`mlock` L3 path and reports
  `memfd_secret = false` — no crash, honest downgrade. Confirm with `Probe` in
  your actual container; this is a consideration, not yet a measured result.

## Kernel configuration

`memfd_secret`'s L4 path (kernel isolation from `/proc/<pid>/mem`, ptrace, and
other readers) requires `CONFIG_SECRETMEM=y`, present from Linux 5.14. **Version
alone is not sufficient** — measured across distros:

| Distro image | Kernel | Arch | `memfd_secret` |
|---|---|---|---|
| Ubuntu 24.04 | 6.8 | amd64 | live |
| Fedora 44 | 7.0.8 | amd64 | live |
| Ubuntu 24.04 (Oracle Cloud) | 6.17 | arm64 | live |
| Oracle Linux 9 (UEK) | 6.12 | arm64 | live |
| Ubuntu 22.04 (Oracle Cloud) | 6.8 | arm64 | live |
| Debian 12 | 6.1 | amd64 | **fallback** — no `CONFIG_SECRETMEM` |
| Rocky 9 | 5.14 | amd64 | **fallback** — no `CONFIG_SECRETMEM` |
| Oracle Linux 10 (UEK) | 6.12 | arm64 | **fallback** — no `CONFIG_SECRETMEM` (regressed from OL9's identical 6.12 UEK, which has it live) |

Where the L4 path is unavailable, secmem uses `mmap`+`mlock` (still off-heap,
still locked, still guarded) and says so through `Capabilities.MemfdSecret =
false`. Do not assume the isolation guarantee from the kernel version; read
`Probe` at startup and treat its report as authoritative for your build and host.
