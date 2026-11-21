# secmem across runtime environments

Whether secmem can protect a secret depends on three things about the
environment it runs in: the process **privilege** (does it hold
`CAP_IPC_LOCK`?), the **`RLIMIT_MEMLOCK`** budget, and the kernel's
**`CONFIG_SECRETMEM`**. This document records how secmem behaves across those
axes, and — per the honesty contract — marks what was measured on real hardware
versus what is reasoned from it. It is a Linux document; the Windows
equivalent of the memlock budget (the process working-set minimum) is
covered in [WINDOWS.md](WINDOWS.md).

The one invariant across every environment: **secmem never silently degrades.**
If it cannot obtain locked, off-heap memory the constructor returns an error
rather than placing a secret on unprotected pages: the wrapped `mlock` error
where the kernel refuses the lock, which no option overrides, and
`ErrNoSecureMemory` on a platform with no lockable memory at all, unless you
explicitly opt in with `WithInsecureFallback()`.

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

Verified on amd64 VMs (Hetzner cloud, WSL2, a local Hyper-V guest; kernels
5.10 → 7.0.8) and arm64 Ampere Altra VMs on OCI (kernels 6.8 → 6.17, four
distro images), running the identical binary in three privilege contexts:

| Context | Outcome | Why |
|---|---|---|
| **root** (or any `CAP_IPC_LOCK` holder) | allocation **succeeds** | `CAP_IPC_LOCK` bypasses `RLIMIT_MEMLOCK` entirely, so `mlock` (and `memfd_secret`) always succeed. |
| **non-root**, allocation within `RLIMIT_MEMLOCK` | allocation **succeeds** | small secrets fit the default per-user memlock budget. |
| **non-root**, allocation exceeds `RLIMIT_MEMLOCK` (e.g. `ulimit -l 0`) | **fails closed** (the wrapped `mlock` error: `ENOMEM` over a non-zero limit, `EPERM` at a zero one) | the pages cannot be locked, so secmem refuses rather than leave the secret swappable. |

**Kernels that charge `memfd_secret` per fault** ("mm/secretmem: properly
account locked pages": mainline since September 2026, and backported to stable
kernels as a security fix; first seen here on Ubuntu 26.04's 7.0.0-1019-azure)
change the first row for that tier only. `CAP_IPC_LOCK` no longer lifts the
limit for secretmem, the budget is counted per user across all of the uid's
processes, and the kernel answers a page fault over it with `SIGBUS` instead of
refusing the mapping. secmem faults every page in inside the constructor, so
the refusal is still an error there and never a signal later; the allocation
then falls through to mmap+mlock, where the table above applies unchanged. A
root process with a low `RLIMIT_MEMLOCK` therefore still gets its buffer, on
the mmap+mlock tier once the secretmem budget is spent: check
`Capabilities().MemfdSecret` per buffer, and raise the limit
(`EnsureMemlockLimit`) to keep large allocations on the stronger tier. Releases
before this fix do not populate, and on such a kernel an over-budget allocation
kills the process with `SIGBUS` at its first write.

The takeaway that matters for deployment: the fail-closed path is only reachable
by a process **without `CAP_IPC_LOCK` and with a memlock budget smaller than
the secret** — which includes root in a default container (below).
[ADOPTION.md](ADOPTION.md) has the formula for sizing that budget from the
containers a service holds at peak. A
process holding `CAP_IPC_LOCK` can always lock memory, so there the question is never "will it
fail closed" but "are the *other* protections (kernel isolation, dump exclusion)
in force" — which `Probe` answers.

## Containers

- **Root containers** (the common default): the container "root" does **not**
  hold `CAP_IPC_LOCK` by default — the default Docker and containerd
  capability set omits it. Unless the container runs with
  `--cap-add IPC_LOCK` (or privileged), locking is bounded by
  `RLIMIT_MEMLOCK` exactly as for a non-root process, and the fail-closed path
  is reachable. With the capability, `mlock` always works. Either way, check
  `Probe` for `memfd_secret` and dump-exclusion status.

- **Rootless containers** (rootless podman/docker): the process is unprivileged,
  and `RLIMIT_MEMLOCK` is whatever the runtime sets. Allocations beyond that
  budget **fail closed**, exactly as for a non-root process above. Measured in
  rootless podman; the next section has the numbers. Remedies: raise the limit
  on the container (`--ulimit memlock=…`), or accept the loud failure as the
  signal it is. `EnsureMemlockLimit` raises the soft limit to the hard one and
  no further: a container whose hard limit is the low one needs the runtime
  flag.

- **Seccomp**: `memfd_secret(2)` is an ordinary syscall. Podman's default
  profile permits it (measured, next section); Docker's default profile is
  expected to as well but has not been run here, and a hardened profile could
  block it. If blocked, secmem falls through to the `mmap`+`mlock` L3 path and
  reports `memfd_secret = false` — no crash, honest downgrade. That fall-through
  under a blocking profile is reasoned, not measured. Confirm with `Probe` in
  your actual container.

### Rootless podman — measured

Run on 2026-11-21 at commit `6de8fc3`: rootless podman 6.0.2 (a podman machine
on WSL2, kernel 6.18.26.1-microsoft-standard-WSL2, which charges secretmem at
`mmap`), image `golang:1.27.4-bookworm`, podman's default seccomp profile in
filter mode, container uid 0 mapped to an ordinary host uid, no
`CAP_IPC_LOCK` in the container's capability set. `Probe` inside it:

```
linux/amd64 [off-heap mlock memfd_secret no-dump no-fork wipe+flush frame-scrub preempt-suppress vector-clear gp-clear guard-pages destroy-quarantine] missing:[runtime-secret]
```

Each row sets the soft and hard limit to the same value, so nothing inside the
container can raise it.

| `RLIMIT_MEMLOCK` | 32-byte buffers that fit | The test suites |
|---|---|---|
| 64 MiB (what this podman gives a container by default) | 4096 allocated and the test stopped there, all on `memfd_secret` | core, `secmem-crypto` and `secmem-lint` pass, plain and under `-race`. One test skips for the budget: the 64 MiB Argon2 workspace needs slightly more than 64 MiB locked. |
| 64 KiB (`--ulimit memlock=65536:65536`) | 6: five on `memfd_secret` at three pages each (this kernel charges the guard pages), one more on `mmap`+`mlock`, then the wrapped `mlock` error. 16 with `WithoutMemfdSecret`. Destroying them gives the whole budget back. | **Do not pass.** In the plain run 61 core tests and 209 `secmem-crypto` tests fail, subtests counted. Nearly all report a refused allocation directly; the dozen or so that report something else come after one in the same test and were not traced one by one. That is a statement about the tests, which hold more buffers at once than sixteen pages allow and mostly report a refusal as a failure where the convention is to skip. The library did what the table above says: it returned the error every time and placed nothing on unlocked pages. |

What this does and does not show:

- A rootless container with podman's default limit runs secmem with every
  protection the kernel offers, `memfd_secret` included.
- A 64 KiB budget is enough for a handful of keys and nothing else. A service
  that holds a buffer per connection or session exhausts it at once;
  [ADOPTION.md](ADOPTION.md) has the sizing formula.
- `secmem-crypto` was tested against the released core it requires (v0.8.1),
  the way a consumer builds it.
- Not measured: a rootless container on a kernel that charges `memfd_secret`
  per fault, where the guard pages are not charged and the counts in the second
  row will differ; rootless Docker; arm64.

## Kernel configuration

`memfd_secret`'s L4 path (kernel isolation from `/proc/<pid>/mem`, ptrace, and
other readers) is attempted on linux/amd64 and linux/arm64 only. It requires
`CONFIG_SECRETMEM=y`, present from Linux 5.14, and on arm64 a linear map the
kernel can split at page granularity — `rodata=full` (or `DEBUG_PAGEALLOC`, or
KFENCE); see [KERNELS.md](KERNELS.md). **Version alone is not sufficient** —
measured across distros:

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
