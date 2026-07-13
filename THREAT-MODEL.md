# secmem threat model

This document states plainly what secmem does **not** protect against. The
per-platform matrix of what it *does* provide is in [README.md](README.md) and,
authoritatively, in the godoc; this is the other half of the honesty contract.

## What secmem is for

secmem reduces the window and the surface in which a secret is exposed in
process memory:

- It keeps secret bytes off the Go GC heap (so they are not scanned, moved, or
  copied by the collector), locked out of swap, and — on Linux amd64 with
  `memfd_secret` — hidden from other readers of process memory.
- It wipes them deterministically on `Destroy`, with an architecture-specific
  routine the compiler cannot elide.
- It makes accidental exposure harder: `Secret` redacts itself through `fmt` /
  `json` / `slog`, guard pages trap linear overflows, and the `redact`
  subpackage scrubs log text.

## What secmem does NOT protect against — on any platform

State these plainly; do not let the guarantees above be read as more than they
are.

- **Cold-boot and full-RAM capture.** If an attacker images all of physical
  memory (freeze-and-dump, DMA, a hypervisor snapshot), any software scheme is
  defeated, because the keys needed to use the secret are captured alongside
  it. The answer to this threat is hardware memory encryption (Intel TME, AMD
  SME/SEV) or a secure enclave — not a userspace library. secmem does **not**
  encrypt secrets at rest in RAM under a rotating key, and does not claim to.

- **A privileged (root / kernel) adversary on platforms without
  `memfd_secret`** — i.e. everywhere except Linux amd64 ≥ 5.14. `mlock` and
  `VirtualLock` stop swapping; they do **not** stop a sufficiently privileged
  process, a debugger, or a kernel from reading the pages.

- **Secrets you copy out of the borrowing closure.** The moment plaintext lands
  in a `string`, an escaping `[]byte`, or a value logged with `%v`, it is
  outside secmem's control and subject to normal GC lifetime. Keep work inside
  `WithBytes`/`WithBytesErr`; do not retain the borrowed slice.

- **The in-use window.** A secret that is actively being used (a signing key
  mid-operation) is plaintext in memory for that time, by necessity. Protection
  is proportional to dormancy; `Seal` the buffer when it is not in use.

- **Code executing inside the process.** Nothing here defends against an
  attacker who already runs code in your address space — such code can call the
  same access methods you can. secmem raises the bar against passive exposure
  (swap, dumps, adjacent overflows, stray logs), not against in-process code
  execution.

- **GC timing of `runtime/secret` heap erasure.** When `Scrub` runs under
  `GOEXPERIMENT=runtimesecret`, heap allocations made inside it are erased once
  the collector observes them unreachable — best-effort timing, never a
  synchronous guarantee. Do not cite it as a compliance control.

## Platform-specific limits

- **`MADV_DONTDUMP` / `MADV_DONTFORK` are best-effort on Linux.** A kernel that
  does not support a flag simply does not apply it; the outcome is reported in
  `Capabilities`, never silently assumed.

- **Windows dump exclusion covers WER dumps only.**
  `WerRegisterExcludedMemoryBlock` keeps the secret out of Windows Error
  Reporting crash dumps; a debugger-driven `MiniDumpWriteDump` by another
  process still captures the pages. For a dormant secret, `Seal` additionally
  encrypts the contents with a kernel-held key (`CryptProtectMemory`), so a
  dump taken while sealed contains ciphertext — but the key is in kernel RAM,
  so this is dump hardening, not cold-boot protection.

- **The guard pages and canary are a bug-catcher, not a confidentiality
  control.** They turn an accidental adjacent over/under-flow into a fault or a
  reported violation. They do nothing against an attacker who can already read
  the mapping.

- **The insecure fallback is exactly that.** `WithInsecureFallback()` places
  secrets on the unprotected Go heap on platforms with no lockable off-heap
  memory. `Capabilities.Insecure` is then true, `Warnings()` leads with the
  exposure, and a one-time warning is logged. Use it only when you have
  accepted the risk.

## Post-quantum posture

The `secmem-crypto` module ships `MLKEM768Key`, at-rest custody for an
ML-KEM-768 (FIPS 203) decapsulation secret. Be precise about what that is
and is not.

- **It is memory hardening applied to a post-quantum key, not a
  post-quantum protocol.** `MLKEM768Key` keeps the 64-byte KEM seed off the
  GC heap for its lifetime and expands it per operation; it does not perform
  key agreement, negotiate parameters, or make a surrounding protocol
  quantum-resistant on its own. The expanded decapsulation key transiently
  touches the heap during each operation — `crypto/mlkem` exposes no in-place
  path — so the seed is hardened at rest and the expansion is not. The type's
  godoc states this inline.

- **The urgent PQ threat is a transport concern secmem does not own.**
  "Harvest now, decrypt later" — recording ciphertext today to break with a
  future quantum computer — is defeated at the key-exchange layer, and Go's
  `crypto/tls` has defaulted to the `X25519MLKEM768` hybrid there (as its top
  preference) since Go 1.24. secmem-crypto hardens where a long-lived KEM
  secret *lives*; it is not a substitute for a post-quantum handshake.

- **Post-quantum signatures (ML-DSA / FIPS 204) are deferred, deliberately.**
  The Go standard library does not yet ship `crypto/mldsa` (as of Go 1.26),
  and secmem-crypto will not vendor a third-party PQ implementation — the
  same discipline that governs the rest of the module: work around the
  standard library only where it is broken for off-heap keys, never merely to
  add an algorithm. A hardened ML-DSA signer follows if and when the standard
  library ships the primitive.

## Composition

secmem is a byte/secret container with a hardened lifecycle; it is not a
RAM-encryption vault. For the cold-boot axis it does not cover, it composes
with a rotating-key in-RAM scheme rather than replacing one. Use the right tool
for the threat you actually face, and read `Capabilities` at startup so you
know which protections your build and platform actually provide.
