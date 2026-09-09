# Adopting secmem in an existing service

secmem protects what you put in it. The work of adoption is deciding what
that is, finding every place a secret enters or leaves the process, and
sizing the locked-memory budget so the first allocation past the limit does
not fail in production. This guide is the paper exercise to do before the
first `NewBuffer` call, followed by the startup order and the CI checks that
keep the result true. It assumes you have read the
[threat model](THREAT-MODEL.md), which says what the containers do and do
not defend against; this document is about applying them.

## 1. Inventory the secrets

List every value whose disclosure is the incident. For each, record where it
comes from, where it goes, how long it must live, and how big it is:

| Secret | Ingress | Egress | Lifetime | Size |
|---|---|---|---|---|
| API token for the payments provider | secret manager, JSON over HTTPS | `Authorization` header, one request at a time | process | 40 B |
| Database password | environment variable | driver's connect string, once | until connected | 32 B |
| Service signing key (Ed25519) | key file on disk, passphrase-protected | never; signatures only | process | 32 B seed |
| Session keys | derived (HKDF) per session | never; AEAD in place | minutes | 32 B × sessions |
| User password, during login | HTTP form body | Argon2, once | milliseconds | ≤ 128 B |

The inventory is where most adoptions find their surprise: the secret that
arrives inside a larger document (a JSON response, a YAML config), the one
that is re-derived in three places, the one that is logged by a debug handler
nobody remembers. Sizes matter for the budget in section 4; lifetimes decide
what should be sealed when idle.

Two sources deserve a note of their own:

- **Environment variables.** `os.Getenv` returns a string, which can never be
  wiped, and the environment block itself stays in process memory for the
  life of the process, readable by anything that can read the process. Copy
  the value into a buffer at startup and treat the block as a residual you
  have written down, or move the secret to a file, an inherited descriptor,
  or a secret manager.
- **Documents.** A secret inside a decoded JSON or YAML document lands on the
  heap as a string unless the field's type puts it somewhere else. That is
  [pitfall 9](PITFALLS.md#9-leaving-a-secret-inside-a-decoded-document).

## 2. Classify each secret: INTERNAL or EXTERNAL

**INTERNAL**: only this process ever needs the plaintext. Signing keys,
session keys, derived encryption and MAC keys, the seed of a key-exchange
private scalar. The goal is that the plaintext never exists outside a
`SecureBuffer` from ingress to `Destroy`. That is achievable, because every
operation on such a key can run in place: `secmem-crypto`'s signers sign
from the buffer, `OpenInto` and `SealFrom` encrypt and decrypt from it, the
`*Into` KDFs derive into it. `Seal` the buffer whenever the key is dormant;
protection is proportional to dormancy.

**EXTERNAL**: the plaintext has to leave the process in the clear. A bearer
token in a request header, a passphrase the user types, a key file written
to disk, a password handed to a database driver, a secret passed to a child
process. A copy at the boundary is unavoidable, so the goal changes: one copy
per crossing, as short-lived as the crossing allows, built inside a `Scrub`
window and wiped after, and a written residual for whatever the helper cannot
reach. `httpauth` is the model: the header string exists for one request, the
scratch it was assembled from is wiped, and the package doc says what is still
a string.

A secret can be both in sequence. The database password is EXTERNAL at
connect time and should be gone afterwards; the driver's own copy is a
residual to record.

The classification is not a judgement about importance. It decides which
question you ask of each secret: "does the plaintext ever leave the buffer?"
for INTERNAL, and "how many copies exist per crossing, and for how long?" for
EXTERNAL.

## 3. Draw the boundary map

For every secret, list each crossing and the helper that handles it. The
crossings this repository has a helper for:

| Crossing | Helper |
|---|---|
| File or stream into a buffer | `NewBufferFromReader`, `SecureBuffer.ReadFrom` |
| Key file into a signer | `ParsePrivateKey`, `ParsePrivateKeyWithPassphrase` |
| Terminal or form input that arrives as `[]byte` | `NewBuffer`, which wipes its input |
| Decoded document field | a `json.Unmarshaler` on the field type; see pitfall 9 |
| Password into a key | `Argon2Into` and the other `*Into` KDFs; `Argon2Workspace` for the working state; `BcryptPBKDFInto` only where a format names bcrypt_pbkdf |
| Buffer into an HTTP header | `httpauth` |
| Buffer into a key file | `MarshalOpenSSHPrivateKey`, `MarshalOpenSSHPrivateKeyWithPassphrase`, `…WithPassphraseParams` |
| Buffer into a socket or file | `SecureBuffer.WriteTo`, on the raw writer; a `bufio.Writer` in between keeps a copy |
| Buffer into a log | never. `Secret` redacts itself; `redact` is the backstop for text that was assembled anyway |

Every crossing without a row here is a plain `string` or `[]byte` crossing.
Some are unavoidable: a driver that takes a DSN string, a child process that
reads an environment variable, a library that caches the key it was given.
Those go into your own threat model as named residuals, with the lifetime of
the copy stated. An adoption is honest when that list exists and is short,
not when it is empty.

Two shapes to look for on the map:

- **A secret that crosses in both directions.** A key parsed from a file and
  later exported again should never round-trip through a `[]byte`; the
  ingress and egress helpers both work in place, and the buffer is the only
  copy in between.
- **A helper that is not in a window.** Everything in the table that touches
  plaintext runs inside `Scrub` or `ScrubErr` already. If you write a crossing
  of your own, the window is yours to open, and the constraints in the
  `Scrub` doc apply: no goroutines, no writes to globals or caches
  ([pitfall 10](PITFALLS.md#10-writing-to-globals-or-caches-inside-a-scrub-window)).

## 4. Size the locked-memory budget

Every container here locks its pages, and the budget for locked pages is
finite: `RLIMIT_MEMLOCK` on Linux and the BSDs, the minimum working set on
Windows. An allocation past the limit fails closed with the platform's
error, which is the right behaviour and a bad surprise at 3 a.m. Compute the
peak and set it at startup.

```
budget  ≥  Σ over buffers      pageround(len)
         + Σ over arenas       count × (slotSize + 16)
         + Σ over workspaces   Argon2Workspace.Size()
         + transients
         + headroom
```

where:

- **`pageround(len)`** is `len` rounded up to a whole page. A `SecureBuffer`
  locks the pages holding the secret and nothing else: the guard pages on
  either side are reserved address space with no backing frames and cost no
  budget. The rounding is what dominates for small secrets. A 40-byte token
  costs a full page, 4 KiB on x86-64 and on most arm64 kernels, 16 KiB or
  64 KiB on some; read `os.Getpagesize()` on the target rather than assuming.
  The ceiling is therefore `limit / pagesize` small buffers: with the 8 MiB
  systemd default that is 2048 buffers at 4 KiB pages and 128 at 64 KiB.
- **Arenas** cost `slotSize + 16` locked bytes per slot as one mapping, plus
  16 bytes of ordinary heap per slot for the index. Many same-sized secrets
  belong in an arena: 500 session keys cost 24 KB locked in an arena of
  32-byte slots and 2 MiB as separate buffers.
- **`Argon2Workspace.Size()`** is a little over the cost parameter's memory:
  the matrix in KiB, plus about 3 KiB per thread of lane scratch, plus a few
  KiB fixed. A pool costs that times its size. At the package default of
  64 MiB a single workspace exceeds the systemd default on its own, and
  `Argon2Into` without a workspace uses the heap for its working state, not
  the budget.
- **Transients** are the buffers helpers allocate for one call. The
  passphrase paths of `ParsePrivateKeyWithPassphrase` and
  `MarshalOpenSSHPrivateKeyWithPassphrase` (and its `Params` form) take a
  scratch of a couple of pages plus the decoded key; `BcryptPBKDFInto` takes
  a workspace of a little over 4 KiB, which is two 4 KiB pages; the parsers
  allocate the decoded file and the key they return. Multiply by the peak
  number of concurrent calls.
- **Headroom.** A quarter over the computed peak is a reasonable default; the
  cost of being generous is locked RAM that is otherwise idle, the cost of
  being exact is an allocation failure under load.

A worked example, for the inventory above on 4 KiB pages: three tokens and
one signing key are four pages (16 KiB); 500 session keys in an arena are
24 KB, rounded to 6 pages; a pool of four Argon2 workspaces at 64 MiB is a
little over 256 MiB. The peak is about 257 MiB before transients, so
`EnsureMemlockLimit(320 << 20)` at startup covers it with room.

Then set it:

- Call `EnsureMemlockLimit(budget)` once, before the first allocation. It
  returns the value achieved together with a non-nil error when the request
  could not be met; treat that error as a deployment error, not a warning,
  because the alternative is a `ErrNoSecureMemory` or `mlock` failure from
  whichever allocation first crosses the line.
- On Linux, raising the soft limit up to the hard limit needs no privilege.
  Raising the hard limit needs `CAP_SYS_RESOURCE`, or the deployment sets it:
  `LimitMEMLOCK=` in a systemd unit, `--ulimit memlock=` for a container. A
  root process or any `CAP_IPC_LOCK` holder bypasses the limit entirely, at
  which point the budget is physical memory and any count taken from an
  untrusted source must be bounded by you, as the threat model's
  availability entry explains.
- On Windows, the budget is the process minimum working set and the default
  is small enough that a 1 MiB buffer was refused on a stock workstation.
  `EnsureMemlockLimit` raises it and reports what it got.

[ENVIRONMENTS.md](ENVIRONMENTS.md) records the measured behaviour under root,
non-root and containers.

## 5. Startup and shutdown order

Before the first secret exists:

1. `HardenProcess` and `DisableCoreDumps`, so the process is non-dumpable
   before there is anything to dump.
2. `EnsureMemlockLimit` with the budget from section 4.
3. `Probe`, and log its `Warnings` (they contain no secrets). Decide in
   advance which capabilities your deployment requires and refuse to start
   without them, rather than discovering at incident time that
   `memfd_secret` was never available on that kernel.
4. `InstallTerminationWipe`, so a signal wipes every registered buffer on
   the way out.

Then load the secrets, in the order the boundary map says: file into buffer,
document field into buffer, password into key. On shutdown, `Destroy` each
buffer as its owner finishes with it; `WipeAllSecrets` is the last resort for
whatever is still registered, not the plan.

## 6. Keep it true in CI

- Run `secmem-lint` as a vet tool. It rejects the one mistake with no visible
  symptom, the borrowed slice escaping its closure.
- Run the test suite once with a small lock budget (`ulimit -l 64` on Linux)
  to see the fail-closed path exercised, and once with the production budget.
- Keep the residual list from section 3 in your own threat model and revisit
  it whenever a new crossing is added. A new integration that takes the
  secret as a `string` is a new residual, and the review is where it gets
  written down.
