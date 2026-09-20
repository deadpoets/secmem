# What is protected, per key type and per attack

This is the summary: which secmem entry point protects which key, how far,
and which attacks remain open when you use it. The per-platform mechanics are
in the [README's platform matrix](README.md#the-platform-guarantee-matrix),
the non-goals in [THREAT-MODEL.md](THREAT-MODEL.md), and the evidence behind
each row in [TESTING.md](TESTING.md).

## The three levels

Every level is a claim about one thing: where the key, and every value derived
from it that would recover it, can be found in the memory of a running process.
It is measured, not argued — see [How the levels are measured](#how-the-levels-are-measured).

**Protected.** Outside an operation, the key exists only in memory secmem
locks: nothing outside it after construction, between operations, after garbage
collection, or after `Destroy`, on both kinds of build. During an operation the
key is in the stack and registers of the goroutine running it (for `WithAESGCM`,
also in two heap objects for the length of the callback), and those are wiped
when the operation returns.

**Protected at rest only.** The durable copy is protected as above, but every
operation leaves copies of the key outside locked memory that secmem cannot
reach to wipe. What happens to them depends on the build:

- *Legacy build* — Windows, macOS, or Linux without
  `GOEXPERIMENT=runtimesecret`: nothing erases them. They stay until the memory
  is reused, and the residue test finds them after several collections and after
  `Destroy`.
- *runtime/secret build* — linux/amd64 or linux/arm64 with the experiment: the
  runtime erases them, but only at the first garbage collection after they
  become unreachable, not when the operation returns. In a process that
  allocates little, that can be up to two minutes (the runtime forces a
  collection when none has run for that long). A key used even once a second
  therefore has a copy outside locked memory almost all the time.

The constructors for these types refuse on a legacy build with
`ErrHeapTransients` unless the caller passes `AllowHeapTransients()`.

**Not protected.** The key is on the ordinary Go heap for as long as the object
holding it is alive, and afterwards until the memory is reused.

## By key type and algorithm

"Left outside locked memory after use" is what the residue test finds with the
victim frozen between operations; the scenario named is the one that measures
it.

| Entry point | Level | Left outside locked memory after use | Residue scenario |
|---|---|---|---|
| `Ed25519Signer` (sign, generate, `NewEd25519Signer`) | **Protected** | nothing: not the seed, the expanded secret, the private or nonce scalar, or the nonce digest | `Ed25519Signer` |
| `ParsePrivateKey`, `ParsePrivateKeyWithPassphrase` for an Ed25519 file | **Protected** | nothing: not the seed, the passphrase, the bcrypt output, or either AES schedule | `ParsePrivateKey/Ed25519-PKCS8`, `ParsePrivateKeyWithPassphrase/Ed25519-OpenSSH` |
| `MarshalOpenSSHPrivateKey…` | **Protected** | nothing: not the seed or the passphrase (the salt is random, so the derived key is not searched) | `MarshalOpenSSHPrivateKeyWithPassphrase/Ed25519` |
| `X25519Key` | **Protected** | nothing: not the scalar, the clamped scalar, or the shared secret | `X25519Key` |
| `HKDFInto`, `HMACInto` over SHA-2 or SHA-3 (and `HKDFSHA256Into`, `HMACSHA256Into`) | **Protected** | nothing: not the secret, the key XORed into either pad, the pseudorandom key, either digest state, or the output | `HKDFSHA256Into`, `HMACSHA256Into`, `HKDFInto/SHA-512-long-secret`, `HMACInto/SHA3-256-long-info` |
| `HKDFInto`, `HMACInto` over any other hash | **Protected at rest only** (refused on a legacy build without the opt-in) | the key's pads and digest states in `crypto/hmac`'s heap objects | not scanned: it is the `crypto/hmac` path, which left exactly these behind when the SHA-256 scenarios ran on it before `HMACInto` moved in place |
| `WithAESGCM` | **Protected** between uses | nothing: not the key, either round-key schedule, or the GHASH table | `WithAESGCM+SealFrom+OpenInto` |
| `OpenInto`, `SealFrom` | **Protected** for the plaintext | the plaintext: nothing. The AEAD key: wherever the `cipher.AEAD` passed in keeps it | `SealFrom+OpenInto/plaintext` |
| A `cipher.AEAD` or `cipher.Block` you build yourself | **Not protected** | the expanded key schedule and GHASH table, for the object's lifetime and after | not a secmem entry point; the `WithAESGCM` scenario with its wipes removed — the same objects, left alone — finds the key and both schedules hundreds of times |
| `Argon2Into`, `Argon2IDKeyInto`, `Argon2DeriveInto` | **Protected** after the call | nothing: not the password, H0, or the output. During the call the working set is a heap allocation, pageable and dumpable, wiped before return | `Argon2IDKeyInto` |
| `Argon2Workspace`, `Argon2Pool` | **Protected** | nothing; the working set is locked memory | `Argon2Workspace` |
| `BcryptPBKDFInto` | **Protected** | nothing: not the password or the output | `BcryptPBKDFInto` |
| `MLKEM768Key` — the decapsulation key | **Protected** (but the type is refused on a legacy build without the opt-in, for the next row) | nothing: not the seed halves, the secret polynomial s, σ, or the SHAKE state that absorbed z | `MLKEM768Key/decapsulation-key` |
| `MLKEM768Key.Decapsulate` — each ciphertext's shared key | **Protected at rest only** (refused on a legacy build without the opt-in) | the 32-byte message decapsulation recovers, which with the public key's hash gives that ciphertext's shared key; the decapsulation key is not exposed | `MLKEM768Key/recovered-message` |
| `Encapsulate` | **Protected** | nothing: not the message, the shared key, or the encryption randomness returned beside it, which with the public ciphertext recovers the shared key | `Encapsulate/shared-key` |
| `ECDSASigner`, `GenerateECDSASigner`, EC key files | **Protected at rest only** (refused on a legacy build without the opt-in) | the private scalar, in several standard-library objects per signature | `ECDSASigner/P-256` |
| `RSASigner`, `GenerateRSASigner`, RSA key files | **Protected at rest only** (refused on a legacy build without the opt-in) | d, p, q, dP, dQ, qInv and the FIPS-form key's limbs, per signature | `RSASigner/2048` |
| `GenerateDicewarePassphrase` | **Protected** by construction | not scanned: the passphrase is random, so the parent cannot know what to search for. It is assembled in the buffer's own memory with no intermediate string, and word selection reads every entry of the list whatever index is drawn | — |
| `SecureBuffer`, `Secret`, `ArenaSlot` holding a key your code uses | **Protected** at rest; after use, as protected as your code | what your callback copied out. The borrow and copy paths clear the registers when they return, so a copy that stays inside locked memory leaves nothing; a preemption *during* a long callback is only prevented inside `Scrub` | `WithBytesErr/copy-then-preempted`, `control/preempted-copy-in-scrub` |
| `ExposeString`, `CopyOut` into a heap slice, `WriteTo` | **Not protected**, by design | the copy you asked for — these are the egress paths | — |

Where the secmem-crypto README's tables classify an entry point as
*contained*, this table says **Protected**; *runtimesecret-only* is
**Protected at rest only**.

## By attack

What each level leaves open. "During use" is the operation itself: the key in
the stack and registers of the goroutine running it, for as long as it runs.

| Attack | Protected | Protected at rest only | Not protected |
|---|---|---|---|
| **Swap or pagefile** | The durable copy is locked (`mlock`; on Windows `VirtualLock`, which keeps it resident while the process runs but not when the whole working set is outswapped). The stack during use can be paged | as Protected, and the per-use heap copies can be paged until erased | the key can be paged at any time |
| **A core dump or crash dump** | The durable copy is excluded where the platform allows it (Linux `MADV_DONTDUMP`, and `memfd_secret` pages cannot be read at all; Windows registers it for WER exclusion; macOS cannot) and `HardenProcess` disables dumps on Linux. A dump taken during use contains the key in the stack | as Protected, plus the per-use copies: in any dump on a legacy build; until the next collection on a runtime/secret build | in the dump |
| **Another process reading this one's memory** (`/proc/<pid>/mem`, `ptrace`, `process_vm_readv`, a debugger) | On linux/amd64 and arm64 with `memfd_secret` live, the durable copy is unreadable even by root. Elsewhere any reader allowed to trace the process can read it (`HardenProcess` stops unprivileged tracers on Linux). After use there is nothing else to find; during use the key is in the stack | as Protected, plus the per-use copies, readable as long as they last | readable by any permitted reader |
| **A memory-disclosure bug in the process** (an over-read through `unsafe` or cgo, a reused buffer) | The durable copy is in its own mapping, bracketed by guard pages that trap a linear overrun from adjacent memory; nothing else is left to disclose after use | as Protected, plus the per-use heap copies, which sit among ordinary heap objects | in reach of any heap over-read |
| **Code running inside the process** | not protected: such code can call the signer or `WithBytes` itself | not protected | not protected |
| **The kernel, a hypervisor, cold boot, DMA** | not protected: `memfd_secret` removes the pages from the kernel's direct map, which stops passive reads, not ring-0 code or physical capture | not protected | not protected |
| **An on-die accelerator on a unified-memory SoC** | not protected: locking constrains the CPU's view, not a GPU's or NPU's | not protected | not protected |
| **Timing and cache side channels** | not addressed by secmem, and not measured: the arithmetic is the standard library's, or `filippo.io/edwards25519`'s, called or copied unchanged, and inherits their constant-time properties. secmem's own code over key bytes — the HMAC pad XOR, X25519 clamping, comparison through `crypto/subtle`, Diceware word selection (shown to read every entry) — is written not to branch or index on their values. Argon2d, and Argon2id after its first half pass, index memory by data by design of the algorithm | same | same |

## RSA and ECDSA stay gated

This is a decision, not a gap waiting to be filled. The copies that leak those
keys are made inside the standard library's own `crypto/internal/fips140`
code, which rebuilds the private key on the heap for every signature; nothing
exported can reach them. The only fix would be to fork that code — the ECDSA
and RSA signing paths and the `bigmod` arithmetic under them — into this
module, several thousand lines of the most consequential code in Go, where a
mistake does not fail a test but silently weakens or leaks the key it was
written to protect. That trade is not worth making, so it will not be made,
and these types stay refused on a build that cannot erase the copies.

What that means if you need RSA or ECDSA:

- **Preferred:** keep the key where it is never in this process's memory — a
  TPM, an HSM, a KMS, or a signing service. secmem's own guarantees stop at
  the process boundary; those move the key outside it.
- **Acceptable:** a short-lived process that loads the key, signs, and exits,
  so the copies die with it and the window is seconds rather than the life of
  a service.
- **A deliberate residual:** pass `AllowHeapTransients()` for a key that is
  loaded once and used rarely — a release-signing key, say. Write it down as a
  residual. The buffer still gives real at-rest custody: the durable copy is
  locked, guard-paged, wiped on `Destroy` and excluded from dumps. What it
  does not give is protection during and after each signature.
- **Not reasonable:** a service that signs continuously on a build without
  `GOEXPERIMENT=runtimesecret`. It has an unwiped copy of the key on the heap
  at almost every moment, and opting in only silences the error that says so.
  A runtime/secret build is better but not a fix: the copies are erased at the
  next garbage collection, and a busy signer makes new ones faster than that.

Ed25519 and X25519 have in-place implementations here and are never refused,
so where the protocol allows a choice, they are the choice that this library
can actually protect.

## How the levels are measured

`secmem-crypto`'s out-of-process residue test (`residue_test.go` and its
per-OS halves, with `residue_scenarios_test.go`) runs each entry point in a
victim process that received known key material straight into a
`SecureBuffer`, freezes it after construction, after use, after garbage
collection and after `Destroy`, and reads every readable page of it, counting
matches outside the memory the kernel reports as locked. On Linux it freezes
the victim with `SIGSTOP`, reads it through `/proc/<pid>/mem` and takes the
locked mappings from `smaps`; on Windows it suspends every thread of the
victim, reads it with `VirtualQueryEx` and `ReadProcessMemory`, and asks
`QueryWorkingSetEx` per page whether the kernel has that page locked in
physical memory — the kernel's answer in both cases, never the victim's. It searches for
every encoding it can derive that recovers the key: raw and little-endian
integers, the RSA FIPS-form limbs and Montgomery constants, the Ed25519 scalars
in `edwards25519`'s internal layout and the nonce digest, the HMAC pads and
chaining values, the ML-KEM secret polynomial and SHAKE state, the AES round
keys and GHASH table, Argon2's H0, and each output. Every scan must also find a
heap canary the victim keeps alive, so a scan that sees nothing fails. Controls
show the scan finding a heap copy, a copy made outside `Scrub`, and a copy the
runtime saved to the stack by preemption, and on Windows a control that a
locked page is reported locked and a heap page is not — without which the scan
could call everything locked and find nothing anywhere. CI runs it on
linux/amd64 and linux/arm64 on both kinds of build, and on windows/amd64, with
no skip allowed.

Its limits, which are the limits of the levels above:

- **macOS is not measured.** It runs the same Go code as a Linux legacy build,
  so the legacy column is what to expect there, but the scan has not been run
  on it. Linux and Windows are measured.
- **Windows is measured, and differs in two ways.** Every entry point the
  table calls *Protected* leaves nothing there either, and the *Protected at
  rest only* rows leave the same copies as a Linux legacy build. But: locked
  pages are readable by any process with `PROCESS_VM_READ` (there is no
  `memfd_secret` equivalent), so the scan finds the buffers' own contents and
  counts them as locked hits — the row "another process reading this one's
  memory" is weaker there, as it says. And `Scrub` cannot block Go's
  asynchronous preemption on Windows, because there is no signal to block: a
  control that deliberately spins inside a window with a secret in registers
  leaves about thirty copies of it in memory the window does not wipe, and
  they survive collection and `Destroy`. No real entry point showed that in
  the scan — their operations are too short to be preempted often — but it is
  not ruled out for a long operation, and it cannot be fixed from this side.
- **What it cannot search for.** The ECDSA nonce (random per signature), the
  RSA signature's intermediate Montgomery tables, Argon2's memory blocks, the
  Blowfish schedule inside bcrypt_pbkdf, and the key a passphrase export derives
  from a fresh random salt. A value nobody can predict is not searched.
- **Between operations, not during.** Each scan freezes the victim between
  operations. The in-use window is real, and the table above names it rather
  than measuring it.
- **The standard library it ran against** — go1.26 — decides what the
  *Protected at rest only* rows leave behind. A later release can change it;
  the test asserts that those copies exist, so a release that removes them turns
  it red and prompts this page to be rewritten.

## Choosing

- **Signing:** Ed25519 is protected; ECDSA and RSA are not beyond at-rest
  custody, and that is settled rather than pending — see below. Keys that must
  be ECDSA or RSA — a WebPKI certificate, UEFI Secure Boot's RSA-2048, a TPM
  policy key — belong in an HSM, a TPM, or a KMS, or in a short-lived process
  that loads the key, signs, and exits.
- **Key agreement:** X25519 is protected. For ML-KEM the decapsulation key and
  the sender side are protected, but each decapsulation's shared key is exposed
  as the table says, so `MLKEM768Key` is refused on a legacy build like RSA and
  ECDSA.
- **Derivation:** HKDF and HMAC over SHA-2 or SHA-3, Argon2 and bcrypt_pbkdf
  are protected.
- **Encryption:** use `WithAESGCM` per use, with `OpenInto` and `SealFrom` for
  the plaintext. A `cipher.AEAD` kept for a session keeps its key on the heap.
- **Your own code on a key:** do it inside `Scrub`, and do not copy the bytes out
  of the borrow.
