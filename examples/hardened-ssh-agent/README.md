# hardened-ssh-agent

A working SSH agent, ~700 lines, whose private keys **never exist on the Go
heap** — and are unreadable by anything, including this process itself,
except during the microseconds of an actual signature.

It speaks the standard agent protocol over `SSH_AUTH_SOCK`. Real `ssh`,
`ssh-add`, `scp`, and `git` work against it unmodified:

```console
$ go run . &
SSH_AUTH_SOCK=/run/user/1000/secmem-agent-4242/agent.sock; export SSH_AUTH_SOCK;
$ export SSH_AUTH_SOCK=/run/user/1000/secmem-agent-4242/agent.sock
$ ssh-add ~/.ssh/id_ed25519
Identity added: /home/you/.ssh/id_ed25519 (you@laptop)
$ ssh-add -T ~/.ssh/id_ed25519.pub      # OpenSSH's own sign-and-verify test
$ ssh your-server
```

Supported: Ed25519 and ECDSA P-256/384/521 identities; list, sign, add,
remove, remove-all, lock, unlock, and **lifetime-constrained adds**
(`ssh-add -t`). Deliberately unsupported (see the forking guide): RSA,
FIDO2 `sk-*` keys, certificates, confirmation prompts (`-c`).

## Why this exists

Every Go program that embeds `golang.org/x/crypto/ssh/agent.NewKeyring()` —
and a great many do — holds private keys as ordinary heap allocations:

| threat | `x/crypto` keyring | OpenSSH `ssh-agent` | this agent |
|---|---|---|---|
| key pages swapped to disk | exposed | `mlockall` (platform-dependent) | mlocked / `memfd_secret` |
| key in a core dump / crash dump | exposed | partially mitigated | `MADV_DONTDUMP` + dumps disabled process-wide |
| GC/runtime copies of key bytes | uncontrolled | n/a (C) | keys live outside the Go heap; wire transients explicitly wiped |
| read primitive in-process (OOB read, `/proc/self/mem` gadget) | exposed | prekey "shielding" (post-Spectre) | keys are **PROT_NONE while idle**; a stray read faults instead of disclosing |
| `/proc/<pid>/mem`, ptrace by same-user process | exposed | exposed | **kernel-invisible** where `memfd_secret` is available (Linux 5.14+) |
| key persists after exit/crash | until pages recycle | zeroed on exit | wiped on `Destroy`, signal-path wipe as backstop, cache-line-flushed |
| key lives longer than intended | manual removal | `-t` lifetime | `-t` lifetime, enforced by **destroying** the SecureBuffer at the deadline |
| heap-buffer overflow reaches key | possible | possible | guard pages fault it; canary detects intra-mapping overflow |

OpenSSH added key shielding precisely because "agent holds keys in plain
memory for hours" is a real attack surface. This agent gets the same class
of protection in pure Go, by construction rather than by patch — the key
storage *is* [secmem](../../README.md).

## The design in one paragraph

An `ssh-add` message arrives carrying a private key. `proto.go` parses it
with subslice-only readers — no copies — so a single `secmem.SecureWipe` of
the message buffer at the end of the request destroys every transient.
Before that wipe, the seed/scalar has been copied into a `SecureBuffer`
(off-heap, mlocked, guard-paged, canaried, dump-excluded), a
`secmem-crypto` signer wraps it, and the buffer is **sealed**: `PROT_NONE`,
contents additionally ciphertext on Windows. It stays sealed — through
idle hours, through the agent-protocol lock, through everything — except
inside `Keyring.Sign`, which unseals, signs via `AsSSH` (SHA-1 `ssh-rsa`
unreachable by construction), and reseals under the same mutex, including
on error paths. The lock passphrase is never stored: locking keeps only an
Argon2id (RFC 9106) derivation in a `SecureBuffer`; unlocking derives the
candidate and compares with `ConstantTimeEqual`, so a wrong guess costs a
full Argon2 work factor and timing reveals nothing.

## What the tests prove

`go test .` — no mocks, no shortcuts:

- **Interop**: every test drives the agent through
  `golang.org/x/crypto/ssh/agent`'s *client* — the reference Go
  implementation — over a real unix socket, and verifies signatures with
  `x/crypto/ssh`. This suite has also been run end-to-end against OpenSSH's
  actual `ssh-add` (add / `-l` / `-T` / `-x` / `-X` / `-D`), which is the
  same wire format.
- **Sealed-at-rest**: tests reach into the keyring and assert
  `IsSealed() == true` after add, after every sign, and while locked. The
  dormant-key claim is checked, not narrated.
- **Lock discipline**: while locked, list is empty and sign/add fail
  (OpenSSH-compatible); a wrong passphrase is refused; the stored state is
  a derivation, not the passphrase.
- **Lifetime enforcement**: a `-t`-constrained key is *destroyed* — its
  SecureBuffer wiped and unmapped, asserted via `IsDestroyed()` — at the
  deadline, and signing with it then fails. Verified end-to-end against
  real `ssh-add -t`.
- **Fail-closed constraints**: a `-c` (confirm) add is refused rather than
  stored without the protection; the spec requires failing an add whose
  constraints the agent can't honor, and we do.
- **Failure honesty**: unsupported key types and unknown messages return
  `AGENT_FAILURE` and the connection survives.

At startup the agent logs `secmem.Probe()` — what this kernel actually
granted (`memfd_secret`? mlock? flush-on-wipe?) and warnings for anything
missing. It never claims hardening it didn't get. All logging passes
through `secmem/redact`, so even a future logging bug is filtered for
credential-shaped output.

## Threat model, honestly

Inherited from [secmem's threat model](../../THREAT-MODEL.md): this defends
key *confidentiality at rest in memory* against swap, dumps, same-user
memory readers, stray in-process reads, and post-exit remanence. It does
**not** defend against code execution inside the agent process (which can
call `Unseal` like the agent does), a hostile root/kernel, or cold-boot RAM
capture. The socket is `0600` in a `0700` directory — anything that can
connect can request signatures, exactly as with `ssh-agent`; the lock and
`-t` key lifetimes are the mitigations for that layer, and per-key
confirmation (`-c`) is a documented fork point.

## Forking guide

This is a minimal core meant to be built on. Natural next steps, in rough
order of effort:

1. **Confirmation prompts** (`ssh-add -c`): the confirm constraint is
   currently *rejected* (fail-closed) because it needs a UI channel. Add a
   `SSH_ASKPASS`-style hook before each `Sign` to turn socket access into
   user-visible events, then accept the constraint.
2. **RSA**: parse the CRT wire fields into SecureBuffers and wrap
   `secmem-crypto`'s RSA signer; `AsSSH` already pins rsa-sha2-only.
3. **FIDO2 / `sk-*` keys**: delegate to a middleware library; the private
   handle still benefits from sealed storage.
4. **Windows**: swap the unix socket for the `\\.\pipe\openssh-ssh-agent`
   named pipe; secmem's Windows backend (VirtualLock, `CryptProtectMemory`
   sealing, WER exclusion) already covers the memory side.
5. **Persistence**: load keys at boot from OpenSSH key files via
   `secmem-crypto`'s OpenSSH import/export instead of requiring `ssh-add`.
