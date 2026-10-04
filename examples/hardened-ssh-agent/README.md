# hardened-ssh-agent

A working SSH agent, about a thousand lines, whose private keys are **never
at rest on the Go heap** — and are unreadable by a stray read inside this
process, or by a passive reader of its memory where the platform allows,
except during the microseconds of an actual signature. The wire message an
`ssh-add` arrives in is one heap buffer, wiped after dispatch. That holds
for every identity it accepts by default; ECDSA is the one place it needs a
build flag or an explicit opt-in, set out below. The limits are in the
threat-model section.

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

### ECDSA identities

Ed25519 signs in place, so an Ed25519 key never reaches the heap on any
build. ECDSA signs through the standard library, which copies the private
scalar onto the heap for every signature, and only `runtime/secret` erases
those copies. So by default the agent accepts ECDSA identities only on a
`GOEXPERIMENT=runtimesecret` build (linux/amd64 or linux/arm64):

```console
$ GOEXPERIMENT=runtimesecret go run .
```

On any other build `ssh-add` of an ECDSA key fails with "agent refused
operation", and the agent logs why. Pass `-allow-heap-transients` to accept
ECDSA keys anyway. That is a real trade: an agent under use signs often, so
the scalar is on the heap for most of its life, and a heap dump of the agent
contains it. The agent states which posture is in force when it starts.

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
the message buffer at the end of the request destroys every transient (a
message that never arrives in full is wiped where the read fails). That
buffer is ordinary heap memory: an add's key is in it from arrival until
the wipe, which includes any wait for the keyring lock behind another
connection's Argon2 derivation.
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
full Argon2 work factor and timing reveals nothing. Around all of it, the
accept loop serves at most 64 connections at once and gives each request
30 s to arrive, so a client that connects and says nothing costs a slot for
30 s and nothing more (details under the threat model).

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
  real `ssh-add -t`. The deadline is a wall-clock one: with the clock
  stood in for one that slept eight hours through a one-hour lifetime, the
  first request after resume destroys the key instead of signing.
- **Fail-closed constraints**: a `-c` (confirm) add is refused rather than
  stored without the protection; the spec requires failing an add whose
  constraints the agent can't honor, and we do.
- **Failure honesty**: unsupported key types and unknown messages return
  `AGENT_FAILURE` and the connection survives.
- **Availability under a hostile local client** (`serve_test.go`, on the
  wire, with the agent's real accept loop): a client that connects and
  sends nothing, half a length prefix, or a header whose body never comes
  is disconnected when the per-message deadline lapses — not before, and
  not by some other limit; a client that pauses for less than the deadline
  between requests is served for as long as it likes, because the deadline
  is per message; with the cap lowered to two, a third connection is
  neither served nor refused until one of the first two ends, and then
  gets the reply to the request it queued; and stopping the agent
  disconnects idle clients at once instead of waiting out their deadline.
  Each test also checks the control is no stricter than documented (the
  agent still answers). The stalled-client test was checked to fail against a
  build with the deadline removed and the connection-cap test against one
  with the cap removed; the per-message and shutdown tests are behaviour
  checks that pass on both builds.

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

**Availability on the socket** is a separate question from key
confidentiality, and the answer is bounded, not absolute. Anything that can
connect can also try to keep the agent busy, and an agent that one idle
client can pin is not hardened in any useful sense. So the agent bounds
what a connection can cost it, in two plain-Go controls in `main.go`:

- Every request gets **30 s to arrive in full** (`messageTimeout`), armed
  before the length prefix and covering the body, and every reply gets the
  same allowance to be handed to the kernel. A client that connects and
  goes quiet, stalls halfway through a message, or stops reading its
  replies is disconnected when that lapses, and its goroutine and
  connection slot are released. The deadline is re-armed per message, so a
  busy client is never cut off. OpenSSH's `ssh` and `ssh-add` hold an agent
  connection only while using it and are unaffected; what this does cut off
  is any client that holds an agent connection idle for 30 s — including a
  long-lived program on an `ssh -A` agent-forwarding host that opens
  `SSH_AUTH_SOCK` once and reuses it — whose next request then fails (EOF
  or EPIPE) and which must reconnect. OpenSSH's `ssh-agent` has no such
  timeout.
- At most **64 connections are served at once** (`maxConns`). The 65th is
  not refused: it sits, completed but unread, in the kernel's listen backlog
  until a served connection ends, and is then served in turn. That holds up
  to the size of the listen backlog (`net.core.somaxconn`, 4096 by default on
  Linux 5.4 and later, 128 before); connections beyond it fail at the kernel
  with `EAGAIN`, a limit no user-space cap can move. The slot is taken *before* `accept`, so an excess
  connection costs the process neither a goroutine nor a file descriptor.
  With the deadline above, waiting behind idle connections is bounded by
  30 s.

What this does **not** do, stated so nobody relies on it: a client that
keeps 64 connections *actively* busy still starves everyone else, for as
long as it keeps that up — the cap turns unbounded resource growth into a
queue, it does not ration the queue between clients. A client can `LOCK`
the agent, as it can OpenSSH's, and while it is locked nothing signs until
someone unlocks it. And the Argon2id derivations behind `LOCK`/`UNLOCK`
run **one at a time under the keyring lock**, deliberately: each allocates
a 64 MiB working set, and serializing them means the agent never holds
more than one, however many connections send passphrases at once, and a
passphrase guess costs a full derivation process-wide. The price is that
while a derivation runs, every other keyring call waits behind it — a
`Sign` that would have been refused at once (the agent is locked) is
refused a derivation time later, and a legitimate `UNLOCK` queues behind
whatever `UNLOCK`s arrived before it, at most 64 of them. `keyring.go`'s
`Unlock` comment gives the reasoning and the alternative it rejected.

**A `-t` lifetime across a suspend** is enforced on the wall clock, but
not at the deadline itself. The timer that destroys an expired key runs on
Go's monotonic clock, which does not advance while the machine is asleep,
so a key whose deadline passed during a suspend is still in memory (sealed)
when the machine wakes, and stays there until the next list request, or
sign request on an unlocked agent, sweeps it or the late timer fires — up
to the time spent asleep. It cannot sign in that interval: every `Sign`
checks the deadline first. And a
wall clock can be set: whoever can move the system clock back extends a
lifetime, and a step forward ends one early.

ECDSA identities accepted through `-allow-heap-transients` fall outside the
"never at rest on the heap" claim: each signature leaves unwiped copies of the
scalar on the heap, one of them cached until the collector evicts it. See
the "ECDSA identities" section above and `secmem-crypto`'s README.

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
5. **Persistence**: load keys at boot from OpenSSH key files instead of
   requiring `ssh-add`. `secmem-crypto` exports an Ed25519 key in OpenSSH
   format (`MarshalOpenSSHPrivateKey`); the import side — parsing the file
   into a `SecureBuffer` without a heap copy of the seed — is not written yet
   and would be the first piece of this step.
