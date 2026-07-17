# Security policy

secmem is a security-focused library — vulnerability reports get priority
handling, and the process is designed to keep a report private until a fix
is ready.

## Audit status

secmem has **not** had an independent third-party security audit. What has
been verified — per-claim tests, kernel-matrix runs, out-of-process
extraction proofs — is documented in [TESTING.md](TESTING.md);
self-verification is not an audit.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting instead:

1. Go to the [Security tab](https://github.com/deadpoets/secmem/security).
2. Click **"Report a vulnerability"**.
3. Describe the issue: affected version(s), platform (this matters — see
   [the guarantee matrix](README.md#the-platform-guarantee-matrix), a real
   flaw might only affect one platform/kernel path), and reproduction steps
   or a PoC if you have one.

This opens a private advisory visible only to you and the maintainer, with
its own discussion thread, and supports coordinated disclosure and CVE
assignment through GitHub Security Advisories once a fix lands.

## What counts as a security issue here

In scope:

- A protection the [guarantee matrix](README.md#the-platform-guarantee-matrix)
  claims is provided but is not — e.g. a secret reachable through
  `/proc/self/mem` when `memfd_secret` is reported live, a wipe the compiler
  can elide, a guard page that doesn't fault.
- A case where `Capabilities`/`Probe` report a protection as active when it
  is not, or where `WithInsecureFallback()` is *not* required but a secret
  ends up on the unprotected heap anyway.
- Anything in [THREAT-MODEL.md](THREAT-MODEL.md)'s "what secmem does NOT
  protect against" section is explicitly **out of scope** — those are
  disclosed, accepted limits, not bugs (cold-boot/full-RAM capture, a
  privileged reader on platforms without `memfd_secret`, code already
  executing inside your process, etc). If you think one of those framings is
  wrong, that's a design discussion — open a public issue for it, not a
  security report.

## Response

Expect an initial response within a few days. Fix timeline depends on
severity and whether a platform-specific workaround exists in the meantime;
you'll be kept in the loop through the private advisory thread.
