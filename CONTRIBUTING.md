# Contributing to secmem

Thanks for considering it. This document exists so a contribution has the
best odds of merging on the first pass — read it before opening a PR, not
after CI fails.

## Before you write code

For anything beyond a small, obvious fix (typo, off-by-one, a missing test),
open an issue first describing what you want to change and why. secmem's bar
is correctness and honesty about guarantees, not feature count — a design
discussion up front saves a rewritten PR later.

## Governance

secmem is BDFL-maintained. **Every PR requires a review from
[@deadpoets](https://github.com/deadpoets)** — this is enforced by branch
protection, not just convention, and applies to the maintainer too: nothing
lands on `main` without going through a PR and passing CI.

## Workflow

1. Fork, then branch off `main`: `feat/…`, `fix/…`, or `docs/…` are the usual
   prefixes.
2. Make the change. Keep the PR scoped to one logical change — a bug fix
   doesn't need a drive-by refactor riding along.
3. Run the full local check before pushing:
   ```sh
   make all    # fmt + vet + test
   make lint   # golangci-lint + staticcheck
   make vuln   # govulncheck
   ```
   CI runs the same checks (plus the cross-platform matrix and a secret
   scan) on every PR — running them locally first is faster than the
   round-trip.
4. **Sign your commits.** `main` requires verified signatures. GPG or SSH
   signing both work:
   ```sh
   git config commit.gpgsign true
   git config gpg.format ssh                        # or leave unset for GPG
   git config user.signingkey ~/.ssh/your_key.pub    # SSH signing key
   ```
   GitHub's own squash-merge signs the final commit on `main` regardless, so
   an unsigned PR branch doesn't block merging — but CI does check signatures
   on the commits you push, and a clean signed history makes review easier.
5. Open the PR against `main`. Fill in the template — it's short on purpose.
6. Address review feedback as new commits (don't force-push mid-review;
   squash happens automatically at merge).

## What a good change looks like here

secmem's honesty contract (see [README.md](README.md#honesty-first)) extends
to contributions:

- **A guarantee you add must be backed by a test that actually exercises
  it** — a claim in a doc comment with no corresponding test doesn't merge.
  See [`guard_canary_test.go`](guard_canary_test.go) and
  [`memfd_isolation_linux_test.go`](memfd_isolation_linux_test.go) for the
  pattern: don't assert the mechanism worked, prove it (fault the guard page,
  read `/proc/self/mem`, etc).
- **A platform limitation gets reported, not silently skipped.** If a
  protection isn't available on some platform/kernel, that shows up in
  `Capabilities`/`Probe`, not as a quiet no-op.
- **New kernel/OS coverage goes in [`KERNELS.md`](KERNELS.md)** — only real
  hardware or a real VM, never cross-compiled-and-assumed.
- No new dependencies without discussion first — the whole point of `secmem`
  is a minimal, auditable surface (`golang.org/x/sys` only, today).

## Reporting a security issue

Do **not** open a public issue for a vulnerability. See
[SECURITY.md](SECURITY.md).

## Code of conduct

Participation in this project is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).
