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

secmem is BDFL-maintained. **Contributed PRs require an approving review from
[@deadpoets](https://github.com/deadpoets)** — enforced by `CODEOWNERS` plus
branch protection, not by convention.

Nothing reaches `main` except through a PR that passes every required check,
on a branch that also requires signed commits and linear history. The required
set covers linux/macOS/Windows, arm64, 386, `GOEXPERIMENT=runtimesecret`, the
no-heap-escape gates, the key residue scans, cross-compilation, the examples,
the API-compatibility report and secret scanning. The list itself lives in the
repository's branch protection settings and is not repeated here, where a
count went stale; not every job in `ci.yml` is on it.

This is a single-maintainer project, and GitHub does not permit self-approval,
so the maintainer's own PRs are gated by that matrix rather than by a second
reviewer. Stated plainly, because claiming a review gate that cannot exist is
exactly the kind of unverifiable assurance this project refuses to make about
its own memory guarantees.

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
   The signature requirement is enforced by branch protection on `main`,
   and GitHub's own squash-merge signs the commit it lands there. An
   unsigned PR branch therefore does not block merging; a signed one makes
   the history easier to audit.
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
  is a minimal, auditable surface. The core depends on `golang.org/x/sys`
  only; `secmem-crypto` adds `filippo.io/edwards25519`, `golang.org/x/crypto`
  and `golang.org/x/sys`; `secmem-lint` depends on `golang.org/x/tools` only.

## Maintaining the forks

`secmem-crypto` carries copies of other people's code: x/crypto's `argon2`,
`blake2b`, `bcrypt_pbkdf` and `blowfish`, the standard library's X25519
ladder, and the EFF wordlist. Each exists because the upstream leaves key
material in memory that nothing exported can reach — the reasons are in each
fork's `doc.go`. A copy means the upstream's later fixes are not ours
automatically, so this is the standing procedure for noticing.

**What watches what.**

| Question | Answered by | When |
|---|---|---|
| Does the manifest still match the tree and its own prose? | `secmem-crypto/forks_test.go` | every CI run, offline |
| Are the verbatim parts still identical to the x/crypto the module resolves? | each fork's `upstream_identity_test.go` | every CI run, and on every Dependabot bump |
| Has upstream changed the copied packages since the fork point? | `internal/forkcheck`, via the **Fork Watch** workflow | weekly, and on demand |
| Is there an advisory against the forked code at its fork point? | the same workflow | weekly |
| Would the next Go release break a stdlib copy or a reflection layout? | Fork Watch's canary job | weekly, against the newest toolchain including release candidates |

`forks.json` is the manifest all of that reads. Run the checker by hand with:

```sh
cd secmem-crypto && go run ./internal/forkcheck        # add -offline to skip the network
```

It diffs upstream **against itself** between the fork point and upstream's
newest release — never against our copy, because a fork-versus-upstream diff
is permanently large (the modifications are the point) and so goes unread.
Upstream against itself is empty in the steady state, which is why a
non-empty result is worth your attention.

**Why Fork Watch reports instead of failing.** An upstream release is an
event outside this repository; a required check for it would block unrelated
work for a reason no pull request can fix — the same reason
`.github/scripts/apicompat.sh` is report-only. It opens or updates one
tracking issue. The deterministic checks above it stay inside `ci.yml`, where
they are required.

**When upstream has moved.** The diff in the report is the input to one
decision, and the decision is yours, not the tool's:

1. If the change is to comments, tests or documentation, nothing needs
   porting: advance the manifest (`go run ./internal/forkcheck -update`
   writes `unchanged_through` for you) and say so on the issue.
2. If it touches the algorithm, port it by hand. The fork's differential
   tests against upstream (`TestMatchesUpstream`,
   `TestBlowfish_MatchesUpstream`) and its RFC vectors are what tell you the
   port is faithful; run them before and after. Then move `fork_point` in
   `forks.json` **and** the prose that states it — the manifest lists those
   files, and `forks_test.go` fails while any of them disagrees.
3. If it is a fix for a vulnerability, treat it as a security fix in this
   module, not as housekeeping: [SECURITY.md](SECURITY.md) applies, and the
   release that carries it says so.

**Never** resolve a drift report by moving `fork_point` without porting the
change. The pair of fields means "taken from X, and upstream has not changed
through Y"; editing Y to silence a job turns the one record of what this
module actually contains into a lie.

**What none of this covers.** `govulncheck` reads a module's dependency
graph, and a fork is not in one: an advisory against x/crypto's `argon2`
would never be reported against this module by the `vuln` job. That is what
Fork Watch's advisory query is for, and it is the single best argument for
keeping the fork list as short as it is.

## Reporting a security issue

Do **not** open a public issue for a vulnerability. See
[SECURITY.md](SECURITY.md).

## Code of conduct

Participation in this project is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).
