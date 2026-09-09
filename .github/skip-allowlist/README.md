# Skip allowlists

One file per CI lane. Each names the tests that are EXPECTED to skip on that
lane's runner, one per line, as `<import path> <test name>`; a name ending in
`/...` covers every subtest under it. `#` starts a comment.

`internal/skipaudit` fails a job on any skip that is not listed here. That is
the point: a skip is a proof that stopped running, and the decision whether
that is the environment or the claim belongs in a reviewed diff to these
files, not in a log nobody reads. Every entry carries the reason it is here.
An entry that stops skipping is reported as a note by the audit; remove it.

| File | Lane |
|---|---|
| `linux.txt` | `test` (ubuntu-latest), `test-arm64-linux`, `test-runtimesecret` — unprivileged |
| `linux-root.txt` | `test-root-linux` — the isolation proofs run as root; nothing may skip |
| `linux-386.txt` | `test-386-linux` — no `memfd_secret` on 32-bit |
| `darwin.txt` | `test` (macos-latest) |
| `windows.txt` | `test` (windows-latest) |
