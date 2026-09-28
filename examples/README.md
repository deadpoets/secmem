# secmem examples

Runnable programs, smallest first. Each is a separate `main` package in one
`examples` module that always builds against the checkout it lives in.

| example | what it shows | secmem surface exercised |
|---|---|---|
| [`password-login/`](password-login/) | register/login flow where the plaintext password provably stops existing after use, and a refused login says the same thing — in words and in how long it takes — whether the account exists or not | `SecureWipe`, `NewEmptyBuffer`, `Argon2DeriveInto`, `ConstantTimeEqual` |
| [`hardened-ssh-agent/`](hardened-ssh-agent/) | **a working SSH agent** — keys off-heap, sealed `PROT_NONE` while idle, kernel-invisible where the platform allows; interops with real `ssh-add`/`ssh`; bounds what a hostile local client can cost it (per-message deadline, connection cap) | nearly all of it: `SecureBuffer`, `Seal`/`Unseal` (dormant-key pattern), `HardenProcess`, `DisableCoreDumps` (via harden), `EnsureMemlockLimit`, `InstallTerminationWipe`, `Probe().Warnings()`, `SecureWipe`, `redact.NewHandler`, `secmem-crypto` signers + `AsSSH` + `Argon2DeriveInto` |

Start with `password-login` to learn the borrowing and wiping idioms in
about 300 lines; read `hardened-ssh-agent` to see them carry a real service.
The agent is deliberately a *minimal usable core* with a forking guide —
if you want a hardened agent with constraints, prompts, or FIDO2 keys, it
is designed to be the thing you fork.

```console
cd examples
go test ./...          # includes the agent's interop and availability suites
go run ./hardened-ssh-agent
```

The godoc `Example*` functions in the library packages remain the quickest
API reference; these programs show the idioms composed under real I/O,
concurrency, and shutdown paths.
