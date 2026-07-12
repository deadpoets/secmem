## What and why

<!-- The change, and the problem it solves. Link the issue if one exists. -->

## Checklist

- [ ] `make all` (fmt, vet, test) passes locally
- [ ] `make lint` (golangci-lint, staticcheck) is clean
- [ ] Commits are signed (`git log --show-signature`)
- [ ] If this adds or changes a guarantee: a test actually exercises it (not
      just documents it — see [CONTRIBUTING.md](../CONTRIBUTING.md#what-a-good-change-looks-like-here))
- [ ] If this adds platform/kernel coverage: [`KERNELS.md`](../KERNELS.md) is
      updated with a **real** hardware/VM run, not a cross-compile assumption
- [ ] Docs updated if behavior, guarantees, or the platform matrix changed
      (README.md / THREAT-MODEL.md / ENVIRONMENTS.md as applicable)
