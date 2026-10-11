# staticcheck, built from a pinned module

CI builds staticcheck from this module instead of running the
`dominikh/staticcheck-action`, which can only `go install` a released
version as published.

Staticcheck 2026.2.1 cannot read the export data that Go 1.27.2 writes
(version 5, [dominikh/go-tools#1832](https://github.com/dominikh/go-tools/issues/1832)).
The upstream fix is a bump of `golang.org/x/tools` to v0.51.0, and it is
not released yet. This module builds the released 2026.2.1 (`v0.8.1`)
against that x/tools, so the analysis is the released one and only the
export-data reader is newer. `go.sum` pins every byte of it.

When a staticcheck release with the fix ships, Dependabot raises it here.
Then this module can stay, with the explicit `golang.org/x/tools` line
dropped, or CI can go back to the action.
