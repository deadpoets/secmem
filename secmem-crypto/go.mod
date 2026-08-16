module github.com/deadpoets/secmem/secmem-crypto

go 1.26

require (
	filippo.io/edwards25519 v1.2.0
	github.com/deadpoets/secmem v0.3.0
	golang.org/x/crypto v0.54.0
)

require golang.org/x/sys v0.47.0 // indirect

// The comment attached to a retract directive is shown to users by `go get`
// and `go list -m -retracted`, so it is kept to one actionable line. Background
// for maintainers, deliberately separated by a blank line so it does NOT become
// part of that rationale: v0.3.0 was tagged from a commit predating this
// module's go.mod floor raise, so it still requires secmem v0.2.0. It is inert
// rather than broken — nothing fails to build — but it does not carry the core
// fixes its version number implies. The tag stays published because
// proxy.golang.org and sum.golang.org are append-only; retracting is the
// supported way to say so, and it reaches the toolchain where a CHANGELOG note
// does not.

// Requires secmem v0.2.0, not v0.3.0 — use v0.3.1 or later.
retract v0.3.0
