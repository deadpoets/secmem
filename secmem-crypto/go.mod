module github.com/deadpoets/secmem/secmem-crypto

go 1.26

require (
	filippo.io/edwards25519 v1.2.0
	github.com/deadpoets/secmem v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.54.0
)

require golang.org/x/sys v0.47.0 // indirect

// secmem is not yet a tagged release; this repo's secmem-crypto and secmem
// modules are developed together in the same checkout. Remove once secmem
// has a real tagged version to depend on.
replace github.com/deadpoets/secmem => ../
