module github.com/deadpoets/secmem/examples

go 1.26.0

toolchain go1.27.4

require (
	github.com/deadpoets/secmem v0.8.1
	github.com/deadpoets/secmem/secmem-crypto v0.1.0
	golang.org/x/crypto v0.59.0
	golang.org/x/term v0.48.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)

// Examples always build against the checkout they live in.
replace github.com/deadpoets/secmem => ../

replace github.com/deadpoets/secmem/secmem-crypto => ../secmem-crypto
