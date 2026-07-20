module github.com/deadpoets/secmem/examples

go 1.26

require (
	github.com/deadpoets/secmem v0.2.0
	github.com/deadpoets/secmem/secmem-crypto v0.1.0
	golang.org/x/crypto v0.54.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// Examples always build against the checkout they live in.
replace github.com/deadpoets/secmem => ../

replace github.com/deadpoets/secmem/secmem-crypto => ../secmem-crypto
