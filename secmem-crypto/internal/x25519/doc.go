// Package x25519 is the X25519 Montgomery ladder from the Go standard
// library's crypto/ecdh, callable on a scalar the caller keeps in locked
// memory.
//
// # Why a copy
//
// The ladder itself runs entirely on the stack. What puts the private scalar
// on the heap is everything around it: crypto/ecdh.NewPrivateKey copies the
// scalar into a heap PrivateKey, and golang.org/x/crypto/curve25519.X25519 —
// a wrapper over crypto/ecdh — builds one on every call and returns the shared
// secret as a fresh heap slice. Neither is reachable to wipe. Measured by
// secmem-crypto's residue test, one X25519 operation through them left the
// scalar and the shared secret on the heap, where a legacy build never
// erases them and a GOEXPERIMENT=runtimesecret build erases them only at the
// next garbage collection. Calling the ladder directly leaves neither.
//
// # What changed relative to upstream
//
//   - The field package is filippo.io/edwards25519/field instead of
//     crypto/internal/fips140/edwards25519/field, which is not importable.
//     The standard library's copy of that package is vendored from the same
//     module.
//   - ScalarMult is new: a fixed-size-array entry point over the verbatim
//     function, so a caller cannot pass a short slice.
//
// x25519ScalarMult is text-identical to the toolchain's own
// crypto/ecdh/x25519.go; upstream_identity_test.go fails when a Go release
// changes it, and forces a re-port.
//
// The copy is not a distribution of Go and does not use the Go name or the
// Go Authors' names to endorse this project.
package x25519
