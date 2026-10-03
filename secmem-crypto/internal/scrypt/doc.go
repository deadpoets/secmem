// Package scrypt is a fork of golang.org/x/crypto/scrypt (v0.57.0) reduced
// to scrypt's memory-hard step and changed so that every byte of its
// working state is in a region the caller owns and wipes.
//
// # Why a fork
//
// Upstream's Key derives a key and returns it, leaving behind, on the heap
// and unwiped: V, the array scrypt exists to fill — 128·r·N bytes, 16 MiB at
// the cost openssl pkcs8 -scrypt writes — whose first block is the first
// PBKDF2's output and whose every block is derived from the passphrase; the
// X and Y blocks it mixes; B, that PBKDF2 output itself; the HMAC states of
// both PBKDF2 calls; and the derived key. Salsa20/8's 64-byte chaining block
// is a stack local of smix. Key takes no workspace and returns a fresh
// slice, so nothing outside the package can reach any of it.
//
// # What changed relative to upstream
//
//   - V, X and Y are views of a region the caller supplies ([Mix]) instead of
//     two heap slices, so they can be a SecureBuffer's mapping: locked for
//     the derivation and wiped by the caller's one wipe of the region.
//   - smix's tmp, the Salsa20/8 chaining block, is a view of the same region
//     instead of a stack local, and is passed in. That is smix's only change,
//     and upstream_identity_test.go checks that it is.
//   - Key is gone. Its two PBKDF2 calls are the caller's — secmem-crypto runs
//     them through its own in-place PBKDF2, in the same region — and what is
//     left is the loop between them, RFC 7914 §6 step 2, as [Mix]: one
//     scryptROMix per block of B, in sequence on the calling goroutine, as
//     upstream runs them.
//   - Key's parameter checks became [Mix]'s preconditions, which panic: the
//     caller is a parser that has already turned a file's parameters into
//     errors, and bounded them, before it allocates the region.
//
// The algorithm is unchanged: blockCopy, blockXOR, salsaXOR, blockMix and
// integer are verbatim, and upstream_identity_test.go checks that against
// the x/crypto the module resolves. Output is pinned by RFC 7914's vectors
// for the Salsa20/8 core (§8), scryptBlockMix (§9), scryptROMix (§10) and
// scrypt itself (§12), and by a differential test against
// golang.org/x/crypto/scrypt; secmem-crypto repeats the last two through its
// own PBKDF2, and opens files a real openssl pkcs8 -scrypt wrote.
//
// # What this does not do
//
// It does not wipe. On return the region holds V, the last X and Y and the
// chaining block; the caller wipes it, with B. salsaXOR's sixteen working
// words are locals — registers, and whatever the compiler spills to the
// stack — and scrypt reads V at indices taken from the block being mixed,
// which is the algorithm's design and upstream's implementation. The
// [secmem.ScrubErr] window the caller runs this inside erases the stack
// band and the registers on the way out; this package opens no window of
// its own and starts no goroutine.
//
// # Maintenance
//
// Dependabot bumps golang.org/x/crypto for the rest of the module; this
// package does not follow automatically. scrypt's output is fixed by
// RFC 7914 and pinned here by its vectors, so a bump only matters if
// upstream gains a fix worth porting. upstream_identity_test.go fails the
// bump when the verbatim functions or smix change, and the weekly Fork Watch
// workflow reports an upstream release that moved the package even when no
// bump arrives: `go run ./internal/forkcheck` prints the diff between the
// fork point and upstream's newest release, which is the input to the port.
// Afterwards update forks.json's fork_point and the prose that states it —
// forks.json lists those files and forks_test.go fails while any of them
// disagrees. CONTRIBUTING.md, "Maintaining the forks", has the whole
// procedure.
//
// # Licence
//
// The upstream code is Copyright 2012 The Go Authors, under the BSD-3-Clause
// licence in LICENSE (with the PATENTS grant) in this directory. Those files
// are copied unmodified from golang.org/x/crypto and apply to this package;
// the secmem-crypto NOTICE file records the fork.
package scrypt
