// Package argon2 is a fork of golang.org/x/crypto/argon2 (v0.56.0) that
// wipes every byte of its internal working state before returning. It
// also carries the portable compression function and one-shot
// finalisation of golang.org/x/crypto/blake2b at the same version.
//
// # Why a fork
//
// Upstream argon2 derives a key and returns it, leaving behind: the 72-byte
// H0 pre-hash (one BLAKE2b step from the password); the whole memory-cost
// matrix B (64 MiB at the RFC 9106 second recommended profile); a 1 KiB
// scratch block in extractKey; roughly 3 KiB of per-goroutine scratch on the
// stack of every worker goroutine processBlocks spawns; the 1 KiB blamka
// temporary on those same stacks; and — the one nothing outside the blake2b
// package can reach — the heap BLAKE2b digest that initHash writes the raw
// password into, whose block buffer neither Sum nor Reset clears.
//
// None of that is reachable from outside the package. runtime/secret.Do (and
// therefore secmem.Scrub) erases the calling goroutine's stack and registers
// and, on Linux, heap allocations once the GC frees them — but its own
// documentation says protection "does not extend to any new goroutines made
// by f", and the matrix is only erased at the collector's convenience, not
// before the call returns. The wipe has to be inside the algorithm.
//
// # What changed relative to upstream
//
//   - Every piece of working state lives in a [Workspace] the caller owns:
//     the matrix, one scratch struct per lane (addresses / in / blamka's
//     tmp), H0, the H' scratch, and the H0 input buffer. No block is a
//     stack local of a worker goroutine any more, and the parent wipes
//     everything deterministically after wg.Wait().
//   - Each worker goroutine runs its segment inside a secmem.Scrub window
//     of its own (runtime/secret does not reach spawned goroutines from
//     outside, but a goroutine may open a window on itself), so the
//     runtime erases its stack and registers on a runtimesecret build and
//     refuses to asynchronously preempt it mid-block, and the legacy path
//     wipes the stack band in place. The parent-goroutine phases (H0, the
//     first two blocks per lane, the final extraction) run in windows too.
//   - The output is written into a caller-supplied slice ([Derive]) instead
//     of a freshly allocated one, so it can be a SecureBuffer's mapping.
//   - H0 and H' are stack-only: blake2b.Sum512/Sum384/Sum256 where x/crypto
//     has a one-shot function, and a forked portable finalisation
//     (blake2b_generic.go) for the other lengths, instead of blake2b.New,
//     so no heap digest ever holds the password or the final block.
//   - On amd64 the vector registers are cleared inside every window (the
//     SSE blamka and BLAKE2b's AVX2 code leave block state in XMM/YMM),
//     with the goroutine pinned to its OS thread so the clear lands where
//     the residue is.
//   - The secret-key (K) and associated-data (X) inputs deriveKey already
//     took are exposed, so RFC 9106 §5 vectors run as-is.
//
// The block-processing core (blamka, indexAlpha, phi, the segment schedule)
// is unchanged; blamka_amd64.s is byte-identical to upstream and
// upstream_identity_test.go checks that, and the verbatim functions,
// against the x/crypto the module resolves. Output is byte-for-byte
// identical to upstream for the same inputs — argon2_test.go checks that
// directly against golang.org/x/crypto/argon2 as well as against the RFC
// vectors.
//
// # Maintenance
//
// Dependabot bumps golang.org/x/crypto for the rest of the module; this
// package does not follow automatically. The algorithm cannot change
// (its output is fixed by RFC 9106 and pinned here by the RFC vectors and
// the differential tests against upstream), so a bump only matters if
// upstream argon2 or blake2b gains a fix worth porting.
// upstream_identity_test.go fails the bump when upstream's assembly or
// verbatim functions change; port by hand from a diff of upstream's argon2
// and blake2b directories between the pinned version and the new one, then
// update the pinned version everywhere it is stated (grep the module for
// v0.56.0: the file headers here, NOTICE and CHANGELOG).
//
// # Licence
//
// The upstream code is Copyright 2017 The Go Authors, under the BSD-3-Clause
// licence in LICENSE (with the PATENTS grant) in this directory. Those files
// are copied unmodified from golang.org/x/crypto and apply to this package;
// the secmem-crypto NOTICE file records the fork.
package argon2
