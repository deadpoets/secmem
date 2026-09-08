// Package bcryptpbkdf is a fork of golang.org/x/crypto/ssh/internal/bcrypt_pbkdf
// (v0.56.0), the KDF that protects OpenSSH private-key files, together with
// the golang.org/x/crypto/blowfish it is built on, changed so that every
// byte of its working state is in a caller-owned [Workspace] that the caller
// wipes.
//
// # Why a fork
//
// Upstream's Key derives a key from a passphrase and leaves behind, on the
// heap and unwiped: a streaming SHA-512 digest that was written the raw
// passphrase, and its 64-byte hash; one freshly allocated Blowfish Cipher —
// a 4 KiB key schedule derived from that hash — for every bcrypt step,
// which at OpenSSH's default of 16 rounds and a 48-byte key+IV is 32 of
// them, about 133 KB; and the derived key itself, which the caller slices
// into an AES key and IV and cannot wipe because the slice is upstream's.
// None of it is reachable from outside x/crypto: bcrypt_pbkdf is an
// internal package, and blowfish exposes no way to re-key a Cipher in
// place, so no wrapper can do better than run it and hope the collector
// gets there first.
//
// # What changed relative to upstream
//
//   - Every piece of working state lives in a [Workspace] the caller owns
//     — the Blowfish schedule, both SHA-512 outputs, bcrypt's 32-byte hash
//     and the per-block accumulator, and a reserve for salt || counter —
//     so it can sit in a SecureBuffer ([Bind]) or a stack frame and be
//     wiped deterministically ([Workspace.Wipe]). Nothing is allocated for
//     a salt that fits the reserve; a longer one spills to a heap buffer
//     that Derive wipes before returning.
//   - The SHA-512 steps are one-shots (sha512.Sum512) instead of a heap
//     digest that is Reset and reused, so no digest object retains the
//     passphrase. Upstream wrote salt then counter in two calls; the two
//     are made contiguous in the reserve for the one-shot.
//   - NewSaltedCipher, which allocated a Cipher per bcrypt step, is
//     replaced by initSaltedCipher, which resets the Workspace's Cipher to
//     the π tables and re-keys it in place.
//   - The output is written into a caller-supplied slice ([Derive]), so it
//     can be a stack array inside a Scrub window or a SecureBuffer's
//     mapping. Upstream's interleave-then-truncate is reproduced without
//     the intermediate buffer; output is byte-identical.
//   - The decryption direction of Blowfish and its KeySizeError are
//     dropped as unused.
//
// The algorithm is unchanged: encryptBlock, ExpandKey, expandKeyWithSalt,
// getNextWord, initCipher and Encrypt are verbatim, const.go is
// byte-identical below its package clause, and upstream_identity_test.go
// checks all of that against the x/crypto the module resolves. Output is
// pinned by OpenBSD's reference vectors (the same ones upstream carries),
// by a differential test of the Blowfish schedule against
// golang.org/x/crypto/blowfish, and end to end in secmem-crypto: keys
// ssh-keygen and x/crypto/ssh encrypted open here, and keys encrypted here
// open with x/crypto/ssh and ssh-keygen.
//
// # What this does not do
//
// Blowfish is a table-driven cipher and its S-box lookups are keyed; that is
// bcrypt's design and upstream's implementation, and this fork does not
// change it. Vector registers are not touched here: SHA-512's assembly
// leaves message-block state in them, and the [secmem.ScrubErr] window the
// caller runs this inside clears them on the way out.
//
// # Maintenance
//
// Dependabot bumps golang.org/x/crypto for the rest of the module; this
// package does not follow automatically. bcrypt_pbkdf's output is fixed by
// OpenBSD's reference implementation and pinned here by its vectors, so a
// bump only matters if upstream gains a fix worth porting.
// upstream_identity_test.go fails the bump when the verbatim functions or
// the constant tables change; port by hand from a diff of upstream's
// ssh/internal/bcrypt_pbkdf and blowfish directories between the pinned
// version and the new one, then update the pinned version everywhere it is
// stated (grep the module for v0.56.0: the file headers here, NOTICE and
// CHANGELOG).
//
// # Licence
//
// The upstream code is Copyright 2010 and 2014 The Go Authors, under the
// BSD-3-Clause licence in LICENSE (with the PATENTS grant) in this
// directory. Those files are copied unmodified from golang.org/x/crypto and
// apply to this package; the secmem-crypto NOTICE file records the fork.
package bcryptpbkdf
