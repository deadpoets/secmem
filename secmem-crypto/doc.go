// Package secmemcrypto adapts secmem's hardened memory primitives to the
// standard library's crypto interfaces. Key material is held in a
// [secmem.SecureBuffer] between operations. During an operation it is in
// one of three places. Kept in locked memory and on the stack of a Scrub
// window: Ed25519 signing, X25519, HKDF and HMAC over SHA-2 or SHA-3, the
// plaintext of [OpenInto] and [SealFrom], the parsers' decoded key
// structure, and the KDFs that run in a locked workspace ([Argon2Workspace],
// [Argon2Pool], [BcryptPBKDFInto]). Held in a heap object this module wipes before return: [Argon2Into]'s working set,
// [WithAESGCM]'s key schedule while its callback runs, and the AES schedule
// of [ParsePrivateKeyWithPassphrase]. Or copied through the Go heap by a
// standard-library primitive that has no in-place API, with every copy this
// module can reach wiped before return and every copy it cannot named in the
// documentation (RSA, ECDSA, ML-KEM, and HKDF or HMAC over any other hash,
// which are refused on a legacy build unless opted in). The module README
// classifies every entry point.
//
// Signers: [Ed25519Signer] (RFC 8032, signs in place), [ECDSASigner] and
// [RSASigner] (custody at rest; each Sign re-materialises the key through
// the standard library and wipes what it can reach — see their docs).
// Because the copies it cannot reach are never erased on a build without
// GOEXPERIMENT=runtimesecret, the ECDSA and RSA constructors and the
// parsers refuse those keys there with [ErrHeapTransients] unless the caller
// passes [AllowHeapTransients]. Ed25519 is never refused.
// [AsSSH] adapts any of them to an ssh.Signer without ever offering SHA-1
// ssh-rsa, and [Ed25519Signer.MarshalOpenSSHPrivateKey] exports into a
// buffer.
//
// Derivation into a buffer: [HKDFInto] and [HMACInto] (in place over SHA-2
// and SHA-3; any other hash is gated like RSA and ECDSA), and Argon2 on an
// in-tree fork of golang.org/x/crypto/argon2 that wipes its working state
// ([Argon2Into], [Argon2Workspace], [Argon2Pool]).
//
// AEAD: [OpenInto] and [SealFrom] keep the plaintext in locked memory, and
// [WithAESGCM] lends AES-GCM whose key schedule is wiped when the callback
// returns. Key agreement: [X25519Key]; ML-KEM-768 via [MLKEM768Key], refused
// on a legacy build like RSA and ECDSA because each decapsulation leaves that
// ciphertext's shared key on the heap, and [Encapsulate], which is not.
// Passphrases:
// [GenerateDicewarePassphrase].
//
// Every type states in its own documentation what it does not cover — the
// heap transients the standard library makes that no wipe here can reach.
// The module README and THREAT-MODEL.md in the repository root collect them.
package secmemcrypto
