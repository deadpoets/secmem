package argon2

// ClearVectorRegs zeroes the vector register file on amd64 (a no-op
// elsewhere) — the helper this package runs at the end of each of its Scrub
// windows, exposed so secmem-crypto's OpenSSH passphrase path can run it
// after its SHA-512 and AES steps. The caller must be pinned to its OS
// thread (runtime.LockOSThread) for the clear to land on the thread that
// holds the residue.
//
// Temporary: the core secmem.Scrub clears the vector registers itself from
// the release that follows v0.4.0. When this module's floor reaches it,
// this function and the fork's own copy of the clear both go.
func ClearVectorRegs() { clearVectorRegs() }
