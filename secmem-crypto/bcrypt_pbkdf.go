// bcrypt_pbkdf.go exposes OpenSSH's bcrypt_pbkdf as a KDF in its own right,
// deriving into a [secmem.SecureBuffer] the way the rest of this module's
// *Into functions do. The algorithm is only reachable inside x/crypto —
// ssh/internal/bcrypt_pbkdf — so a caller who has to reproduce ssh-keygen's
// derivation outside a key file has no way to do it without vendoring the
// package. This module already carries a fork of it that keeps its working
// state in caller-owned memory (internal/bcryptpbkdf), used by the OpenSSH
// passphrase paths; exposing it costs nothing beyond the wrapper below and
// is what [Argon2Into] does for the Argon2 fork.
package secmemcrypto

import (
	"errors"
	"fmt"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/secmem-crypto/internal/bcryptpbkdf"
)

// MaxBcryptPBKDFKeyLen is the largest output bcrypt_pbkdf produces, and so
// the largest out this package will derive into. It is upstream's limit,
// not a choice made here.
const MaxBcryptPBKDFKeyLen = 1024

// BcryptPBKDFInto computes bcrypt_pbkdf(password, salt, rounds) into out,
// writing out.Len() bytes — OpenSSH's password-based KDF, the one
// ssh-keygen runs over a passphrase to get the key and IV that protect a
// private-key file. The output is byte-identical to
// golang.org/x/crypto/ssh/internal/bcrypt_pbkdf.Key for the same inputs.
//
// # Choose Argon2 instead, unless you need this exact function
//
// bcrypt_pbkdf is here for interoperability, not because it is the best
// password KDF available. It is bcrypt in a PBKDF construction: its memory
// footprint is a 4 KiB Blowfish schedule regardless of the cost you ask
// for, so raising rounds buys time-hardness and no memory-hardness at all,
// and a GPU or FPGA attacker is limited by that same small working set.
// [Argon2Into] is memory-hard, is what RFC 9106 recommends, and is what new
// designs in this module should use. Reach for this function when the
// requirement names bcrypt_pbkdf: opening or writing an OpenSSH key file's
// protection yourself, reproducing a derivation ssh-keygen performed, or
// interoperating with a format that specifies it.
//
// # Cost
//
// rounds must be at least 1; ssh-keygen writes 16 by default and its -a
// flag sets it. Cost is linear in rounds, and there is no upper bound here
// — the OpenSSH file format's own cap belongs to the functions that read
// and write those files, not to the primitive. salt must be 1 to 1 MiB, and
// out 1 to [MaxBcryptPBKDFKeyLen] bytes; OpenSSH uses a 16-byte salt and a
// 48-byte output (a 32-byte AES key and a 16-byte IV).
//
// # What touches the heap
//
// Nothing that holds secret state, which is a stronger claim than
// [Argon2Into] can make and the reason this module forked the algorithm.
// The whole working set — the Blowfish key schedule, both SHA-512 outputs,
// bcrypt's hash and the per-block accumulator — lives in one locked
// SecureBuffer allocated for the call and wiped before it returns, and the
// derived bytes are written straight into out's mapping. The one exception
// is a salt longer than 60 bytes, which spills to a heap buffer that the
// derivation wipes; salts are not secret, and OpenSSH's is 16 bytes.
//
// Because that workspace is locked memory, a host whose lock budget cannot
// hold about 4.5 KiB more fails here rather than falling back to the heap.
// That is the module's rule, and at this size it is reachable only on a
// budget already exhausted; see [secmem.EnsureMemlockLimit].
//
// # Locking
//
// out is borrowed for the whole derivation, so writers to it (Destroy,
// Seal, CopyIn) block for that long; other readers do not, and one that
// races the call sees the previous contents until the derived bytes land.
// The call also allocates and borrows its own workspace, taking the two in
// ascending [secmem.SecureBuffer.LockOrder] as every two-buffer operation
// here does. That workspace is created inside the call, so its ordinal is
// above anything the caller already holds and it can never invert the
// caller's nesting. The caller's own nesting is the caller's: if password
// is borrowed from another SecureBuffer around this call, that buffer's
// ordinal must be below out's, which is the module's ascending-LockOrder
// rule. password and salt are only read — neither is wiped nor retained.
//
// Errors, never panics: nil, destroyed or empty out; out larger than
// [MaxBcryptPBKDFKeyLen]; rounds below 1; an empty password; an empty or
// oversized salt; and a workspace that cannot be allocated or locked.
func BcryptPBKDFInto(password, salt []byte, rounds int, out *secmem.SecureBuffer) error {
	if out == nil {
		return errors.New("secmemcrypto: nil output buffer")
	}
	if out.IsDestroyed() {
		return fmt.Errorf("secmemcrypto: bcrypt_pbkdf derive: %w", secmem.ErrDestroyed)
	}
	// The length checks Derive would make are made here too, against
	// out.Len(), so the caller is told which input was wrong before a
	// workspace is allocated for a call that cannot succeed.
	switch size := out.Len(); {
	case size <= 0:
		return errors.New("secmemcrypto: empty output buffer")
	case size > MaxBcryptPBKDFKeyLen:
		return fmt.Errorf("secmemcrypto: bcrypt_pbkdf derive: output buffer is %d bytes, want at most %d", size, MaxBcryptPBKDFKeyLen)
	}
	if rounds < 1 {
		return fmt.Errorf("secmemcrypto: bcrypt_pbkdf derive: rounds must be >= 1, got %d", rounds)
	}

	ws, err := secmem.NewEmptyBuffer(bcryptpbkdf.Size)
	if err != nil {
		return fmt.Errorf("secmemcrypto: bcrypt_pbkdf derive: allocate workspace: %w", err)
	}
	defer func() { _ = ws.Destroy() }()

	err = secmem.ScrubErr(func() error {
		return borrowOrdered(ws, out, func(mem, dst []byte) error {
			defer secmem.SecureWipe(mem)
			return bcryptpbkdf.Derive(dst, password, salt, rounds, bcryptpbkdf.Bind(mem))
		})
	})
	if err != nil {
		return fmt.Errorf("secmemcrypto: bcrypt_pbkdf derive: %w", err)
	}
	return nil
}
