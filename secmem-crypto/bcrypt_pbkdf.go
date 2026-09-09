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
// stated once in the fork and only named here.
const MaxBcryptPBKDFKeyLen = bcryptpbkdf.MaxKeyLen

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
// hold it fails here rather than falling back to the heap. The workspace is
// a little over 4 KiB, and the budget is charged in whole pages (the
// formula in ADOPTION.md §4): two 4 KiB pages per call in flight, or one
// larger page where the kernel uses them, on top of out itself. That is the
// module's rule, and at this size it is reachable only on a budget already
// exhausted; see [secmem.EnsureMemlockLimit].
//
// # Locking
//
// out is borrowed under WithBytesErr — the buffer's shared read lease — for
// the whole derivation, so writers to it (Destroy, Seal, CopyIn) block for
// that long. Other readers do not block, and the lease does not make the
// write atomic: the derived bytes land block by block, interleaved across
// out, so a reader that races the call can see a mixture of old and new
// bytes. Do not read out, or derive into it twice, from another goroutine
// while a call is in flight. out must not be read-only: like every in-place
// writer in this module the borrow cannot detect that state, and the first
// write faults.
//
// The workspace is created inside the call and borrowed after out, so its
// [secmem.SecureBuffer.LockOrder] ordinal is above out's and that nesting
// is ascending by construction. What the caller nests around the call is
// the caller's: if password or salt is borrowed from another SecureBuffer,
// that buffer must have been created before out — the module's
// ascending-LockOrder rule, which the example observes by allocating the
// passphrase first. password and salt are only read — neither is wiped nor
// retained.
//
// Errors, never panics, the read-only case above excepted: nil, destroyed
// or sealed out; out larger than [MaxBcryptPBKDFKeyLen]; rounds below 1; an
// empty password; an empty or oversized salt; and a workspace that cannot
// be allocated or locked. The input bounds are checked before the workspace
// is allocated, by the same function the fork checks them with, so a
// rejected call costs nothing and leaves out untouched.
func BcryptPBKDFInto(password, salt []byte, rounds int, out *secmem.SecureBuffer) error {
	if out == nil {
		return errors.New("secmemcrypto: bcrypt_pbkdf derive: nil output buffer")
	}
	if out.IsDestroyed() {
		return fmt.Errorf("secmemcrypto: bcrypt_pbkdf derive: %w", secmem.ErrDestroyed)
	}
	if err := bcryptpbkdf.Check(out.Len(), password, salt, rounds); err != nil {
		return fmt.Errorf("secmemcrypto: bcrypt_pbkdf derive: %w", err)
	}
	err := secmem.ScrubErr(func() error {
		return out.WithBytesErr(func(dst []byte) error {
			return withScratch(bcryptpbkdf.Size, func(mem []byte) error {
				return bcryptpbkdf.Derive(dst, password, salt, rounds, bcryptpbkdf.Bind(mem))
			})
		})
	})
	if err != nil {
		return fmt.Errorf("secmemcrypto: bcrypt_pbkdf derive: %w", err)
	}
	return nil
}
