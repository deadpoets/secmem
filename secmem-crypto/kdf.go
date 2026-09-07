// kdf.go derives keys directly into a [secmem.SecureBuffer], so the derived
// key material is never returned as a plain heap-backed []byte a caller
// could forget to wipe.
//
// Argon2 runs on an in-tree fork of golang.org/x/crypto/argon2 that wipes
// its whole working state (see [Argon2Into]). The HKDF and HMAC paths are
// not fully off-heap end-to-end — see the caveat on each function. All are
// hardened at the boundary that matters most in practice: the derived key,
// once these functions return, lives only in SecureBuffer, not in a slice
// the caller has to remember to wipe.
package secmemcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/secmem-crypto/internal/argon2"
)

// Argon2id default cost parameters: the SECOND RECOMMENDED option of
// RFC 9106 §4 (t=3 passes, m=64 MiB, p=4 lanes), the profile for
// memory-constrained environments. The FIRST recommended option (t=1,
// m=2 GiB) trades passes for a much larger memory floor.
//
// FROZEN: Argon2id is deterministic, so changing these values would
// silently change every consumer's derived keys. They will never be
// altered; if a different profile is ever warranted it will be a new
// symbol, not a new value here. Callers with their own cost policy should
// use [Argon2IDKeyInto] or [Argon2Into] directly.
const (
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024 // KiB — 64 MiB
	Argon2Threads = 4
)

// Argon2Mode selects the Argon2 variant for [Argon2Into]. The zero value is
// Argon2id.
type Argon2Mode uint8

const (
	// Argon2id is the hybrid variant RFC 9106 §4 recommends for password
	// hashing and password-based key derivation: data-independent memory
	// access for the first half of the first pass, data-dependent after.
	// The zero value, and what [Argon2IDKeyInto] uses.
	Argon2id Argon2Mode = iota
	// Argon2i uses data-independent memory access throughout. It is the
	// side-channel-resistant variant and needs more passes than Argon2id
	// for the same resistance to time-memory trade-offs (RFC 9106 §7.3
	// recommends t=3 or more).
	Argon2i
	// Argon2d uses data-dependent memory access throughout: the strongest
	// trade-off resistance and the fastest, but its memory access pattern
	// depends on the password, so it is unsuitable wherever an observer
	// can share a cache with the derivation (RFC 9106 §4 scopes it to
	// cryptocurrencies and backend servers with no side-channel threat).
	// golang.org/x/crypto/argon2 does not expose it; it is exposed here
	// because it is part of the standard and its RFC vector is one of the
	// three that pin this implementation.
	Argon2d
)

// Argon2Params is the full RFC 9106 parameter set for [Argon2Into].
//
// Time (passes), Memory (KiB) and Threads (lanes) are the cost parameters;
// Time and Threads must be at least 1, and a Memory below the algorithm's
// minimum of 8*Threads KiB is raised to it (and otherwise rounded down to a
// multiple of 4*Threads), exactly as golang.org/x/crypto/argon2 does. The
// requested value is what the derivation commits to, so two callers must
// agree on the value before rounding.
//
// Secret is the optional secret value K (a "pepper": a key stored apart
// from the password hashes so that a leaked hash database alone is not
// enough to mount an offline attack) and Data the optional associated
// data X. nil for either means absent, which is the profile shared by the
// reference CLI, libsodium and golang.org/x/crypto (whose public API cannot
// express them at all). Both are hashed into H0 only; the derivation
// otherwise ignores them. A pepper is a long-lived secret and belongs in a
// [secmem.SecureBuffer] between calls; borrow it for the call and pass the
// bytes, observing the lock-ordering note on [Argon2Into].
type Argon2Params struct {
	Mode    Argon2Mode
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
	Secret  []byte // K, optional
	Data    []byte // X, optional
}

// Argon2DeriveInto derives out.Len() bytes from password and salt using
// Argon2id with the RFC 9106 §4 recommended parameters
// [Argon2Time]/[Argon2Memory]/[Argon2Threads]. It is [Argon2IDKeyInto]
// with this package's defaults; use that directly when the defaults don't
// fit your cost policy.
func Argon2DeriveInto(password, salt []byte, out *secmem.SecureBuffer) error {
	return Argon2IDKeyInto(password, salt, Argon2Time, Argon2Memory, Argon2Threads, out)
}

// Argon2IDKeyInto derives out.Len() bytes from password and salt using
// Argon2id with explicit cost parameters, writing the result directly into
// out. memory is in KiB (see [Argon2Memory]'s doc for the default). It is
// [Argon2Into] with Mode Argon2id and no Secret or Data — the profile
// golang.org/x/crypto/argon2.IDKey computes, byte for byte.
func Argon2IDKeyInto(password, salt []byte, time, memory uint32, threads uint8, out *secmem.SecureBuffer) error {
	return Argon2Into(password, salt, Argon2Params{Time: time, Memory: memory, Threads: threads}, out)
}

// Argon2Into derives out.Len() bytes from password and salt with the Argon2
// variant and parameters in p, writing the result directly into out, and
// wipes every byte of the derivation's working state before returning.
//
// # Output
//
// For the same inputs the output is byte-identical to the reference
// implementation and to golang.org/x/crypto/argon2 (whose IDKey and Key are
// Argon2Into with Mode Argon2id/Argon2i and no Secret or Data); the
// RFC 9106 §5 vectors and a differential fuzz target against x/crypto pin
// that. The raw derived bytes are not a PHC-encoded string: password-
// verification storage, which embeds the parameters alongside the hash, is
// out of scope for this function.
//
// # What is wiped, and what is not
//
// Argon2 is a memory-hard function: the point of it is a large working
// state (p.Memory KiB — 64 MiB at this package's defaults) that every
// intermediate value passes through, plus the pre-hash H0 one BLAKE2b step
// from the password. golang.org/x/crypto/argon2 leaves all of it behind on
// the heap and on the stacks of the worker goroutines it spawns, where no
// wrapper can reach it: runtime/secret.Do (and so [secmem.Scrub]) does not
// extend to goroutines the wrapped function creates, and erases heap only
// when the collector gets to it. This function therefore runs an in-tree
// fork (internal/argon2; see its package documentation for the full list
// of changes and the licence) in which:
//
//   - the matrix, every worker's scratch, H0, the H' scratch and the H0
//     input (the one buffer holding the raw password) live in one
//     workspace the parent goroutine owns and wipes with [secmem.SecureWipe]
//     before this function returns — deterministically, not at the
//     collector's convenience;
//   - H0 and H' are computed with stack-only BLAKE2b (x/crypto's one-shot
//     functions, and a forked portable finalisation for the output lengths
//     they do not cover), so no heap digest ever holds the password or the
//     final block (upstream's does, and neither Sum nor Reset clears it);
//   - the parent's hashing phases run under [secmem.Scrub], and so does
//     each worker goroutine — a goroutine can open a window on itself even
//     though its spawner's window does not reach it — so that on a
//     runtime/secret build every worker's stack and registers are erased
//     by the runtime and the worker is not asynchronously preempted while
//     block state is in registers, and on the legacy path each worker's
//     stack band is wiped in place; on amd64 the vector registers are
//     additionally cleared inside every window, pinned to the thread that
//     dirtied them.
//
// What remains, stated so that it can be relied on rather than guessed:
//
//   - During the call the workspace is ordinary Go heap: pageable, part of
//     any core dump or minidump taken while the derivation runs, and not
//     registered with secmem, so [secmem.WipeAllSecrets] and the
//     termination wipe do not cover it. The H0 input in it holds the
//     password and Secret side by side. [Argon2Workspace] runs the same
//     derivation with the working state in a locked, registered
//     SecureBuffer instead, and [Argon2Pool] shares several between
//     callers; they fail at construction when the lock budget is too
//     small rather than falling back to this path, so which posture a
//     program has is decided where it can be seen.
//   - On the legacy Scrub path (Windows, macOS, or any build without
//     GOEXPERIMENT=runtimesecret) an asynchronous preemption can still
//     interrupt a worker and copy its registers into runtime-owned
//     buffers this package cannot reach; the in-place stack wipe covers
//     the copy on the goroutine's own stack, not those. A GC stack shrink
//     during a segment frees a worker stack unwiped for the same reason
//     any Scrub window has that limit.
//   - Scrub reserves stack headroom on entry, which can grow the calling
//     goroutine's stack; a password held in a stack array of the caller
//     is copied by that growth like any other frame. Keep the password in
//     a SecureBuffer or a heap slice you wipe, as the examples do.
//
// Nothing here changes what [secmem.SecureBuffer] does for the output
// itself, which is written in place under WithBytesErr and is never a
// heap []byte.
//
// # Locking and cost
//
// out is borrowed under WithBytesErr — the buffer's shared read lease — for
// the whole derivation, which at password-hashing parameters is tens to
// hundreds of milliseconds depending on the machine. Writers to out
// (Destroy, Seal, CopyIn and the rest) block for that long; other readers
// do not, and a concurrent reader sees the previous contents until the tag
// lands, or a partly written tag for outputs over 64 bytes. Do not read
// out from another goroutine while a derivation into it is in flight. out
// must not be read-only: like every in-place writer in this module the
// borrow cannot detect that state, and the first write faults. If Secret
// or the password is borrowed from another SecureBuffer for the call, that
// is a nested borrow of two buffers and the module's LockOrder discipline
// applies (acquire in ascending [secmem.SecureBuffer.LockOrder]).
//
// The wipe adds one pass over the working set with secmem's cache-flushing
// wipe, about 5.5 ms for 64 MiB on a 2025 desktop where the derivation
// itself takes about 29 ms at the package defaults, so roughly a fifth
// more there; on the slower, memory-bound hardware password hashing is
// usually tuned on the fraction is smaller. The per-segment Scrub windows
// and register clears are microseconds in total. internal/argon2's
// benchmarks measure the halves separately. Callers that wrapped the
// previous Argon2IDKeyInto in [secmem.ScrubErr] on the old doc's advice
// should drop the wrapper: it would put the workspace allocation inside a
// runtime/secret window, which registers 64 MiB for GC-time erasure that
// the explicit wipe already performs.
//
// The heap workspace is allocated and released per call. Measured at the
// package defaults that churn is small (the Go allocator reuses the span),
// and a reused [Argon2Workspace] runs in the same time as this function;
// its reason to exist is where the state lives, not speed.
//
// Errors, never panics, for every input this function can check: nil,
// destroyed or empty out; Time or Threads of 0; an unknown Mode; an input
// longer than the 32-bit length Argon2 commits to; a Memory whose matrix
// does not fit the address space. A Memory the host cannot actually
// allocate is fatal, as it is in x/crypto.
func Argon2Into(password, salt []byte, p Argon2Params, out *secmem.SecureBuffer) error {
	mode, err := validateArgon2(password, salt, p, out)
	if err != nil {
		return err
	}

	// The workspace is allocated outside any Scrub window on purpose: under
	// runtime/secret a 64 MiB allocation inside Do would be tracked for
	// erasure at the next GC, which is redundant with the explicit wipe
	// below and costs sweep time. Derive scrubs the phases that need it.
	ws := argon2.NewWorkspace(p.Memory, p.Threads)
	defer ws.Wipe()
	err = out.WithBytesErr(func(dst []byte) error {
		argon2.Derive(dst, mode, password, salt, p.Secret, p.Data, p.Time, ws)
		return nil
	})
	if err != nil {
		return fmt.Errorf("secmemcrypto: argon2 derive: %w", err)
	}
	return nil
}

// HMACInto computes HMAC(h, key=secret, message=info) into out — a
// single-block keyed PRF, the primitive for domain-separated subkey
// derivation from an already-uniform master key (e.g. "derive the
// checkpoint-signing subkey" or "derive the audit-log subkey" from one root
// secret).
//
// This is NOT [HKDFInto], and the two are not interchangeable. HKDF's
// Extract step is itself HMAC, but with the arguments swapped for its own
// purpose: HKDFSHA256Into(secret, nil, info, out) computes
// HMAC-SHA256(zeros, secret) — secret as HKDF's *message*, an all-zero
// value as the key — not HMAC-SHA256(secret, info). The two calls look
// similar and silently derive completely different bytes from the same
// inputs; use HMACInto when you need a raw keyed PRF and HKDFInto when you
// need RFC 5869's full Extract-then-Expand construction.
//
// out.Len() must equal h().Size() exactly (32 for SHA-256) — a raw HMAC's
// output length is fixed by the hash, unlike HKDF's variable-length Expand.
//
// Heap caveat: crypto/hmac.New allocates its inner/outer hash state from
// secret (verified: 5 allocations, entirely construction — writing the
// digest into out via Sum(dst[:0]) adds none beyond those). That state
// lives in unexported heap fields this package cannot reach to wipe
// directly — the same disclosure [HKDFInto] makes for its own reader state.
// The call is wrapped in [secmem.ScrubErr], which erases it once
// unreachable on GOEXPERIMENT=runtimesecret builds; elsewhere it is
// reclaimed by the GC but not explicitly zeroed.
func HMACInto(h func() hash.Hash, secret, info []byte, out *secmem.SecureBuffer) error {
	if h == nil {
		return errors.New("secmemcrypto: nil hash function")
	}
	if out == nil {
		return errors.New("secmemcrypto: nil output buffer")
	}
	if out.IsDestroyed() {
		return fmt.Errorf("secmemcrypto: hmac derive: %w", secmem.ErrDestroyed)
	}
	want := h().Size()
	if size := out.Len(); size != want {
		return fmt.Errorf("secmemcrypto: hmac derive: output buffer is %d bytes, want exactly %d (the hash's fixed size)", size, want)
	}

	err := secmem.ScrubErr(func() error {
		mac := hmac.New(h, secret)
		mac.Write(info)
		return out.WithBytesErr(func(dst []byte) error {
			mac.Sum(dst[:0])
			return nil
		})
	})
	if err != nil {
		return fmt.Errorf("secmemcrypto: hmac derive: %w", err)
	}
	return nil
}

// HMACSHA256Into is [HMACInto] over SHA-256 — the common case, with the
// hash named in the symbol so a future variant is a new function, not a
// changed default.
func HMACSHA256Into(secret, info []byte, out *secmem.SecureBuffer) error {
	return HMACInto(sha256.New, secret, info, out)
}

// HKDFInto derives out.Len() bytes from secret using HKDF (RFC 5869) over
// the given hash, writing the result directly into out.
//
// salt is optional (nil is valid and equals the RFC's HashLen-zeros
// default) but RECOMMENDED by RFC 5869 §3.1 whenever one is available —
// particularly when secret is a Diffie-Hellman output or other
// not-perfectly-uniform input, where the salted extract step adds real
// strength. Use nil salt only for secrets that are already uniformly
// random (an existing master key). Do not use HKDF to stretch a password:
// that is [Argon2IDKeyInto]'s job.
//
// info is the RFC's context/application-separation parameter: different
// info values yield independent sub-keys from the same secret.
//
// The output length is capped at 255×Hash.Size() bytes (RFC 5869 §2.3 —
// 8160 bytes for SHA-256); larger buffers are rejected up front.
//
// This intentionally builds on golang.org/x/crypto/hkdf rather than the
// stdlib crypto/hkdf: x/crypto's io.Reader model lets the derivation write
// directly into the locked SecureBuffer mapping, where stdlib's Key()
// returns a heap-allocated slice. The reader's internal extract/expand
// state (the pseudorandom key and the last HMAC block) lives in unexported
// heap fields it provides no way to wipe; the derivation — including the
// Extract step that computes the PRK, which hkdf.New performs — is therefore
// wrapped in [secmem.ScrubErr], which on GOEXPERIMENT=runtimesecret builds
// erases those allocations once unreachable. On other builds that state is
// reclaimed by the GC but not explicitly zeroed — a residue window this
// library can narrow but not close from outside the hkdf package.
func HKDFInto(h func() hash.Hash, secret, salt, info []byte, out *secmem.SecureBuffer) error {
	if h == nil {
		return errors.New("secmemcrypto: nil hash function")
	}
	if out == nil {
		return errors.New("secmemcrypto: nil output buffer")
	}
	if out.IsDestroyed() {
		return fmt.Errorf("secmemcrypto: hkdf derive: %w", secmem.ErrDestroyed)
	}
	size := out.Len()
	if size <= 0 {
		return errors.New("secmemcrypto: empty output buffer")
	}
	if maxOut := 255 * h().Size(); size > maxOut {
		return fmt.Errorf("secmemcrypto: hkdf derive: output %d exceeds the RFC 5869 limit of %d bytes (255 x hash size)", size, maxOut)
	}

	err := secmem.ScrubErr(func() error {
		// hkdf.New INSIDE the window, not before it. New performs the Extract
		// step — PRK = HMAC(salt, secret) — and the PRK is key-equivalent for
		// every byte Expand goes on to produce. Constructing the reader outside
		// the scrub left that computation's stack residue and the PRK allocation
		// outside the very window this function's doc says covers the
		// derivation, which is the one value it most needed to cover.
		r := hkdf.New(h, secret, salt, info)
		return out.WithBytesErr(func(dst []byte) error {
			_, err := io.ReadFull(r, dst)
			return err
		})
	})
	if err != nil {
		return fmt.Errorf("secmemcrypto: hkdf derive: %w", err)
	}
	return nil
}

// HKDFSHA256Into is [HKDFInto] over SHA-256 — the common case, with the
// hash named in the symbol so a future variant is a new function, not a
// changed default.
func HKDFSHA256Into(secret, salt, info []byte, out *secmem.SecureBuffer) error {
	return HKDFInto(sha256.New, secret, salt, info, out)
}
