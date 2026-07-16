// kdf.go derives keys directly into a [secmem.SecureBuffer], so the derived
// key material is never returned as a plain heap-backed []byte a caller
// could forget to wipe.
//
// Neither derivation is fully off-heap end-to-end — see the caveat on each
// function. Both are hardened at the boundary that matters most in
// practice: the derived key, once these functions return, lives only in
// SecureBuffer, not in a slice the caller has to remember to wipe.
package secmemcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"

	"github.com/deadpoets/secmem"
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
// use [Argon2IDKeyInto] directly.
const (
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024 // KiB — 64 MiB
	Argon2Threads = 4
)

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
// out. memory is in KiB (see [Argon2Memory]'s doc for the default). time and
// threads must be at least 1 (returned as errors, never panics); a
// too-small memory value is raised to the algorithm's minimum by
// golang.org/x/crypto/argon2 itself.
//
// Interoperability: the output equals Argon2id with an empty secret-key
// (K) and empty associated-data (X) — the parameter profile shared by the
// reference implementation's CLI, libsodium, and essentially every
// mainstream binding. golang.org/x/crypto/argon2 does not expose K or X at
// all (an upstream API boundary this library cannot reach around), so
// RFC 9106 configurations that set them cannot be expressed here. The raw
// derived bytes are also not a PHC-encoded string: password-verification
// storage (which embeds parameters alongside the hash) is out of scope
// for this function.
//
// Heap caveat: golang.org/x/crypto/argon2 has no in-place variant — IDKey
// allocates and returns the derived key on the Go heap before this
// function copies it into out and wipes the heap copy. That intermediate
// exists for the duration of one call and is explicitly zeroed immediately
// after the copy. This function deliberately does NOT wrap the derivation
// in [secmem.Scrub]: Argon2's working set (the full memory-cost buffer,
// 64 MiB at the package defaults) and its internal worker goroutines
// conflict with Scrub's allocation-light, single-goroutine constraints.
// Callers who want stack/register hygiene around the call can wrap it in
// [secmem.ScrubErr] themselves.
func Argon2IDKeyInto(password, salt []byte, time, memory uint32, threads uint8, out *secmem.SecureBuffer) error {
	if out == nil {
		return errors.New("secmemcrypto: nil output buffer")
	}
	if out.IsDestroyed() {
		return fmt.Errorf("secmemcrypto: argon2 derive: %w", secmem.ErrDestroyed)
	}
	if time < 1 {
		return fmt.Errorf("secmemcrypto: argon2 derive: time (passes) must be >= 1, got %d", time)
	}
	if threads < 1 {
		return fmt.Errorf("secmemcrypto: argon2 derive: threads (parallelism) must be >= 1, got %d", threads)
	}
	size := out.Len()
	if size <= 0 {
		return errors.New("secmemcrypto: empty output buffer")
	}
	if uint64(size) > math.MaxUint32 {
		return fmt.Errorf("secmemcrypto: output too large: %d", size)
	}

	//nolint:gosec // size is bounds-checked above against math.MaxUint32
	derived := argon2.IDKey(password, salt, time, memory, threads, uint32(size))
	err := out.WithBytesErr(func(dst []byte) error {
		copy(dst, derived)
		return nil
	})
	secmem.SecureWipe(derived)
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
// heap fields it provides no way to wipe; the derivation is therefore
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

	r := hkdf.New(h, secret, salt, info)
	err := secmem.ScrubErr(func() error {
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
