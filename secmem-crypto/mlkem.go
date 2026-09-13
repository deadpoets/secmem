// mlkem.go provides MLKEM768Key, a post-quantum ML-KEM-768 (FIPS 203)
// decapsulation key whose seed lives in a SecureBuffer.
package secmemcrypto

import (
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"github.com/deadpoets/secmem"
)

// MLKEM768Key is an ML-KEM-768 (FIPS 203, the NIST post-quantum key
// encapsulation mechanism) decapsulation key whose 64-byte seed is held in
// a [secmem.SecureBuffer] between operations. The seed is the compact,
// regenerable secret; Decapsulate expands it into the full decapsulation
// key on demand and wipes that expansion before returning.
//
// Post-quantum posture: this hardens the at-rest custody of a KEM secret.
// The urgent PQ threat — "harvest now, decrypt later" against recorded
// traffic — is addressed at the transport layer (Go's crypto/tls already
// defaults to the X25519MLKEM768 hybrid key exchange); this type is for
// applications that hold a long-lived ML-KEM decapsulation secret and want
// it off the garbage-collected heap at rest.
//
// # What transits the heap, and for how long
//
// crypto/mlkem has no in-place API: every expansion allocates a heap
// DecapsulationKey768 which, in go1.26, stores the seed halves d and z
// verbatim ([32]byte each) and the secret polynomial vector s (about
// 1.5 KB) next to the public parts. That object is wiped by reflection
// through its unexported fields (mlkemwipe.go) at the end of every
// expansion — construction, and each Decapsulate — with a tripwire test
// pinning the layout and a call that fails closed, returning an error,
// when the layout is not the one it expects. So the seed and s are on the
// heap only for the duration of the call, and are zero afterwards.
//
// The rest of crypto/mlkem's working state — the SHA3 and SHAKE digests
// that absorb d and z, σ, and the intermediate polynomials — does not
// escape to the heap in go1.26: the compiler keeps it on the stack of the
// call, inside the [secmem.ScrubErr] window, which wipes it. The residue test
// searches a process that decapsulates for d, z, s, σ and the SHAKE state
// that absorbed z, and finds none of them outside locked memory on either
// kind of build.
//
// One value does escape: the 32-byte message m that decapsulation recovers,
// returned as a fresh heap slice by an unexported function nothing here can
// reach. With the public key's hash it gives that ciphertext's shared key —
// not the decapsulation key. On a GOEXPERIMENT=runtimesecret build the
// runtime erases it at the first garbage collection after the call; on any
// other build it is reclaimed by the collector, not zeroed, and the residue
// test finds it after collections and after Destroy. Treat each shared key
// Decapsulate returns as exposed to a reader of the process's memory on a
// legacy build. The shared key crypto/mlkem returns is copied into a
// SecureBuffer and its heap copy wiped. The encapsulation key is public and
// is computed once at construction, so EncapsulationKeyBytes performs no
// expansion at all.
//
// # Refused on a legacy build
//
// Because of that message, [GenerateMLKEM768Key] and [NewMLKEM768Key] refuse
// with [ErrHeapTransients] on every build without GOEXPERIMENT=runtimesecret
// on linux/amd64 or linux/arm64, the same way [RSASigner] and [ECDSASigner]
// are refused, unless the caller passes [AllowHeapTransients]. The refusal
// comes before the seed is read. [Encapsulate], the sender side, leaves
// nothing behind and is never refused.
type MLKEM768Key struct {
	seedBuf *secmem.SecureBuffer
	ek      []byte // public encapsulation key, captured at construction
}

// GenerateMLKEM768Key generates a fresh 64-byte ML-KEM-768 seed directly
// into a new SecureBuffer using crypto/rand. With the default
// [crypto/rand.Reader] the seed is never materialized on the Go heap by the
// generation itself; see [GenerateEd25519Signer] for the caveat about a
// replaced Reader, and the type comment for the expansion that follows.
//
// To persist the generated key, use [MLKEM768Key.WithSeed].
//
// On a build without GOEXPERIMENT=runtimesecret it returns an error wrapping
// [ErrHeapTransients] unless opts include [AllowHeapTransients]; see the
// type comment.
func GenerateMLKEM768Key(opts ...Option) (*MLKEM768Key, error) {
	if err := resolveOptions(opts).checkHeapTransients("secmemcrypto: generate ML-KEM seed"); err != nil {
		return nil, err
	}
	buf, err := secmem.NewEmptyBuffer(mlkem.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: allocate seed buffer: %w", err)
	}
	if err := buf.WithBytesErr(func(seed []byte) error {
		_, e := io.ReadFull(rand.Reader, seed)
		return e
	}); err != nil {
		_ = buf.Destroy()
		return nil, fmt.Errorf("secmemcrypto: generate seed: %w", err)
	}
	k, err := newMLKEM768Key(buf)
	if err != nil {
		_ = buf.Destroy()
		return nil, err
	}
	return k, nil
}

// NewMLKEM768Key wraps an existing 64-byte ML-KEM-768 seed already held in a
// SecureBuffer. The seed is expanded once, to validate it and to capture
// the public encapsulation key, and the expansion is wiped (see the type
// comment). On success, the MLKEM768Key owns seedBuf — call
// [MLKEM768Key.Destroy] to release it. On failure, ownership is not
// transferred.
//
// On a build without GOEXPERIMENT=runtimesecret it returns an error wrapping
// [ErrHeapTransients] unless opts include [AllowHeapTransients]; see the
// type comment.
func NewMLKEM768Key(seedBuf *secmem.SecureBuffer, opts ...Option) (*MLKEM768Key, error) {
	if err := resolveOptions(opts).checkHeapTransients("secmemcrypto: new ML-KEM key"); err != nil {
		return nil, err
	}
	return newMLKEM768Key(seedBuf)
}

func newMLKEM768Key(seedBuf *secmem.SecureBuffer) (*MLKEM768Key, error) {
	if seedBuf == nil {
		return nil, errors.New("secmemcrypto: nil SecureBuffer")
	}
	if seedBuf.IsDestroyed() {
		return nil, fmt.Errorf("secmemcrypto: new ML-KEM key: %w", secmem.ErrDestroyed)
	}
	if n := seedBuf.Len(); n != mlkem.SeedSize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrBadSeedLength, n, mlkem.SeedSize)
	}
	var ek []byte
	err := secmem.ScrubErr(func() error {
		return seedBuf.WithBytesErr(func(seed []byte) (err error) {
			dk, e := mlkem.NewDecapsulationKey768(seed)
			if e != nil {
				return e
			}
			defer func() { err = errors.Join(err, wipeMLKEMDecapsulationKey(dk)) }()
			ek = dk.EncapsulationKey().Bytes() // public — not secret
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: new ML-KEM key: %w", err)
	}
	return &MLKEM768Key{seedBuf: seedBuf, ek: ek}, nil
}

// EncapsulationKeyBytes returns a copy of the 1184-byte public ML-KEM-768
// encapsulation key, which a peer uses to produce ciphertexts (see
// [Encapsulate]). It is not secret. It was computed once at construction,
// so — like [Ed25519Signer.Public] — it keeps working after Destroy and
// while the seed is sealed, and touches no secret material. Returns an
// error only on a nil receiver.
func (k *MLKEM768Key) EncapsulationKeyBytes() ([]byte, error) {
	if k == nil || k.ek == nil {
		return nil, fmt.Errorf("secmemcrypto: encapsulation key: %w", secmem.ErrDestroyed)
	}
	out := make([]byte, len(k.ek))
	copy(out, k.ek)
	return out, nil
}

// Decapsulate recovers the shared key from a ciphertext produced against
// this key's encapsulation key, returning it in a new SecureBuffer (the
// caller owns and must Destroy it). It errors if the ciphertext is invalid,
// or if this key is destroyed or sealed. The expansion and decapsulation
// run inside [secmem.ScrubErr], and the expanded key is wiped before
// return; an error wrapping the wipe's failure means the expansion could
// not be located and is still live on the heap.
func (k *MLKEM768Key) Decapsulate(ciphertext []byte) (*secmem.SecureBuffer, error) {
	if k == nil || k.seedBuf == nil || k.seedBuf.IsDestroyed() {
		return nil, fmt.Errorf("secmemcrypto: decapsulate: %w", secmem.ErrDestroyed)
	}
	if k.seedBuf.IsSealed() {
		return nil, fmt.Errorf("secmemcrypto: decapsulate: %w", secmem.ErrSealed)
	}
	out, err := secmem.NewEmptyBuffer(mlkem.SharedKeySize)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: allocate shared key buffer: %w", err)
	}
	err = secmem.ScrubErr(func() error {
		return k.seedBuf.WithBytesErr(func(seed []byte) (err error) {
			dk, e := mlkem.NewDecapsulationKey768(seed)
			if e != nil {
				return e
			}
			defer func() { err = errors.Join(err, wipeMLKEMDecapsulationKey(dk)) }()
			shared, e := dk.Decapsulate(ciphertext)
			if e != nil {
				return e
			}
			e = out.WithBytesErr(func(dst []byte) error {
				copy(dst, shared)
				return nil
			})
			secmem.SecureWipe(shared)
			return e
		})
	})
	if err != nil {
		_ = out.Destroy()
		return nil, fmt.Errorf("secmemcrypto: decapsulate: %w", err)
	}
	return out, nil
}

// Encapsulate is the sender-side mirror of [MLKEM768Key.Decapsulate]:
// given a peer's 1184-byte encapsulation key (from their
// [MLKEM768Key.EncapsulationKeyBytes]), it produces a ciphertext to send to
// that peer and the freshly generated shared secret, returned in a new
// SecureBuffer (the caller owns and must Destroy it). The ciphertext is
// public; the shared secret is not.
//
// crypto/mlkem's Encapsulate returns the shared key as a plain heap []byte,
// the first half of a 64-byte slice whose second half is the encryption
// randomness, which recovers the shared key from the public ciphertext. This
// copies the shared key into protected memory and wipes the whole slice
// inside [secmem.ScrubErr]. The random message m and the SHA3 digest that
// absorbs it stay on the stack in go1.26, inside the window, and the residue
// test finds none of m, the shared key or the randomness outside locked
// memory on either kind of build, so Encapsulate is not refused on a legacy
// build. It does not require (and has no access to) a decapsulation key,
// which is why it is a free function rather than a method.
func Encapsulate(encapsulationKey []byte) (ciphertext []byte, sharedSecret *secmem.SecureBuffer, err error) {
	ek, err := mlkem.NewEncapsulationKey768(encapsulationKey)
	if err != nil {
		return nil, nil, fmt.Errorf("secmemcrypto: encapsulate: %w", err)
	}
	return encapsulateInto(func() ([]byte, []byte, error) {
		shared, ct := ek.Encapsulate()
		return shared, ct, nil
	})
}

// encapsulateInto runs kem inside a Scrub window, copies the shared key it
// returns into a new buffer and wipes the heap slice it came in — to its
// capacity, not its length. In go1.26 crypto/mlkem returns the shared key as
// the first half of G = SHA3-512(m || H(ek)), a 64-byte heap slice whose
// second half is the encryption randomness r; r and the public ciphertext
// give m back, and m the shared key, so a wipe of the first 32 bytes left
// the shared key recoverable. The residue test drives this function with
// crypto/mlkem/mlkemtest's derandomized encapsulation, which reaches the same
// kemEncaps, so the scan knows m.
func encapsulateInto(kem func() (shared, ct []byte, err error)) (ciphertext []byte, sharedSecret *secmem.SecureBuffer, err error) {
	out, err := secmem.NewEmptyBuffer(mlkem.SharedKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("secmemcrypto: allocate shared key buffer: %w", err)
	}
	var ct []byte
	err = secmem.ScrubErr(func() error {
		shared, c, e := kem()
		if e != nil {
			return e
		}
		ct = c
		e = out.WithBytesErr(func(dst []byte) error {
			copy(dst, shared)
			return nil
		})
		secmem.SecureWipe(sharedKeyBacking(shared, ct))
		return e
	})
	if err != nil {
		_ = out.Destroy()
		return nil, nil, fmt.Errorf("secmemcrypto: encapsulate: %w", err)
	}
	return ct, out, nil
}

// sharedKeyBacking is shared extended to its capacity, which in go1.26 also
// covers the encryption randomness — unless that range would reach into ct,
// which the caller is about to return, in which case it is shared alone.
func sharedKeyBacking(shared, ct []byte) []byte {
	full := shared[:cap(shared)]
	if len(full) == 0 || cap(ct) == 0 {
		return full
	}
	//nolint:gosec // G103: addresses compared for overlap only; nothing is dereferenced.
	fs := uintptr(unsafe.Pointer(unsafe.SliceData(full)))
	//nolint:gosec // G103: as above.
	cs := uintptr(unsafe.Pointer(unsafe.SliceData(ct)))
	if fs < cs+uintptr(cap(ct)) && cs < fs+uintptr(len(full)) {
		return shared
	}
	return full
}

// WithSeed borrows the 64-byte seed for the duration of fn — the deliberate
// egress point for persisting a generated key. The slice is valid ONLY
// inside fn and must not be retained. Returns an error wrapping
// [secmem.ErrDestroyed] or [secmem.ErrSealed] when the seed is no longer
// accessible.
func (k *MLKEM768Key) WithSeed(fn func(seed []byte) error) error {
	if k == nil || k.seedBuf == nil {
		return fmt.Errorf("secmemcrypto: with seed: %w", secmem.ErrDestroyed)
	}
	return k.seedBuf.WithBytesErr(fn)
}

// Destroy wipes and releases the underlying seed buffer. Destroy is
// idempotent and nil-receiver safe. EncapsulationKeyBytes keeps working
// afterwards, since the encapsulation key is not secret.
func (k *MLKEM768Key) Destroy() error {
	if k == nil {
		return nil
	}
	return k.seedBuf.Destroy()
}
