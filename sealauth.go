// sealauth.go authenticates the sealed state. Seal takes a keyed tag over
// the bytes it leaves at rest and Unseal verifies it before anything reads
// them, so a bit that changed while the buffer was dormant — a Rowhammer
// flip, a DRAM soft error, a stray write through a stale pointer that the
// PROT_NONE page did not catch because it landed while the buffer was being
// resealed — is refused with ErrIntegrity instead of being handed out as the
// secret. A one-bit fault in a dormant signing key is not a nuisance: a
// signature made under a key that differs from the real one in a known
// position reveals that bit of the real key.
//
// The tag is keyed, never a bare hash. An unkeyed digest of a password-sized
// secret sitting on the Go heap would be an offline guess-confirmation
// oracle; the key makes the tag worthless to anyone who reads it.
//
// # The prekey
//
// The key is derived from a 16 KiB prekey, not held as 32 or 64 bytes. That
// is the OpenSSH key-shielding design and it is aimed at RAMBleed-class
// reads: an attacker who recovers bits of physical memory through a
// data-dependent Rowhammer side channel reads slowly and imperfectly, and a
// key that is SHA-512 of 16 KiB demands every one of those 131072 bits
// exactly right. The prekey is allocated once per process, lazily on the
// first Seal, in a locked region registered with the janitor like any other
// secret. It is never reallocated while it is live, because a victim that
// re-allocates is a victim whose pages an attacker can place.
//
// The root key SHA-512(prekey) is recomputed on the stack for every tag and
// never cached: cached, it would be exactly the small, long-lived target the
// prekey exists to avoid. The derivation runs inside a Scrub window.
//
// # Construction
//
//	R      = SHA-512(prekey)
//	tag    = HMAC-SHA-512(R, "secmem/seal/v1/mac" || id || nonce || len || SHA-512(bytes))[:32]
//
// where id is the buffer's janitor key, nonce is 16 fresh bytes per Seal and
// bytes is the whole inner region as it sits at rest — on Windows, after
// CryptProtectMemory. Hash-then-MAC lets the message hash be a one-shot
// directly over the region, and HMAC is the standard library's one-shot
// SHA-512 twice over a stack scratch, the shape secmem-crypto's in-place HMAC
// uses and residue-tests. Nothing here allocates (pinned by a test) and
// nothing secret is captured by a closure.
//
// The construction has a version in its label so that a later change is a
// new label, not a silent reinterpretation of old tags. No tag ever leaves
// the process, so there is nothing to migrate.
//
// # What this does not do
//
// It detects a change; it does not prevent one, and it does not detect a
// flip in the in-use window between Unseal and Seal. A flip in the prekey
// makes every sealed buffer unrecoverable — fail-closed, deliberately. The
// at-rest bytes stay plaintext off Windows; encrypting them under the same
// root key is the planned next step and the reason the layout above binds
// everything the cipher will need.

package secmem

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

const (
	// sealPrekeyLen is the prekey size — OpenSSH's choice, see above.
	sealPrekeyLen = 16 << 10
	sealRootLen   = sha512.Size
	sealBlockLen  = sha512.BlockSize
	sealTagLen    = 32
	sealNonceLen  = 16
)

// sealLabelMac is the domain-separation label. A byte array, not a string
// constant, so it is copied into the stack message rather than referenced.
var sealLabelMac = [...]byte{'s', 'e', 'c', 'm', 'e', 'm', '/', 's', 'e', 'a', 'l', '/', 'v', '1', '/', 'm', 'a', 'c'} //nolint:gochecknoglobals // constant label

// sealKeyring is the process's prekey. One per process; see the file comment
// for why it is allocated once and never moved.
//
// After WipeAllSecrets the region holds zeros and wiped is set. A zeroed
// prekey must never derive a key, so the next Seal allocates a fresh one and
// bumps gen; a buffer sealed under an earlier generation can only have
// survived the wipe through errWipeSkipped, and its Unseal reports ErrWiped
// rather than a misleading ErrIntegrity.
type sealKeyring struct {
	mu     sync.Mutex // guards region, lock, wiped, key, gen — the init state
	region secRegion
	lock   *bufferRWLock
	wiped  *atomic.Bool
	key    uint64 // janitor key
	gen    uint64
}

var sealKeys sealKeyring //nolint:gochecknoglobals // one prekey per process, by design

// withPrekey runs fn with the live prekey under the keyring's shared lock,
// initialising or regenerating it first. The lock is a leaf: nothing is
// acquired while it is held, so taking it under a buffer's exclusive lock
// cannot deadlock against the janitor's passes, which lock one region at a
// time.
func (k *sealKeyring) withPrekey(fn func(prekey []byte, gen uint64) error) error {
	k.mu.Lock()
	if k.lock == nil || k.wiped.Load() {
		if err := k.initLocked(); err != nil {
			k.mu.Unlock()
			return err
		}
	}
	lock, region, wiped, gen := k.lock, k.region, k.wiped, k.gen
	k.mu.Unlock()

	lock.rLock()
	defer lock.rUnlock()
	if wiped.Load() {
		// Wiped between the check above and the lock; the caller's own
		// region is being wiped by the same pass.
		return ErrWiped
	}
	return fn(region.inner, gen)
}

// initLocked allocates and fills a prekey, releasing a wiped predecessor's
// mapping first. Caller holds k.mu.
func (k *sealKeyring) initLocked() error {
	if k.lock != nil {
		// The emergency wipe left the old region mapped and zero; reclaim it
		// the way an owner's Destroy would. Nothing can be borrowing it: every
		// withPrekey saw wiped and returned.
		_ = emergencyJanitor.release(k.key, false)
		k.lock, k.region, k.wiped, k.key = nil, secRegion{}, nil, 0
	}
	region, data, _, err := allocSecretMem(sealPrekeyLen)
	if err != nil {
		return fmt.Errorf("secmem: seal prekey: %w", err)
	}
	// Page-exact by construction, so there is no canary slack to arm; the
	// janitor gets the empty layout.
	if len(data) != len(region.inner) {
		secureWipeSlice(region.inner)
		_ = freeSecretMem(region)
		return errors.New("secmem: seal prekey: allocation is not page-exact")
	}
	lock, wiped := newBufferRWLock(), new(atomic.Bool)
	key, err := emergencyJanitor.register(region, canaryLayout{}, lock, nil, wiped)
	if err != nil {
		secureWipeSlice(region.inner)
		_ = freeSecretMem(region)
		return fmt.Errorf("secmem: seal prekey: %w", err)
	}
	// Registered before it is filled, like every buffer (see fillInitial), so
	// there is no instant at which a live prekey is unreachable by the wipe.
	lock.lock()
	if _, err := rand.Read(region.inner); err != nil {
		lock.unlock()
		_ = emergencyJanitor.release(key, false)
		return fmt.Errorf("secmem: seal prekey: %w", err)
	}
	lock.unlock()
	// Read-only for its whole life: a stray write faults instead of silently
	// re-keying every sealed buffer. The janitor's wipe lifts it.
	if err := mprotectSecretMem(region, 1 /*PROT_READ*/); err != nil {
		_ = emergencyJanitor.release(key, false)
		return fmt.Errorf("secmem: seal prekey: %w", err)
	}
	k.region, k.lock, k.wiped, k.key = region, lock, wiped, key
	k.gen++
	return nil
}

// sealPRFState is HMAC-SHA-512 with the key pads prepared once: (R ^ ipad)
// with room for a message after it, (R ^ opad) with room for the inner
// digest. A stack value; done wipes it.
type sealPRFState struct {
	ipad  [sealBlockLen + sealBlockLen]byte
	opad  [sealBlockLen + sealRootLen]byte
	inner [sealRootLen]byte
}

func (st *sealPRFState) init(root *[sealRootLen]byte) {
	copy(st.ipad[:], root[:])
	copy(st.opad[:], root[:])
	for i := range sealBlockLen {
		st.ipad[i] ^= 0x36
		st.opad[i] ^= 0x5c
	}
}

// prf writes HMAC-SHA-512(R, msg) to out. msg is at most sealBlockLen bytes.
func (st *sealPRFState) prf(out *[sealRootLen]byte, msg []byte) {
	n := sealBlockLen + copy(st.ipad[sealBlockLen:], msg)
	st.inner = sha512.Sum512(st.ipad[:n])
	copy(st.opad[sealBlockLen:], st.inner[:])
	*out = sha512.Sum512(st.opad[:])
}

func (st *sealPRFState) done() {
	secureWipeSlice(st.ipad[:])
	secureWipeSlice(st.opad[:])
	secureWipeSlice(st.inner[:])
}

// sealComputeTag derives the at-rest tag for data under the given prekey,
// buffer identity and nonce. Every secret intermediate — the root key, the
// pads, the digests — is a local wiped before return; the caller runs it in
// a Scrub window for the frame and register residue.
func sealComputeTag(tag *[sealTagLen]byte, prekey []byte, id uint64, nonce *[sealNonceLen]byte, data []byte) {
	// The prekey is 16 KiB of crypto/rand output, not a password: it has no
	// shortage of entropy to stretch, and a slow hash here would only make
	// every Seal and Unseal slower.
	root := sha512.Sum512(prekey)
	var st sealPRFState
	st.init(&root)
	secureWipeSlice(root[:])

	// Hash-then-MAC: the digest of the secret bytes is the MAC's message, a
	// stack local keyed and wiped below, never stored or compared on its own.
	// What it needs is collision resistance, not the cost of a password hash;
	// CodeQL sees secret bytes going into a fast hash and asks for the latter.
	// codeql[go/weak-sensitive-data-hashing]
	d := sha512.Sum512(data)
	var msg [len(sealLabelMac) + 8 + sealNonceLen + 8 + sha512.Size]byte
	n := copy(msg[:], sealLabelMac[:])
	binary.BigEndian.PutUint64(msg[n:], id)
	n += 8
	n += copy(msg[n:], nonce[:])
	binary.BigEndian.PutUint64(msg[n:], uint64(len(data)))
	n += 8
	copy(msg[n:], d[:])

	var out [sealRootLen]byte
	st.prf(&out, msg[:])
	copy(tag[:], out[:sealTagLen])

	secureWipeSlice(out[:])
	secureWipeSlice(d[:])
	st.done()
}

// sealAuthenticate takes a fresh nonce and the tag over region.inner as it
// is right now. Caller holds s.mu with the region readable.
func (s *SecureBuffer) sealAuthenticate() error {
	if _, err := rand.Read(s.sealNonce[:]); err != nil {
		return err
	}
	err := sealKeys.withPrekey(func(prekey []byte, gen uint64) error {
		s.sealGen = gen
		return ScrubErr(func() error {
			sealComputeTag(&s.sealTag, prekey, s.janitorKey, &s.sealNonce, s.region.inner)
			return nil
		})
	})
	if err != nil {
		return err
	}
	s.sealTagged = true
	return nil
}

// sealVerify recomputes the tag over region.inner and compares it in constant
// time with the one Seal took. Caller holds s.mu with the region readable.
func (s *SecureBuffer) sealVerify() error {
	var want [sealTagLen]byte
	err := sealKeys.withPrekey(func(prekey []byte, gen uint64) error {
		if gen != s.sealGen {
			return ErrWiped
		}
		return ScrubErr(func() error {
			sealComputeTag(&want, prekey, s.janitorKey, &s.sealNonce, s.region.inner)
			return nil
		})
	})
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(want[:], s.sealTag[:]) != 1 {
		return ErrIntegrity
	}
	return nil
}
