//go:build unix

// keyring.go holds the agent's keys. This is the file that earns the word
// "hardened" in the directory name; the policy it enforces is:
//
//  1. Private key material lives ONLY in secmem.SecureBuffer — off the Go
//     heap, mlocked (memfd_secret where the kernel offers it), guard-paged,
//     canaried, excluded from dumps, wiped on Destroy.
//
//  2. Keys are SEALED whenever the agent is not actively signing. A sealed
//     buffer is PROT_NONE — a read primitive anywhere in the process
//     faults instead of disclosing the key — and on Windows its contents
//     are additionally ciphertext (CryptProtectMemory). The unsealed
//     window is the microseconds of one signature, under the keyring lock.
//     This is the "dormant-key pattern" from secmem's own test suite.
//
//  3. The agent-protocol LOCK passphrase is never stored. Locking stores
//     an Argon2id derivation (RFC 9106 parameters) in a SecureBuffer;
//     unlocking derives the candidate into a second SecureBuffer and
//     compares in constant time. Wrong-passphrase attempts each cost a
//     full Argon2id derivation, which is the throttle.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/deadpoets/secmem"
	secmemcrypto "github.com/deadpoets/secmem/secmem-crypto"
)

var (
	errLocked       = errors.New("keyring: agent is locked")
	errNotLocked    = errors.New("keyring: agent is not locked")
	errBadPass      = errors.New("keyring: incorrect passphrase")
	errKeyNotFound  = errors.New("keyring: key not found")
	errKeyMismatch  = errors.New("keyring: provided public key does not match private key")
	errShuttingDown = errors.New("keyring: shutting down")
)

// secureSigner is what both secmemcrypto signers provide: standard
// crypto.Signer signing plus explicit key destruction.
type secureSigner interface {
	crypto.Signer
	Destroy() error
}

// record is one held identity.
type record struct {
	// keyBuf is the SecureBuffer holding the seed (Ed25519) or scalar
	// (ECDSA). The signer OWNS it — record.destroy releases it through
	// signer.Destroy, never keyBuf.Destroy — but we retain the pointer
	// because Seal/Unseal are the holder's calls in the dormant-key
	// pattern: sealed at rest, unsealed only inside Keyring.Sign.
	keyBuf  *secmem.SecureBuffer
	signer  secureSigner
	ssh     ssh.Signer
	blob    []byte // wire-format public key; the protocol's identity handle
	comment string

	// expiresAt is when the identity self-destructs; zero means never.
	// Enforcement is destruction: at the deadline the SecureBuffer is
	// wiped and unmapped, not merely hidden from List.
	expiresAt time.Time
}

func (r *record) destroy() {
	// Destroy on a sealed buffer is documented to work (it unprotects and
	// decrypts internally before wiping), so no Unseal is needed here.
	_ = r.signer.Destroy()
}

// Keyring is the agent's in-memory key store. All methods are safe for
// concurrent use. Signing is serialized by design: the unseal→sign→seal
// window must be exclusive or one connection's seal would fault another
// connection's in-flight signature. An ssh-agent is a human-rate service;
// exclusivity costs nothing and keeps the invariant checkable.
type Keyring struct {
	mu        sync.Mutex
	keys      []*record
	destroyed bool

	// Lock state. lockCheck holds Argon2id(passphrase, lockSalt) — 32
	// bytes in secure memory. The passphrase itself is never retained.
	lockCheck *secmem.SecureBuffer
	lockSalt  [16]byte
}

// lockCheckLen is the Argon2id output size for the lock derivation.
const lockCheckLen = 32

func NewKeyring() *Keyring { return &Keyring{} }

// Locked reports whether the agent-protocol lock is engaged.
func (k *Keyring) Locked() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.lockCheck != nil
}

// Add moves the private key material in req into secure memory and
// registers the identity. req's byte fields alias the wire message, which
// the caller wipes after Add returns — by then the only live copy of the
// key is inside a SecureBuffer, sealed.
func (k *Keyring) Add(req *addIdentityRequest) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case k.destroyed:
		return errShuttingDown
	case k.lockCheck != nil:
		return errLocked
	}

	rec, err := buildRecord(req)
	if err != nil {
		return err
	}
	if req.lifetimeSecs > 0 {
		d := time.Duration(req.lifetimeSecs) * time.Second
		rec.expiresAt = time.Now().Add(d)
		// One-shot timer per constrained add; the sweep it triggers also
		// reaps any other identity past its deadline. Sign and List
		// additionally sweep lazily, closing the race at the boundary —
		// a signature can never be produced by an expired key even if
		// the timer goroutine is delayed.
		time.AfterFunc(d, k.expire)
	}

	// Replace an existing identity with the same public key (ssh-add
	// semantics) rather than accumulating duplicates.
	for i, old := range k.keys {
		if bytes.Equal(old.blob, rec.blob) {
			old.destroy()
			k.keys[i] = rec
			return nil
		}
	}
	k.keys = append(k.keys, rec)
	return nil
}

// buildRecord constructs the sealed record for a parsed add request. On
// any failure every intermediate SecureBuffer is destroyed before return.
func buildRecord(req *addIdentityRequest) (*record, error) {
	switch string(req.keyType) {
	case "ssh-ed25519":
		return buildEd25519Record(req)
	default:
		return buildECDSARecord(req)
	}
}

func buildEd25519Record(req *addIdentityRequest) (*record, error) {
	seedBuf, err := secmem.NewEmptyBuffer(ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("keyring: allocating seed buffer: %w", err)
	}
	if _, err := seedBuf.CopyIn(req.edSeed, 0); err != nil {
		_ = seedBuf.Destroy()
		return nil, fmt.Errorf("keyring: copying seed: %w", err)
	}

	signer, err := secmemcrypto.NewEd25519Signer(seedBuf)
	if err != nil {
		_ = seedBuf.Destroy() // ownership was not transferred on failure
		return nil, fmt.Errorf("keyring: %w", err)
	}

	// Cross-check: the wire message carries both seed and public key.
	// NewEd25519Signer derived the public key from the seed; if it does
	// not match what the client claimed, the message is corrupt or
	// malicious — reject rather than serve an identity the client did
	// not intend.
	derived, _ := signer.Public().(ed25519.PublicKey)
	if !bytes.Equal(derived, req.edPub) {
		_ = signer.Destroy()
		return nil, errKeyMismatch
	}

	return finishRecord(seedBuf, signer, req.comment)
}

func buildECDSARecord(req *addIdentityRequest) (*record, error) {
	var curve elliptic.Curve
	switch string(req.ecCurveName) {
	case "nistp256":
		curve = elliptic.P256()
	case "nistp384":
		curve = elliptic.P384()
	case "nistp521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("keyring: unsupported curve %q", req.ecCurveName)
	}
	scalarLen := (curve.Params().BitSize + 7) / 8
	if len(req.ecScalar) == 0 || len(req.ecScalar) > scalarLen {
		return nil, fmt.Errorf("keyring: scalar length %d invalid for %s", len(req.ecScalar), req.ecCurveName)
	}

	scalarBuf, err := secmem.NewEmptyBuffer(scalarLen)
	if err != nil {
		return nil, fmt.Errorf("keyring: allocating scalar buffer: %w", err)
	}
	// mpints are minimal-length; left-pad by writing right-aligned into
	// the zero-initialized buffer, exactly what big.Int.FillBytes would
	// do — without a big.Int copy of the scalar on the heap.
	if _, err := scalarBuf.CopyIn(req.ecScalar, scalarLen-len(req.ecScalar)); err != nil {
		_ = scalarBuf.Destroy()
		return nil, fmt.Errorf("keyring: copying scalar: %w", err)
	}

	// NewECDSASigner validates the scalar (rejects 0 and ≥ group order)
	// and derives the public point; the wire Q is not trusted or used.
	signer, err := secmemcrypto.NewECDSASigner(curve, scalarBuf)
	if err != nil {
		_ = scalarBuf.Destroy()
		return nil, fmt.Errorf("keyring: %w", err)
	}
	// Belt-and-braces equivalent of the Ed25519 cross-check is implicit:
	// the public key served in List is derived from the scalar, so a
	// corrupted Q in the message cannot cause a mismatched identity.
	if _, ok := signer.Public().(*ecdsa.PublicKey); !ok {
		_ = signer.Destroy()
		return nil, errors.New("keyring: unexpected public key type")
	}

	return finishRecord(scalarBuf, signer, req.comment)
}

// finishRecord wraps the signer for SSH, records the public blob, and —
// the load-bearing line — seals the key buffer before the record becomes
// visible to anything.
func finishRecord(keyBuf *secmem.SecureBuffer, signer secureSigner, comment string) (*record, error) {
	sshSigner, err := secmemcrypto.AsSSH(signer)
	if err != nil {
		_ = signer.Destroy()
		return nil, fmt.Errorf("keyring: wrapping for ssh: %w", err)
	}

	if err := keyBuf.Seal(); err != nil {
		_ = signer.Destroy()
		return nil, fmt.Errorf("keyring: sealing key: %w", err)
	}
	return &record{
		keyBuf:  keyBuf,
		signer:  signer,
		ssh:     sshSigner,
		blob:    sshSigner.PublicKey().Marshal(),
		comment: comment,
	}, nil
}

// expire destroys every identity past its deadline. Runs regardless of
// the agent-protocol lock: memory hygiene does not wait for a passphrase.
func (k *Keyring) expire() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.expireLocked()
}

func (k *Keyring) expireLocked() {
	if k.destroyed {
		return
	}
	now := time.Now()
	kept := k.keys[:0]
	for _, r := range k.keys {
		if !r.expiresAt.IsZero() && !now.Before(r.expiresAt) {
			r.destroy()
			continue
		}
		kept = append(kept, r)
	}
	k.keys = kept
}

// Identity is one entry of a List answer: public data only.
type Identity struct {
	Blob    []byte
	Comment string
}

// List returns the held identities. While locked it returns an empty list
// and no error, matching OpenSSH ssh-agent's observable behavior.
func (k *Keyring) List() []Identity {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.destroyed {
		return nil
	}
	k.expireLocked()
	if k.lockCheck != nil {
		return nil
	}
	out := make([]Identity, 0, len(k.keys))
	for _, r := range k.keys {
		out = append(out, Identity{Blob: r.blob, Comment: r.comment})
	}
	return out
}

// Sign signs data with the identity whose public blob matches keyBlob.
// The key is unsealed for exactly the duration of the signature, under
// the keyring lock, and resealed before Sign returns — including on error.
func (k *Keyring) Sign(keyBlob, data []byte) (*ssh.Signature, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case k.destroyed:
		return nil, errShuttingDown
	case k.lockCheck != nil:
		return nil, errLocked
	}
	k.expireLocked()

	var rec *record
	for _, r := range k.keys {
		if bytes.Equal(r.blob, keyBlob) {
			rec = r
			break
		}
	}
	if rec == nil {
		return nil, errKeyNotFound
	}

	if err := rec.keyBuf.Unseal(); err != nil {
		return nil, fmt.Errorf("keyring: unsealing key: %w", err)
	}
	defer func() {
		// Reseal unconditionally. If sealing itself failed the key would
		// remain resident-but-unsealed; treat that as fatal-for-this-key
		// rather than a silent downgrade.
		if err := rec.keyBuf.Seal(); err != nil {
			rec.destroy()
			k.removeRecordLocked(rec)
		}
	}()

	sig, err := rec.ssh.Sign(rand.Reader, data)
	if err != nil {
		return nil, fmt.Errorf("keyring: signing: %w", err)
	}
	return sig, nil
}

// Remove destroys the identity matching keyBlob.
func (k *Keyring) Remove(keyBlob []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case k.destroyed:
		return errShuttingDown
	case k.lockCheck != nil:
		return errLocked
	}
	for _, r := range k.keys {
		if bytes.Equal(r.blob, keyBlob) {
			r.destroy()
			k.removeRecordLocked(r)
			return nil
		}
	}
	return errKeyNotFound
}

// RemoveAll destroys every identity.
func (k *Keyring) RemoveAll() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case k.destroyed:
		return errShuttingDown
	case k.lockCheck != nil:
		return errLocked
	}
	for _, r := range k.keys {
		r.destroy()
	}
	k.keys = nil
	return nil
}

func (k *Keyring) removeRecordLocked(rec *record) {
	for i, r := range k.keys {
		if r == rec {
			k.keys = append(k.keys[:i], k.keys[i+1:]...)
			return
		}
	}
}

// Lock engages the agent-protocol lock. The passphrase bytes alias the
// wire message and are wiped by the caller; only the Argon2id derivation
// survives, in secure memory.
func (k *Keyring) Lock(passphrase []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case k.destroyed:
		return errShuttingDown
	case k.lockCheck != nil:
		return errLocked // already locked; OpenSSH also refuses
	}

	if _, err := rand.Read(k.lockSalt[:]); err != nil {
		return fmt.Errorf("keyring: lock salt: %w", err)
	}
	check, err := secmem.NewEmptyBuffer(lockCheckLen)
	if err != nil {
		return fmt.Errorf("keyring: lock buffer: %w", err)
	}
	if err := secmemcrypto.Argon2DeriveInto(passphrase, k.lockSalt[:], check); err != nil {
		_ = check.Destroy()
		return fmt.Errorf("keyring: lock derivation: %w", err)
	}
	k.lockCheck = check
	return nil
}

// Unlock disengages the lock if passphrase matches. The comparison is
// constant-time over Argon2id derivations; a wrong guess costs the full
// RFC 9106 work factor.
func (k *Keyring) Unlock(passphrase []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case k.destroyed:
		return errShuttingDown
	case k.lockCheck == nil:
		return errNotLocked
	}

	candidate, err := secmem.NewEmptyBuffer(lockCheckLen)
	if err != nil {
		return fmt.Errorf("keyring: unlock buffer: %w", err)
	}
	defer func() { _ = candidate.Destroy() }()
	if err := secmemcrypto.Argon2DeriveInto(passphrase, k.lockSalt[:], candidate); err != nil {
		return fmt.Errorf("keyring: unlock derivation: %w", err)
	}

	var equal bool
	err = candidate.WithBytesErr(func(cand []byte) error {
		ok, cmpErr := k.lockCheck.ConstantTimeEqual(cand)
		equal = ok
		return cmpErr
	})
	if err != nil {
		return fmt.Errorf("keyring: unlock comparison: %w", err)
	}
	if !equal {
		return errBadPass
	}

	_ = k.lockCheck.Destroy()
	k.lockCheck = nil
	k.lockSalt = [16]byte{}
	return nil
}

// DestroyAll wipes every key and the lock state, and marks the keyring
// unusable. Called on shutdown; secmem's termination-wipe handler is the
// backstop if the process dies without reaching this.
func (k *Keyring) DestroyAll() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.destroyed {
		return
	}
	k.destroyed = true
	for _, r := range k.keys {
		r.destroy()
	}
	k.keys = nil
	if k.lockCheck != nil {
		_ = k.lockCheck.Destroy()
		k.lockCheck = nil
	}
}
