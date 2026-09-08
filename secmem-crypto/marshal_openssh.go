// marshal_openssh.go is the egress: an Ed25519Signer rendered as an OpenSSH
// private-key file, unencrypted or passphrase-protected, assembled entirely
// inside SecureBuffers. Earlier versions went through ssh.MarshalPrivateKey
// and encoding/pem, each of which builds heap intermediates around the key
// (the marshal scratch, the padded key block, base64's 1 KiB encoder window)
// that are unreachable and unwiped; the doc comment named that limit. The
// container is now written in place by openssh_wire.go, so the only heap
// objects a marshal creates hold public data or ciphertext — and, for the
// encrypted form, the AES key schedule, which aeswipe.go clears.
package secmemcrypto

import (
	"crypto/aes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/secmem-crypto/internal/bcryptpbkdf"
)

// MarshalOpenSSHPrivateKey renders s as an unencrypted OpenSSH private-key
// PEM file (the "-----BEGIN OPENSSH PRIVATE KEY-----" format ssh-keygen and
// authorized_keys tooling expect) and returns it in a fresh SecureBuffer —
// the caller owns it and must call Destroy. This is the egress point for
// persisting a generated key: writing it to disk, registering it with a
// cloud provider's SSH-key API, or handing it to another process. AsSSH
// covers the complementary case — signing over a live connection without
// ever exporting key material at all; use that when you don't actually need
// a portable file. [Ed25519Signer.MarshalOpenSSHPrivateKeyWithPassphrase]
// writes the same file passphrase-protected.
//
// The file is assembled in place: the container is written into one
// SecureBuffer straight from the seed buffer, and the PEM armour into the
// returned one, with no heap copy of the key or of its base64 form at any
// point. The size of the output depends on comment's length, so — unlike
// this package's *Into functions — this allocates the result internally
// rather than asking the caller to pre-size a destination.
//
// A fingerprint does not require this method: it is computed over the
// public key alone, which is not secret — ssh.FingerprintSHA256(pub) on
// the AsSSH-adapted signer's PublicKey() needs nothing from here.
//
// Returns an error wrapping [secmem.ErrDestroyed] or [secmem.ErrSealed]
// when the seed is no longer accessible.
func (s *Ed25519Signer) MarshalOpenSSHPrivateKey(comment string) (*secmem.SecureBuffer, error) {
	out, err := s.marshalOpenSSH(comment, nil)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: marshal openssh private key: %w", err)
	}
	return out, nil
}

// MarshalOpenSSHPrivateKeyWithPassphrase is [Ed25519Signer.MarshalOpenSSHPrivateKey]
// with the private block encrypted under passphrase the way ssh-keygen does
// by default: aes256-ctr with a key and IV from bcrypt_pbkdf at 16 rounds
// over a fresh 16-byte salt. ssh-keygen, ssh-agent, x/crypto/ssh and
// [ParsePrivateKeyWithPassphrase] all open the result. An empty passphrase
// is an error, not an unencrypted file.
//
// The KDF runs on this module's fork of bcrypt_pbkdf with its whole working
// state in a SecureBuffer (see internal/bcryptpbkdf), the key and IV and the
// cipher's scratch live in that same buffer, and the block is encrypted in
// place inside the container's buffer, so the passphrase and the key never
// go through the heap. The one heap object that does hold secret state is the
// AES key schedule crypto/aes allocates; it is wiped through its unexported
// fields before this returns, and if that wipe cannot locate the schedule
// on the running toolchain the call fails rather than leave it behind.
//
// The passphrase is only read — pass a SecureBuffer's borrow — and the
// returned file, being ciphertext, is safe to write anywhere, though it is
// handed back in a SecureBuffer like the unencrypted form.
func (s *Ed25519Signer) MarshalOpenSSHPrivateKeyWithPassphrase(comment string, passphrase []byte) (*secmem.SecureBuffer, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("secmemcrypto: marshal openssh private key: empty passphrase (use MarshalOpenSSHPrivateKey for an unencrypted file)")
	}
	out, err := s.marshalOpenSSH(comment, passphrase)
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: marshal openssh private key: %w", err)
	}
	return out, nil
}

// marshalOpenSSH writes the container for s into a SecureBuffer, encrypts
// the private block in place when a passphrase is given, and PEM-encodes
// the container into the returned buffer. Sizes are computed up front so
// every write is bounds-checked against an exact layout.
func (s *Ed25519Signer) marshalOpenSSH(comment string, passphrase []byte) (*secmem.SecureBuffer, error) {
	if s == nil || s.seedBuf == nil {
		return nil, secmem.ErrDestroyed
	}
	encrypted := len(passphrase) > 0

	cipherName, kdfName, blockSize := opensshCipherNone, opensshKDFNone, opensshNoneBlock
	var kdfOpts [opensshKDFOptsSize]byte // string salt | uint32 rounds; public
	kdfOptsLen := 0
	if encrypted {
		cipherName, kdfName, blockSize = opensshCipherCTR, opensshKDFBcrypt, opensshAESBlock
		w := sshWriter{b: kdfOpts[:]}
		w.length(opensshSaltLen)
		if _, err := rand.Read(kdfOpts[w.n : w.n+opensshSaltLen]); err != nil {
			return nil, fmt.Errorf("salt: %w", err)
		}
		w.n += opensshSaltLen
		w.uint32(opensshRounds)
		kdfOptsLen = w.n
	}
	var check [4]byte // the check integer, random as OpenSSH writes it
	if _, err := rand.Read(check[:]); err != nil {
		return nil, fmt.Errorf("check bytes: %w", err)
	}

	const keyType = opensshKeyEd25519
	pubBlobLen := sshStrLen(len(keyType)) + sshStrLen(ed25519.PublicKeySize)
	privLen := 4 + 4 + sshStrLen(len(keyType)) + sshStrLen(ed25519.PublicKeySize) +
		sshStrLen(ed25519.PrivateKeySize) + sshStrLen(len(comment))
	padLen := (blockSize - privLen%blockSize) % blockSize
	privPadded := privLen + padLen
	total := len(opensshMagic) + sshStrLen(len(cipherName)) + sshStrLen(len(kdfName)) +
		sshStrLen(kdfOptsLen) + 4 + sshStrLen(pubBlobLen) + sshStrLen(privPadded)

	cont, err := secmem.NewEmptyBuffer(total)
	if err != nil {
		return nil, fmt.Errorf("allocate container buffer: %w", err)
	}
	defer func() { _ = cont.Destroy() }()

	err = secmem.ScrubErr(func() error {
		return borrowOrdered(s.seedBuf, cont, func(seed, c []byte) error {
			w := sshWriter{b: c}
			w.bytes(opensshMagic)
			w.strs(cipherName)
			w.strs(kdfName)
			w.str(kdfOpts[:kdfOptsLen])
			w.uint32(1) // number of keys
			w.length(pubBlobLen)
			w.strs(keyType)
			w.str(s.pubKey)
			w.length(privPadded)
			start := w.n
			w.bytes(check[:])
			w.bytes(check[:])
			w.strs(keyType)
			w.str(s.pubKey)
			w.length(ed25519.PrivateKeySize)
			w.bytes(seed)
			w.bytes(s.pubKey)
			w.strs(comment)
			for i := 1; i <= padLen; i++ {
				c[w.n] = byte(i) //nolint:gosec // G115: i ≤ blockSize ≤ 16.
				w.n++
			}
			if w.n != total {
				return errors.New("internal: container layout mismatch")
			}
			if !encrypted {
				return nil
			}
			block := c[start : start+privPadded]
			return opensshCrypt(block, block, passphrase, kdfOpts[4:4+opensshSaltLen], opensshRounds, cipherAES256CTR, false)
		})
	})
	if err != nil {
		return nil, err
	}

	out, err := secmem.NewEmptyBuffer(pemLen(opensshPEMType, total))
	if err != nil {
		return nil, fmt.Errorf("allocate openssh private key buffer: %w", err)
	}
	if err := borrowOrdered(cont, out, func(c, o []byte) error {
		if n := pemEncode(o, opensshPEMType, c); n != len(o) {
			return errors.New("internal: PEM layout mismatch")
		}
		return nil
	}); err != nil {
		_ = out.Destroy()
		return nil, err
	}
	return out, nil
}

// The layout of the locked scratch buffer opensshCrypt works in: the KDF
// workspace, then the derived key and IV, then the cipher's two blocks.
const (
	scratchKIV    = bcryptpbkdf.Size
	scratchCipher = scratchKIV + opensshKeyIVLen
	scratchSize   = scratchCipher + cipherScratch
)

// opensshCrypt derives the AES-256 key and IV from passphrase with
// bcrypt_pbkdf and applies mode to src, writing dst: CTR in either
// direction (dst may be src), CBC for decryption only, as OpenSSH uses it.
// Every byte of secret state it creates is in one SecureBuffer allocated
// for the call — the KDF workspace, the key and IV, the cipher's keystream
// and chaining blocks — and is wiped before return; the AES round keys,
// which crypto/aes puts on the heap, are wiped through aeswipe.go, whose
// failure is this function's failure. What SHA-512's and AES's assembly
// leave in the vector registers is not cleared here: both callers run this
// inside a [secmem.ScrubErr] window, which clears the vector file on the
// way out, on the thread that ran it (vecclear_amd64_test.go proves the
// clear reaches this function's residue).
func opensshCrypt(dst, src, passphrase, salt []byte, rounds int, mode opensshCipher, decrypt bool) error {
	scratch, err := secmem.NewEmptyBuffer(scratchSize)
	if err != nil {
		return fmt.Errorf("allocate kdf workspace: %w", err)
	}
	defer func() { _ = scratch.Destroy() }()
	return scratch.WithBytesErr(func(mem []byte) (err error) {
		defer secmem.SecureWipe(mem)
		ws := bcryptpbkdf.Bind(mem[:bcryptpbkdf.Size])
		kiv := mem[scratchKIV:scratchCipher]
		cipherMem := mem[scratchCipher:scratchSize]

		if err := bcryptpbkdf.Derive(kiv, passphrase, salt, rounds, ws); err != nil {
			return err
		}
		key, iv := kiv[:32], kiv[32:]
		blk, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		defer func() {
			if werr := wipeAESBlock(blk); werr != nil {
				err = errors.Join(err, werr)
			}
		}()
		switch mode {
		case cipherAES256CTR:
			ctrXOR(blk, iv, dst, src, cipherMem)
		case cipherAES256CBC:
			if !decrypt {
				return fmt.Errorf("%w: aes256-cbc for encryption", ErrUnsupportedKey)
			}
			cbcDecrypt(blk, iv, dst, src, cipherMem)
		default:
			return fmt.Errorf("%w: OpenSSH cipher", ErrUnsupportedKey)
		}
		return nil
	})
}
