// parse_encrypted.go is ParsePrivateKey for passphrase-protected OpenSSH
// files. The container is read in place from a SecureBuffer as the
// unencrypted path does; the private block is decrypted from it into a
// second SecureBuffer, never onto the heap, and handed to the same per-type
// extraction. The KDF is this module's fork of bcrypt_pbkdf
// (internal/bcryptpbkdf), whose working state is a SecureBuffer the call
// wipes; the AES modes are written out over one cipher.Block whose round
// keys are wiped before the call returns (openssh_cipher.go, aeswipe.go).
package secmemcrypto

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/deadpoets/secmem"
)

// ErrNotEncrypted is returned by [ParsePrivateKeyWithPassphrase] for a key
// that is not passphrase-protected. It is deliberate that the call does not
// fall through to a plain parse: a caller that expected a protected file
// should learn that it is not one. Use [ParsePrivateKey] for it.
var ErrNotEncrypted = errors.New("secmemcrypto: private key is not passphrase-protected")

// ParsePrivateKeyWithPassphrase parses a passphrase-protected OpenSSH
// private key ("OPENSSH PRIVATE KEY", PEM-armoured or raw; the format
// ssh-keygen writes for every key type when given a passphrase) and returns
// a signer that holds it in a [secmem.SecureBuffer]. The caller owns the
// result and must call Destroy. Key types, the public-key cross-check, and
// the error and ownership rules are [ParsePrivateKey]'s.
//
// Supported protection is what ssh-keygen and x/crypto/ssh write and read:
// KDF bcrypt, cipher aes256-ctr or aes256-cbc, up to 2048 rounds (x/crypto's
// cap: cost is linear in rounds and the count comes from the file). Other
// ciphers (chacha20-poly1305@openssh.com, the aes128 and aes192 variants),
// PKCS#8 "ENCRYPTED PRIVATE KEY" (PBES2), and legacy PEM Proc-Type /
// DEK-Info encryption return an error wrapping [ErrUnsupportedKey]. A wrong
// passphrase returns an error wrapping [x509.IncorrectPasswordError], the
// value x/crypto/ssh returns for the same condition, so a caller migrating
// from ssh.ParseRawPrivateKeyWithPassphrase keeps its errors.Is check. A
// key that is not protected at all returns [ErrNotEncrypted]; an empty
// passphrase is an error before anything is read.
//
// What touches the heap: everything ParsePrivateKey's doc lists, plus the
// AES key schedule crypto/aes allocates — wiped through the type's
// unexported fields before return, and if that wipe cannot locate the
// schedule on the running toolchain the call fails rather than leave it
// behind. The KDF's working state (the Blowfish schedule and both SHA-512
// outputs, about 4 KiB), the derived key and IV, and the cipher's scratch
// live in one SecureBuffer for the call. data and passphrase are the
// caller's: neither is wiped nor retained.
func ParsePrivateKeyWithPassphrase(data, passphrase []byte) (Signer, error) {
	if len(data) == 0 {
		return nil, errors.New("secmemcrypto: parse private key: empty input")
	}
	if len(passphrase) == 0 {
		return nil, errors.New("secmemcrypto: parse private key: empty passphrase")
	}
	var s Signer
	err := secmem.ScrubErr(func() error {
		var perr error
		s, perr = parseEncryptedPrivateKey(data, passphrase)
		return perr
	})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: parse private key: %w", err)
	}
	return s, nil
}

// parseEncryptedPrivateKey locates the container the way parsePrivateKey
// does and classifies what it finds: only an OpenSSH container can be
// opened here; every other shape is named as unsupported or as not
// encrypted. The container goes into a SecureBuffer before its header is
// read, because until the header is read it may be an unencrypted key.
func parseEncryptedPrivateKey(data, passphrase []byte) (Signer, error) {
	var (
		blob *secmem.SecureBuffer
		err  error
	)
	switch {
	case bytes.HasPrefix(data, opensshMagic):
		blob, err = copyToBuffer(data)
	case looksLikeDER(data):
		return nil, derEncryptionError(data)
	case bytes.Contains(data, pemBegin):
		typ, body, perr := pemBlock(data)
		if errors.Is(perr, ErrEncryptedKey) {
			return nil, fmt.Errorf("%w: legacy PEM encryption (Proc-Type / DEK-Info headers)", ErrUnsupportedKey)
		}
		if perr != nil {
			return nil, perr
		}
		switch string(typ) { // comparison only: no string is allocated
		case opensshPEMType:
			blob, err = decodePEMBody(body)
		case "ENCRYPTED PRIVATE KEY":
			return nil, fmt.Errorf("%w: PKCS#8 encryption (PBES2)", ErrUnsupportedKey)
		case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY":
			return nil, ErrNotEncrypted
		default:
			return nil, fmt.Errorf("%w: PEM block type %q", ErrUnsupportedKey, typ)
		}
	default:
		return nil, fmt.Errorf("%w: not PEM, OpenSSH, or DER", errMalformed)
	}
	if err != nil {
		return nil, err
	}
	return parseOpenSSHEncrypted(blob, passphrase)
}

// derEncryptionError classifies a bare DER SEQUENCE by its first element:
// an INTEGER (a version) opens every unencrypted structure ParsePrivateKey
// reads; a SEQUENCE (an AlgorithmIdentifier) opens EncryptedPrivateKeyInfo.
func derEncryptionError(data []byte) error {
	in := cryptobyte.String(data)
	var seq, elem cryptobyte.String
	var tag cbasn1.Tag
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadAnyASN1Element(&elem, &tag) {
		return errMalformed
	}
	if tag == cbasn1.INTEGER {
		return ErrNotEncrypted
	}
	return fmt.Errorf("%w: PKCS#8 encryption (PBES2)", ErrUnsupportedKey)
}

// parseOpenSSHEncrypted opens a protected "openssh-key-v1" container held
// in blob and returns the signer. blob is destroyed on every path.
func parseOpenSSHEncrypted(blob *secmem.SecureBuffer, passphrase []byte) (Signer, error) {
	var (
		s   Signer
		der *secmem.SecureBuffer
	)
	err := blob.WithBytesErr(func(b []byte) error {
		h, err := readOpenSSHHeader(b)
		if err != nil {
			return err
		}
		if string(h.cipher) == opensshCipherNone || string(h.kdf) == opensshKDFNone {
			return ErrNotEncrypted
		}
		if string(h.kdf) != opensshKDFBcrypt {
			return fmt.Errorf("%w: OpenSSH KDF %q", ErrUnsupportedKey, h.kdf)
		}
		mode := opensshCipherByName(h.cipher)
		if mode == cipherUnsupported {
			return fmt.Errorf("%w: OpenSSH cipher %q", ErrUnsupportedKey, h.cipher)
		}
		if h.numKeys != 1 {
			return fmt.Errorf("%w: OpenSSH file holds %d keys, want 1", ErrUnsupportedKey, h.numKeys)
		}
		o := sshReader{h.kdfOpts}
		salt, ok1 := o.str()
		rounds, ok2 := o.uint32()
		if !ok1 || !ok2 || len(o.b) != 0 || len(salt) == 0 || rounds == 0 {
			return fmt.Errorf("%w: bcrypt KDF options", errMalformed)
		}
		if rounds > opensshMaxRounds {
			// The file names the cost; an oversized count would tie the
			// caller up for a very long time, not fail. Same cap as x/crypto.
			return fmt.Errorf("%w: bcrypt KDF rounds %d exceed the maximum %d this parser will run", ErrUnsupportedKey, rounds, opensshMaxRounds)
		}
		if len(h.privBlock) == 0 || len(h.privBlock)%opensshAESBlock != 0 {
			return fmt.Errorf("%w: encrypted block is not a multiple of the cipher block size", errMalformed)
		}

		plain, err := secmem.NewEmptyBuffer(len(h.privBlock))
		if err != nil {
			return fmt.Errorf("allocate key buffer: %w", err)
		}
		defer func() { _ = plain.Destroy() }()
		return plain.WithBytesErr(func(p []byte) error {
			if err := opensshCrypt(p, h.privBlock, passphrase, salt, int(rounds), mode, true); err != nil {
				return err
			}
			var err error
			s, der, err = parseOpenSSHPrivateBlock(p, h.pubBlob)
			if errors.Is(err, errCheckMismatch) {
				// The check integers are the format's passphrase test; a
				// mismatch after decryption is a wrong passphrase, not a
				// malformed file (the odds of a wrong one passing are 2^-32,
				// and the block then fails to parse).
				return x509.IncorrectPasswordError
			}
			return err
		})
	})
	_ = blob.Destroy()
	if err != nil {
		return nil, err
	}
	if der != nil {
		return rsaFromDER(der)
	}
	return s, nil
}
