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
	"github.com/deadpoets/secmem/secmem-crypto/internal/bcryptpbkdf"
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
// result and must call Destroy. Key types, the public-key cross-check, the
// error and ownership rules, and the [ErrHeapTransients] refusal of RSA and
// EC keys without [AllowHeapTransients] are [ParsePrivateKey]'s.
//
// Supported protection is what ssh-keygen and x/crypto/ssh write and read:
// KDF bcrypt, cipher aes256-ctr or aes256-cbc, up to 2048 rounds (x/crypto's
// cap: cost is linear in rounds and the count comes from the file). Other
// ciphers (chacha20-poly1305@openssh.com, the aes128 and aes192 variants),
// PKCS#8 "ENCRYPTED PRIVATE KEY" (PBES2), and legacy PEM Proc-Type /
// DEK-Info encryption return an error wrapping [ErrUnsupportedKey]; the
// legacy form additionally wraps [ErrRetiredAlgorithm], because that one is
// refused on purpose and will not arrive in a later release, while the
// others are simply not implemented yet. A key that is not protected at all
// returns [ErrNotEncrypted]; a header that names a cipher without a KDF, or
// a KDF without a cipher, is malformed rather than either; an empty
// passphrase is an error before anything is read.
//
// Everything that can be decided without the passphrase is decided before
// the KDF runs: the container's structure and header, the KDF parameters,
// and — from the cleartext public-key block — the key type, so an
// unsupported type is [ErrUnsupportedKey] and an RSA or EC key on a build
// without GOEXPERIMENT=runtimesecret is [ErrHeapTransients] (absent
// [AllowHeapTransients]) at no bcrypt cost and before any of the key is
// handed to the standard library.
//
// After decryption the outcome is binary. The two AES modes are
// unauthenticated, so a file can be altered without the passphrase, and a
// parser that reported which check failed — the check integers, the
// padding, a length, the public half against the private — would tell
// whoever altered it where in the block the damage landed. This one
// reports every failure to turn the decrypted block into a key as one
// error, wrapping [x509.IncorrectPasswordError] (the value x/crypto/ssh
// returns for a wrong passphrase, so a caller migrating from
// ssh.ParseRawPrivateKeyWithPassphrase keeps its errors.Is check) and
// reading the same for a wrong passphrase as for a corrupt file. What stays
// observable is success: damage confined to the comment, which no reader
// validates, leaves a key that opens — here as in OpenSSH. One cost of the
// single answer: a failure to lock memory for the key's own buffer at that
// point is reported as this error too; [ParsePrivateKey] on the unprotected
// form of the same key names it.
//
// What touches the heap: everything ParsePrivateKey's doc lists, plus the
// AES key schedule crypto/aes allocates — wiped through the type's
// unexported fields before return, and if that wipe cannot locate the
// schedule on the running toolchain the call fails rather than leave it
// behind. The KDF's working state (the Blowfish schedule and both SHA-512
// outputs, about 4 KiB), the derived key and IV, and the cipher's scratch
// live in one SecureBuffer for the call. data and passphrase are the
// caller's: neither is wiped nor retained.
func ParsePrivateKeyWithPassphrase(data, passphrase []byte, opts ...Option) (Signer, error) {
	if len(data) == 0 {
		return nil, errors.New("secmemcrypto: parse private key: empty input")
	}
	if len(passphrase) == 0 {
		return nil, errors.New("secmemcrypto: parse private key: empty passphrase")
	}
	var s Signer
	err := secmem.ScrubErr(func() error {
		var perr error
		s, perr = parseEncryptedPrivateKey(data, passphrase, resolveOptions(opts))
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
func parseEncryptedPrivateKey(data, passphrase []byte, o options) (Signer, error) {
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
			// The legacy form: refused permanently, not pending. The
			// passphrase is not even looked at. See ErrRetiredAlgorithm.
			return nil, fmt.Errorf("%w: %w", ErrUnsupportedKey, errLegacyPEM)
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
			return nil, fmt.Errorf("%w: PEM block type %s", ErrUnsupportedKey, labelForError(typ))
		}
	default:
		return nil, fmt.Errorf("%w: not PEM, OpenSSH, or DER", errMalformed)
	}
	if err != nil {
		return nil, err
	}
	return parseOpenSSHEncrypted(blob, passphrase, o)
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

// errOpenSSHDecrypt is the one error for everything that goes wrong after
// the private block is decrypted: the check integers disagreeing (the
// format's own passphrase test), a length that overruns, a bad pad, halves
// that disagree, a key type other than the public block's, a scalar out of
// range, an RSA key the standard library finds inconsistent. aes256-ctr and
// aes256-cbc carry no authenticator, so a wrong passphrase and a modified
// file produce the same kind of noise, and a parser that named which of
// those checks failed would tell whoever modified the file where in the
// block the damage landed. This is that check collapsed to one bit. It
// wraps x509.IncorrectPasswordError because a wrong passphrase is the
// common cause and the value is what x/crypto/ssh returns for it.
//
// The cost is that the rare non-content failure inside that stretch — the
// host declining to lock memory for the key's own buffer, after it just
// locked the container's, the plaintext's and the KDF's — is reported this
// way too. ParsePrivateKey on the unprotected form of the same key names
// it.
var errOpenSSHDecrypt = fmt.Errorf("OpenSSH private block did not decrypt to a valid key (wrong passphrase or corrupt file): %w", x509.IncorrectPasswordError)

// parseOpenSSHEncrypted opens a protected "openssh-key-v1" container held
// in blob and returns the signer. blob is destroyed on every path.
//
// Order matters here and is the point: every refusal that does not need
// the passphrase — the header, the KDF parameters, the key type and the
// heap-transients gate read off the cleartext public-key block — comes
// before the KDF runs, and every failure after decryption is
// errOpenSSHDecrypt.
func parseOpenSSHEncrypted(blob *secmem.SecureBuffer, passphrase []byte, o options) (Signer, error) {
	var (
		s   Signer
		der *secmem.SecureBuffer
	)
	err := blob.WithBytesErr(func(b []byte) error {
		h, err := readOpenSSHHeader(b)
		if err != nil {
			return err
		}
		if string(h.cipher) == opensshCipherNone { // the header guarantees the KDF agrees
			return ErrNotEncrypted
		}
		if string(h.kdf) != opensshKDFBcrypt {
			return fmt.Errorf("%w: OpenSSH KDF %s", ErrUnsupportedKey, labelForError(h.kdf))
		}
		mode := opensshCipherByName(h.cipher)
		if mode == cipherUnsupported {
			// Named before the tail is judged: an AEAD cipher's tag sits
			// after the private block, and a chacha20-poly1305 file must be
			// refused as the cipher it is, not as trailing junk.
			return fmt.Errorf("%w: OpenSSH cipher %s", ErrUnsupportedKey, labelForError(h.cipher))
		}
		if len(h.rest) != 0 { // neither AES mode carries an authenticator: the file ends with the block
			return fmt.Errorf("%w: trailing bytes after the OpenSSH container", errMalformed)
		}
		if h.numKeys != 1 {
			return fmt.Errorf("%w: OpenSSH file holds %d keys, want 1", ErrUnsupportedKey, h.numKeys)
		}
		kdf := sshReader{h.kdfOpts}
		salt, ok1 := kdf.str()
		rounds, ok2 := kdf.uint32()
		if !ok1 || !ok2 || len(kdf.b) != 0 || len(salt) == 0 || rounds == 0 {
			return fmt.Errorf("%w: bcrypt KDF options", errMalformed)
		}
		if len(salt) > bcryptpbkdf.MaxSaltLen {
			// The KDF's own bound (upstream's), checked here so the file's
			// error is the file's: without this it would surface as a bare
			// bcrypt_pbkdf error matching no sentinel of this package.
			return fmt.Errorf("%w: bcrypt KDF salt of %d bytes exceeds %d", errMalformed, len(salt), bcryptpbkdf.MaxSaltLen)
		}
		if rounds > opensshMaxRounds {
			// The file names the cost; an oversized count would tie the
			// caller up for a very long time, not fail. Same cap as x/crypto.
			return fmt.Errorf("%w: bcrypt KDF rounds %d exceed the maximum %d this parser will run", ErrUnsupportedKey, rounds, opensshMaxRounds)
		}
		if len(h.privBlock) == 0 || len(h.privBlock)%opensshAESBlock != 0 {
			return fmt.Errorf("%w: encrypted block is not a multiple of the cipher block size", errMalformed)
		}
		if err := admitOpenSSHKeyType(h.pubBlob, o); err != nil {
			return err
		}

		plain, err := secmem.NewEmptyBuffer(len(h.privBlock))
		if err != nil {
			return fmt.Errorf("allocate key buffer: %w", err)
		}
		defer func() { _ = plain.Destroy() }()
		return plain.WithBytesErr(func(p []byte) error {
			if err := opensshCrypt(p, h.privBlock, passphrase, salt, int(rounds), mode, true); err != nil {
				// Not a verdict on the block: the KDF's bounds were checked
				// above, so this is the AES schedule wipe failing closed,
				// which the caller must see as itself.
				return err
			}
			var err error
			s, der, err = parseOpenSSHPrivateBlock(p, h.pubBlob, opensshAESBlock, o)
			if err != nil {
				return errOpenSSHDecrypt
			}
			return nil
		})
	})
	_ = blob.Destroy()
	if err != nil {
		return nil, err
	}
	if der != nil {
		// The standard library's consistency checks on the assembled DER
		// (n = p·q, e·d ≡ 1, …) are the last thing that reads the decrypted
		// block, and damage to d, p, q or iqmp is caught nowhere earlier;
		// their failure is the same one bit.
		s, err := rsaFromDER(der, o)
		if err != nil {
			return nil, errOpenSSHDecrypt
		}
		return s, nil
	}
	return s, nil
}

// admitOpenSSHKeyType decides, from the container's cleartext public-key
// block, whether the key inside is one this call will return: its type must
// be one the private-block parser handles, and an RSA or EC key must pass
// the heap-transients gate for this build and these options — the same
// gate the signer constructors apply, with the same message, so a caller
// sees one error for one condition whichever entry point it used. Both are
// refused here, before the KDF, so a refused file costs no bcrypt
// derivation and no byte of its key is decrypted. The private block's own
// type field is compared with this one after decryption, so a file whose
// halves disagree is refused there as every other post-decryption failure.
func admitOpenSSHKeyType(pubBlob []byte, o options) error {
	pub := sshReader{pubBlob}
	keyType, ok := pub.str()
	if !ok {
		return fmt.Errorf("%w: public key block", errMalformed)
	}
	switch string(keyType) { // comparison only: no string is allocated
	case "ssh-ed25519":
		return nil
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return o.checkHeapTransients("secmemcrypto: new ecdsa signer")
	case "ssh-rsa":
		return o.checkHeapTransients("secmemcrypto: new rsa signer")
	default:
		return fmt.Errorf("%w: OpenSSH key type %s", ErrUnsupportedKey, labelForError(keyType))
	}
}
