// parse_encrypted.go is ParsePrivateKey for passphrase-protected OpenSSH
// files (pbes2.go has the PKCS#8 counterpart, and the container dispatch
// here routes to it). The container is read in place from a SecureBuffer
// as the unencrypted path does; the private block is decrypted from it
// into a second SecureBuffer, never onto the heap, and handed to the same
// per-type extraction. The KDF is this module's fork of bcrypt_pbkdf
// (internal/bcryptpbkdf), whose working state is a SecureBuffer the call
// wipes; the AES modes are written out over one cipher.Block whose round
// keys are wiped before the call returns (openssh_cipher.go, aeswipe.go),
// and chacha20-poly1305@openssh.com over a core of this module's own whose
// state is stack locals wiped in the call (openssh_chacha.go).
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

// ParsePrivateKeyWithPassphrase parses a passphrase-protected private key
// and returns a signer that holds it in a [secmem.SecureBuffer]: an OpenSSH
// file ("OPENSSH PRIVATE KEY", PEM-armoured or raw; the format ssh-keygen
// writes for every key type when given a passphrase) or a PKCS#8
// EncryptedPrivateKeyInfo ("ENCRYPTED PRIVATE KEY", PEM-armoured or bare
// DER; what openssl pkcs8 -topk8, openssl genpkey and most tooling that
// exports a key from a PKCS#12 write). The caller owns the result and must
// call Destroy. Key types, the public-key cross-check, the error and
// ownership rules, and the [ErrHeapTransients] refusal of RSA and EC keys
// without [AllowHeapTransients] are [ParsePrivateKey]'s.
//
// For a PKCS#8 file the protection is PBES2 with PBKDF2 — under HMAC-SHA1
// (the format's default, which a file names by omitting the field),
// -SHA-224, -256, -384, -512, -512/224 or -512/256, up to
// [MaxPBKDF2Iterations] — and AES-128, -192 or -256 in CBC mode. The
// scrypt KDF and the AES-GCM schemes return an error wrapping
// [ErrUnsupportedKey]; PBES1, the PKCS#12 PBEs, and PBES2 over DES, 3DES or
// RC2 additionally wrap [ErrRetiredAlgorithm], as legacy PEM encryption
// does. PKCS#8 puts the key's algorithm inside the ciphertext, so unlike
// the OpenSSH path the RSA/EC gate can only be applied after the KDF has
// run; it is still applied before any signer is built. Everything else
// about the file — its structure, every parameter, the iteration count
// against the cap — is decided before the derivation. AES-CBC
// authenticates nothing, so after it the answer is the same one bit as
// below; what stays observable is success, and for an Ed25519 file without
// a public key (openssl writes v1) damage confined to the seed leaves a
// file that opens as a different key, exactly as it would through openssl.
//
// For an OpenSSH file the protection is KDF bcrypt, up to 2048 rounds (x/crypto's cap:
// cost is linear in rounds and the count comes from the file), under the
// ciphers ssh-keygen writes that this package runs: AES-128/192/256 in CTR
// or CBC mode, and chacha20-poly1305@openssh.com, whose authenticator
// follows the private block and whose 64-byte key material is two ChaCha20
// keys, only the first of which a key file uses. OpenSSH derives exactly
// key||IV from the KDF, so the key length is part of the format, not a
// local choice. Of these, x/crypto/ssh reads only aes256-ctr (ssh-keygen's
// default) and aes256-cbc. The other ciphers ssh-keygen -Z accepts — the
// AES-GCM pair and 3des-cbc — as well as legacy PEM Proc-Type / DEK-Info
// encryption return an error wrapping [ErrUnsupportedKey]; the legacy form
// additionally wraps [ErrRetiredAlgorithm], because that one is refused on
// purpose and will not arrive in a later release. A
// key that is not protected at all returns [ErrNotEncrypted]; a header that
// names a cipher without a KDF, or a KDF without a cipher, is malformed
// rather than either; an empty passphrase is an error before anything is
// read.
//
// Everything that can be decided without the passphrase is decided before
// the KDF runs: the container's structure and header, the KDF parameters,
// and — from the cleartext public-key block — the key type, so an
// unsupported type is [ErrUnsupportedKey] and an RSA or EC key on a build
// without GOEXPERIMENT=runtimesecret is [ErrHeapTransients] (absent
// [AllowHeapTransients]) at no bcrypt cost and before any of the key is
// handed to the standard library.
//
// After the KDF the outcome is binary. The AES modes are unauthenticated,
// so a file can be altered without the passphrase, and a parser that
// reported which check failed — the check integers, the padding, a length,
// the public half against the private — would tell whoever altered it
// where in the block the damage landed. This one reports every failure to
// turn the decrypted block into a key as one error, wrapping
// [x509.IncorrectPasswordError] (the value x/crypto/ssh returns for a wrong
// passphrase, so a caller migrating from ssh.ParseRawPrivateKeyWithPassphrase
// keeps its errors.Is check) and reading the same for a wrong passphrase as
// for a corrupt file. chacha20-poly1305@openssh.com is authenticated, so
// there a wrong passphrase and an altered file both fail at the tag, before
// anything is decrypted; that failure is reported as the same error, so the
// answer reads the same whichever cipher the file names. What stays
// observable, for the AES modes, is success: damage confined to the
// comment, which no reader validates, leaves a key that opens — here as in
// OpenSSH. One cost of the single answer: a failure to lock memory for the
// key's own buffer at that point is reported as this error too;
// [ParsePrivateKey] on the unprotected form of the same key names it.
//
// What touches the heap: everything ParsePrivateKey's doc lists, plus, for
// the AES modes, the key schedule crypto/aes allocates — wiped through the
// type's unexported fields before return, and if that wipe cannot locate
// the schedule on the running toolchain the call fails rather than leave it
// behind. The chacha20-poly1305 core is written out in this package and
// allocates nothing. The KDF's working state (for bcrypt the Blowfish
// schedule and both SHA-512 outputs, about 4 KiB; for PBKDF2 the padded
// keys, the running blocks and the hash inputs, under 1 KiB), the derived
// key and IV, and the cipher's scratch live in one SecureBuffer for the
// call. data and passphrase are the caller's: neither is wiped nor retained.
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
// does and classifies what it finds: an OpenSSH container and a PKCS#8
// EncryptedPrivateKeyInfo are opened, each by its own parser; every other
// shape is named as unsupported or as not encrypted. The container goes
// into a SecureBuffer before its header is read, because until the header
// is read it may be an unencrypted key.
func parseEncryptedPrivateKey(data, passphrase []byte, o options) (Signer, error) {
	var (
		blob  *secmem.SecureBuffer
		pkcs8 bool
		err   error
	)
	switch {
	case bytes.HasPrefix(data, opensshMagic):
		blob, err = copyToBuffer(data)
	case looksLikeDER(data):
		if err := derIsEncrypted(data); err != nil {
			return nil, err
		}
		pkcs8 = true
		blob, err = copyToBuffer(data)
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
			pkcs8 = true
			blob, err = decodePEMBody(body)
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
	if pkcs8 {
		return parsePKCS8Encrypted(blob, passphrase, o)
	}
	return parseOpenSSHEncrypted(blob, passphrase, o)
}

// derIsEncrypted classifies a bare DER SEQUENCE by its first element: an
// INTEGER (a version) opens every unencrypted structure ParsePrivateKey
// reads, and is ErrNotEncrypted here; a SEQUENCE (an AlgorithmIdentifier)
// opens EncryptedPrivateKeyInfo, which is the caller's to parse.
func derIsEncrypted(data []byte) error {
	in := cryptobyte.String(data)
	var seq, elem cryptobyte.String
	var tag cbasn1.Tag
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadAnyASN1Element(&elem, &tag) {
		return errMalformed
	}
	switch tag {
	case cbasn1.INTEGER:
		return ErrNotEncrypted
	case cbasn1.SEQUENCE:
		return nil
	}
	return errMalformed
}

// errOpenSSHDecrypt is the one error for everything that goes wrong after
// the private block is decrypted: the check integers disagreeing (the
// format's own passphrase test), a length that overruns, a bad pad, halves
// that disagree, a key type other than the public block's, a scalar out of
// range, an RSA key the standard library finds inconsistent. The AES modes
// carry no authenticator, so a wrong passphrase and a modified file produce
// the same kind of noise, and a parser that named which of those checks
// failed would tell whoever modified the file where in the block the damage
// landed. This is that check collapsed to one bit. It wraps
// x509.IncorrectPasswordError because a wrong passphrase is the common cause
// and the value is what x/crypto/ssh returns for it.
//
// chacha20-poly1305@openssh.com is authenticated, so there the same two
// causes fail earlier, at the tag inside opensshCrypt, and nothing is
// decrypted; that failure is folded into this error too, so the answer is
// one whichever cipher the file names.
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
// the passphrase — the header, what follows the private block, the KDF
// parameters, the key type and the heap-transients gate read off the
// cleartext public-key block — comes before the KDF runs, and every failure
// after it, an authenticator that does not verify or a decrypted block that
// does not become a key, is errOpenSSHDecrypt.
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
			// after the private block, and a file naming a cipher this
			// package does not run must be refused as that cipher, not as
			// trailing junk.
			return fmt.Errorf("%w: OpenSSH cipher %s", ErrUnsupportedKey, labelForError(h.cipher))
		}
		// What may follow the private block's string is the cipher's
		// authenticator, which OpenSSH places after the string rather than
		// inside it: 16 bytes for chacha20-poly1305, nothing for the AES
		// modes, which authenticate nothing. Anything else is trailing junk.
		if len(h.rest) != mode.tagLen() {
			return fmt.Errorf("%w: %d bytes follow the encrypted block, want %d for this cipher's authenticator", errMalformed, len(h.rest), mode.tagLen())
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
		// The padding granularity is the cipher's block: an AES block for
		// the AES modes, 8 bytes for chacha20-poly1305, as OpenSSH's
		// chachapoly cipher declares.
		if len(h.privBlock) == 0 || len(h.privBlock)%mode.blockLen() != 0 {
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
			if err := opensshCrypt(p, h.privBlock, h.rest, passphrase, salt, int(rounds), mode, true); err != nil {
				if errors.Is(err, x509.IncorrectPasswordError) {
					// chacha20-poly1305's authenticator did not verify: a
					// wrong passphrase or a modified file, which the tag
					// cannot tell apart, and the same one bit as every
					// failure after decryption below.
					return errOpenSSHDecrypt
				}
				// Not a verdict on the block: the KDF's bounds were checked
				// above, so this is the AES schedule wipe failing closed,
				// which the caller must see as itself.
				return err
			}
			var err error
			s, der, err = parseOpenSSHPrivateBlock(p, h.pubBlob, mode.blockLen(), o)
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
