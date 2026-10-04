// pbes2.go is ParsePrivateKeyWithPassphrase for PKCS#8 "ENCRYPTED PRIVATE
// KEY" files: EncryptedPrivateKeyInfo (RFC 5958 §3) protected with PBES2
// (RFC 8018 §6.2), which is what openssl pkcs8 -topk8 has written since
// 1.1.0 and what most tooling that exports a key from a PKCS#12 writes. The
// container is read in place from a SecureBuffer, the key is derived with
// this module's in-place PBKDF2 (pbkdf2_inplace.go) or scrypt
// (scrypt_inplace.go) into a locked scratch, the ciphertext is decrypted
// from the container into a second SecureBuffer under the same AES-CBC
// routine and round-key wipe the OpenSSH path uses, and the plaintext
// PrivateKeyInfo is handed to parsePKCS8, exactly as an unencrypted file's
// would be.
//
// What it opens: PBES2 with PBKDF2 under HMAC-SHA-1 (the format's DEFAULT
// PRF: the field is absent from such a file), -SHA-224, -256, -384, -512,
// -512/224 or -512/256, or with scrypt (RFC 7914: openssl pkcs8 -scrypt)
// inside MaxScryptMemory and MaxScryptWork, and aes-128, -192 or -256 in CBC
// mode. What it refuses as merely unimplemented (ErrUnsupportedKey): the
// AES-GCM schemes, and a PBKDF2 salt given as otherSource. What it refuses
// for good (ErrUnsupportedKey wrapping ErrRetiredAlgorithm): PBES1 and the
// PKCS#12 PBEs — the single-DES, 3DES and RC2 constructions over MD5 or
// SHA-1 that openssl pkcs8 wrote by default before 1.1.0 — and PBES2 over
// DES, 3DES or RC2. The remedy for all of those is one openssl command,
// which the error names.

package secmemcrypto

import (
	"crypto/aes"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/deadpoets/secmem"
)

// MaxPBKDF2Iterations is the largest PBKDF2 iteration count
// [ParsePrivateKeyWithPassphrase] will run for a PKCS#8 PBES2 file. A file
// naming more is refused with [ErrUnsupportedKey] before any derivation:
// the file names the cost, and without a cap an attacker-supplied count
// would tie the caller up rather than fail — the same reasoning as the
// bcrypt-rounds cap on OpenSSH files. openssl pkcs8 writes 2048 by default;
// current guidance (OWASP, 2023) is 600 000 for HMAC-SHA-256; this is a
// little over three times that. Measured on one core (BenchmarkPBKDF2InPlace)
// an iteration is about half a microsecond under HMAC-SHA-256 and about one
// under HMAC-SHA1 — each one-shot hash wipes its digest with the core's
// fenced, cache-flushing wipe, which is most of the cost — so a file at the
// cap takes one to two seconds to open, or to refuse a wrong passphrase.
const MaxPBKDF2Iterations = 2_000_000

// MaxScryptMemory is the most working memory, in bytes, that
// [ParsePrivateKeyWithPassphrase] will lock to run scrypt for a PKCS#8
// PBES2 file. The file names scrypt's N, r and p, and they are a demand for
// memory before they are a cost in time: the derivation holds
// 128·r·(N + 2·p + 2) bytes — the array V of N blocks, the two blocks it
// mixes, the p blocks PBKDF2 expands the passphrase into, and the copy of
// those the second PBKDF2 hashes. A file whose parameters come to more is
// refused with [ErrUnsupportedKey] before any derivation, as one over
// [MaxPBKDF2Iterations] is. What the call locks for the derivation is that
// figure plus under 2 KiB of fixed state, so this is also, to within a few
// pages, the budget a process opening such files must have: see
// [secmem.EnsureMemlockLimit].
//
// openssl pkcs8 -scrypt writes N=16384, r=8, p=1 — 16 MiB — and will itself
// neither write nor open parameters past 32 MiB. This is twice that, and
// the same 64 MiB as [Argon2Memory]: at r=8 it admits N up to 32768, which
// is what x/crypto/scrypt's documentation recommends and OpenSSL refuses.
const MaxScryptMemory = 64 << 20

// MaxScryptWork is the largest scrypt cost N·r·p
// [ParsePrivateKeyWithPassphrase] will run for a PKCS#8 PBES2 file; a file
// naming more is refused with [ErrUnsupportedKey] before any derivation.
// [MaxScryptMemory] alone does not bound the time: p multiplies the work
// and adds only 256·r bytes each, so parameters inside the memory cap can
// still ask for the better part of an hour. The memory-hard step is
// proportional to N·r·p — 4·N·r·p Salsa20/8 cores — and openssl's default
// is 131072; this is thirty-two times that. Measured on one core
// (BenchmarkScryptInPlace) a unit is about 0.17 microseconds, so a file
// that reaches the cap as a writer would, through N or a modest p, takes
// about 0.7 seconds to open, or to refuse a wrong passphrase.
//
// The most the two caps leave reachable is about three times that. N·r·p
// does not count scrypt's first PBKDF2, which fills the p blocks with one
// HMAC for every 32 bytes: a cost in r·p alone, which only the memory cap
// bounds, at 32 MiB of blocks. N=16, r=1, p=262135 is exactly at
// [MaxScryptMemory] and within 144 of this cap, and under the longest salt
// the parser reads it takes a little over two seconds
// (BenchmarkScryptInPlace_BothCaps) — the same order as a file at
// [MaxPBKDF2Iterations].
const MaxScryptWork = 1 << 22

// maxPBES2Salt bounds the KDF salt a file carries, PBKDF2's or scrypt's. It
// sizes the locked working region, so a hostile length would be a
// locked-memory demand rather than a cost; every writer uses 8 or 16 bytes.
const maxPBES2Salt = 1024

// OIDs of PBES2 and its parts (RFC 8018 §A; the AES identifiers from
// RFC 3565 / NIST's CSOR arc), and of the constructions refused by name.
var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}

	// The PRFs of RFC 8018 §B.1.1: hmacWithSHA1 .. hmacWithSHA512-256,
	// all under the digestAlgorithm arc 1.2.840.113549.2.
	oidHMACArc = asn1.ObjectIdentifier{1, 2, 840, 113549, 2}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	oidAES192GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 26}
	oidAES256GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}

	oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	oidRC2CBC     = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 2}
	oidDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}

	// PBES1 (RFC 8018 §A.3) and the PKCS#12 PBEs (RFC 7292 §C) live under
	// these two arcs; the members are checked by their last component.
	oidPBES1Arc     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5}
	oidPKCS12PBEArc = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1}
)

// The two refusals that carry ErrRetiredAlgorithm here. Like errLegacyPEM
// they are built once, with the remedy in them.
var (
	errRetiredPBE = fmt.Errorf("%w: PKCS#8 PBES1 / PKCS#12 password-based encryption (MD5 or SHA-1 with DES, 3DES or RC2); re-encrypt it with openssl pkcs8 -topk8 -v2 aes-256-cbc", ErrRetiredAlgorithm)

	errRetiredPBES2Cipher = fmt.Errorf("%w: PBES2 over DES, 3DES or RC2; re-encrypt it with openssl pkcs8 -topk8 -v2 aes-256-cbc", ErrRetiredAlgorithm)
)

// errPBES2Decrypt is the one error for everything that goes wrong after the
// ciphertext is decrypted: a bad PKCS#7 pad, a plaintext that is not a
// PrivateKeyInfo, a scalar out of range, an RSA key the standard library
// finds inconsistent, halves that disagree. AES-CBC carries no
// authenticator, so a wrong passphrase and a modified file produce the same
// kind of noise, and naming which check failed would tell whoever modified
// the file where the damage landed — errOpenSSHDecrypt's argument, and the
// same one bit. It wraps x509.IncorrectPasswordError for the same reason:
// a wrong passphrase is the common cause, and the value is what
// x/crypto/ssh returns for it.
var errPBES2Decrypt = fmt.Errorf("PKCS#8 encrypted key did not decrypt to a valid key (wrong passphrase or corrupt file): %w", x509.IncorrectPasswordError)

// encryptedPKCS8Error is ParsePrivateKey's answer for an EncryptedPrivateKeyInfo
// it will not open: ErrEncryptedKey, carrying ErrRetiredAlgorithm and the
// remedy when the file names a construction refused for good — so the plain
// entry point says the same thing about such a file as the passphrase one,
// as it does for legacy PEM. Only the algorithm identifiers are read; a
// file that is malformed past them is still just "encrypted" here, and the
// passphrase entry point is where the shape is judged.
func encryptedPKCS8Error(der []byte) error {
	in := cryptobyte.String(der)
	var seq, alg, params, kdf, scheme cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) {
		return ErrEncryptedKey
	}
	switch {
	case oidIsRetiredPBE(oid):
		return fmt.Errorf("%w: %w", ErrEncryptedKey, errRetiredPBE)
	case !oid.Equal(oidPBES2):
		return ErrEncryptedKey
	}
	if !alg.ReadASN1(&params, cbasn1.SEQUENCE) || !params.ReadASN1(&kdf, cbasn1.SEQUENCE) ||
		!params.ReadASN1(&scheme, cbasn1.SEQUENCE) || !scheme.ReadASN1ObjectIdentifier(&oid) {
		return ErrEncryptedKey
	}
	if oid.Equal(oidDESEDE3CBC) || oid.Equal(oidRC2CBC) || oid.Equal(oidDESCBC) {
		return fmt.Errorf("%w: %w", ErrEncryptedKey, errRetiredPBES2Cipher)
	}
	return ErrEncryptedKey
}

// pbes2File is what readPBES2 takes from an EncryptedPrivateKeyInfo: the
// KDF's parameters — PBKDF2's PRF and iteration count, or scrypt's N, r and
// p — the key length the scheme fixes, and the salt, IV and ciphertext,
// which alias the container and live only as long as its borrow.
type pbes2File struct {
	scrypt  bool // the KDF is scrypt: n, r and p apply; otherwise prf and iter
	prf     inPlaceHash
	iter    int
	n, r, p int
	keyLen  int
	salt    []byte
	iv      []byte
	ct      []byte
}

// readPBES2 reads an EncryptedPrivateKeyInfo in place and decides every
// refusal that needs no passphrase: the structure, the algorithm and every
// parameter in it, the iteration cap or scrypt's memory and work caps, the
// salt's form and length, and the ciphertext's length against the block
// size. Nothing here costs a derivation, and a file refused here has none
// of its key touched.
//
//	EncryptedPrivateKeyInfo ::= SEQUENCE {
//	  encryptionAlgorithm  AlgorithmIdentifier,   -- id-PBES2
//	  encryptedData        OCTET STRING }
//	PBES2-params ::= SEQUENCE {
//	  keyDerivationFunc    AlgorithmIdentifier,   -- id-PBKDF2 or id-scrypt
//	  encryptionScheme     AlgorithmIdentifier }  -- an AES-CBC OID, IV as parameter
//
// The KDF's own parameters are readPBKDF2Params' and readScryptParams'.
func readPBES2(der []byte) (pbes2File, error) {
	var f pbes2File
	in := cryptobyte.String(der)
	var seq, alg, ct cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() || !seq.ReadASN1(&alg, cbasn1.SEQUENCE) {
		return f, errMalformed
	}
	var oid asn1.ObjectIdentifier
	if !alg.ReadASN1ObjectIdentifier(&oid) {
		return f, errMalformed
	}
	if !seq.ReadASN1(&ct, cbasn1.OCTET_STRING) || !seq.Empty() {
		return f, errMalformed
	}
	switch {
	case oid.Equal(oidPBES2):
	case oidIsRetiredPBE(oid):
		return f, fmt.Errorf("%w: %w", ErrUnsupportedKey, errRetiredPBE)
	default:
		return f, fmt.Errorf("%w: PKCS#8 encryption algorithm %v", ErrUnsupportedKey, oid)
	}
	var params, kdf, scheme cryptobyte.String
	if !alg.ReadASN1(&params, cbasn1.SEQUENCE) || !alg.Empty() ||
		!params.ReadASN1(&kdf, cbasn1.SEQUENCE) || !params.ReadASN1(&scheme, cbasn1.SEQUENCE) || !params.Empty() {
		return f, errMalformed
	}

	// The encryption scheme first: it fixes the key length that the KDF
	// parameters' optional keyLength is then checked against.
	if !scheme.ReadASN1ObjectIdentifier(&oid) {
		return f, errMalformed
	}
	switch {
	case oid.Equal(oidAES128CBC):
		f.keyLen = 16
	case oid.Equal(oidAES192CBC):
		f.keyLen = 24
	case oid.Equal(oidAES256CBC):
		f.keyLen = 32
	case oid.Equal(oidAES128GCM), oid.Equal(oidAES192GCM), oid.Equal(oidAES256GCM):
		return f, fmt.Errorf("%w: PBES2 scheme AES-GCM", ErrUnsupportedKey)
	case oid.Equal(oidDESEDE3CBC), oid.Equal(oidRC2CBC), oid.Equal(oidDESCBC):
		return f, fmt.Errorf("%w: %w", ErrUnsupportedKey, errRetiredPBES2Cipher)
	default:
		return f, fmt.Errorf("%w: PBES2 scheme %v", ErrUnsupportedKey, oid)
	}
	var iv cryptobyte.String
	if !scheme.ReadASN1(&iv, cbasn1.OCTET_STRING) || !scheme.Empty() || len(iv) != opensshAESBlock {
		return f, errMalformed
	}
	f.iv = iv

	if !kdf.ReadASN1ObjectIdentifier(&oid) {
		return f, errMalformed
	}
	switch {
	case oid.Equal(oidPBKDF2):
	case oid.Equal(oidScrypt):
		f.scrypt = true
	default:
		return f, fmt.Errorf("%w: PBES2 KDF %v", ErrUnsupportedKey, oid)
	}
	var kdfParams cryptobyte.String
	if !kdf.ReadASN1(&kdfParams, cbasn1.SEQUENCE) || !kdf.Empty() {
		return f, errMalformed
	}
	var err error
	if f.scrypt {
		err = readScryptParams(&f, kdfParams)
	} else {
		err = readPBKDF2Params(&f, kdfParams)
	}
	if err != nil {
		return f, err
	}

	if len(ct) == 0 || len(ct)%opensshAESBlock != 0 {
		return f, fmt.Errorf("%w: encrypted data is not a multiple of the cipher block size", errMalformed)
	}
	f.ct = ct
	return f, nil
}

// readPBKDF2Params reads PBKDF2's parameters (RFC 8018 §A.2) into f, whose
// keyLen the encryption scheme has already fixed.
//
//	PBKDF2-params ::= SEQUENCE {
//	  salt                 CHOICE { specified OCTET STRING, otherSource AlgorithmIdentifier },
//	  iterationCount       INTEGER (1..MAX),
//	  keyLength            INTEGER (1..MAX) OPTIONAL,
//	  prf                  AlgorithmIdentifier DEFAULT hmacWithSHA1 }
func readPBKDF2Params(f *pbes2File, kdfParams cryptobyte.String) error {
	var salt cryptobyte.String
	if kdfParams.PeekASN1Tag(cbasn1.SEQUENCE) {
		return fmt.Errorf("%w: PBKDF2 salt given as otherSource", ErrUnsupportedKey)
	}
	if !kdfParams.ReadASN1(&salt, cbasn1.OCTET_STRING) || len(salt) == 0 {
		return errMalformed
	}
	if len(salt) > maxPBES2Salt {
		return fmt.Errorf("%w: PBKDF2 salt of %d bytes exceeds %d", errMalformed, len(salt), maxPBES2Salt)
	}
	f.salt = salt
	iter, over, ok := readASN1Count(&kdfParams)
	if !ok || (!over && iter == 0) {
		return errMalformed
	}
	if over || iter > MaxPBKDF2Iterations {
		// The file names the cost; an oversized count would tie the
		// caller up for a very long time, not fail.
		return fmt.Errorf("%w: PBKDF2 iteration count exceeds the maximum %d this parser will run", ErrUnsupportedKey, MaxPBKDF2Iterations)
	}
	f.iter = iter
	// keyLength, if present, is redundant with the scheme; a file where the
	// two disagree was not written by anything this parser should trust.
	if kdfParams.PeekASN1Tag(cbasn1.INTEGER) {
		var keyLen int
		if !kdfParams.ReadASN1Integer(&keyLen) {
			return errMalformed
		}
		if keyLen != f.keyLen {
			return fmt.Errorf("%w: PBKDF2 keyLength disagrees with the encryption scheme", errMalformed)
		}
	}
	f.prf = hashSHA1 // the DEFAULT, which a writer using it omits
	var prf cryptobyte.String
	var havePRF bool
	if !kdfParams.ReadOptionalASN1(&prf, &havePRF, cbasn1.SEQUENCE) {
		return errMalformed
	}
	if havePRF {
		var oid asn1.ObjectIdentifier
		if !prf.ReadASN1ObjectIdentifier(&oid) || !prf.SkipOptionalASN1(cbasn1.NULL) || !prf.Empty() {
			return errMalformed
		}
		f.prf = prfByOID(oid)
		if f.prf == hashNone {
			return fmt.Errorf("%w: PBKDF2 PRF %v", ErrUnsupportedKey, oid)
		}
	}
	if !kdfParams.Empty() {
		return errMalformed
	}
	return nil
}

// readScryptParams reads scrypt's parameters (RFC 7914 §7) into f, whose
// keyLen the encryption scheme has already fixed, and decides everything
// about them: their shape, whether they are parameters scrypt is defined
// for, and whether this parser will run them.
//
//	scrypt-params ::= SEQUENCE {
//	  salt                      OCTET STRING,
//	  costParameter             INTEGER (1..MAX),   -- N
//	  blockSize                 INTEGER (1..MAX),   -- r
//	  parallelizationParameter  INTEGER (1..MAX),   -- p
//	  keyLength                 INTEGER (1..MAX) OPTIONAL }
func readScryptParams(f *pbes2File, kdfParams cryptobyte.String) error {
	var salt cryptobyte.String
	if !kdfParams.ReadASN1(&salt, cbasn1.OCTET_STRING) || len(salt) == 0 {
		return errMalformed
	}
	if len(salt) > maxPBES2Salt {
		return fmt.Errorf("%w: scrypt salt of %d bytes exceeds %d", errMalformed, len(salt), maxPBES2Salt)
	}
	f.salt = salt
	n, nOver, okN := readASN1Count(&kdfParams)
	r, rOver, okR := readASN1Count(&kdfParams)
	p, pOver, okP := readASN1Count(&kdfParams)
	if !okN || !okR || !okP || (!nOver && n == 0) || (!rOver && r == 0) || (!pOver && p == 0) {
		return errMalformed
	}
	// What scrypt is defined for (RFC 7914 §2): N a power of two greater
	// than 1, and below 2^(128·r/8) — which only r = 1 can bring within
	// reach of a count, and which OpenSSL enforces too. A file outside
	// either was not written by a working scrypt. An N too wide to read is
	// left to the memory cap below, which it necessarily exceeds.
	if !nOver && (n == 1 || n&(n-1) != 0) {
		return fmt.Errorf("%w: scrypt cost parameter N is not a power of two greater than 1", errMalformed)
	}
	if !nOver && !rOver && r == 1 && n >= 1<<16 {
		return fmt.Errorf("%w: scrypt cost parameter N is not below 2^(128*r/8)", errMalformed)
	}
	// The file names the memory and the time; see MaxScryptMemory and
	// MaxScryptWork. r is bounded first so the products cannot overflow:
	// past that check 128·r is at most the cap and the block count is under
	// 2^33, and past the memory check N, r and p are each under 2^20.
	//nolint:gosec // G115: readASN1Count returns counts in [0, 2^31).
	un, ur, up := uint64(n), uint64(r), uint64(p)
	if nOver || rOver || pOver || ur > MaxScryptMemory/128 || 128*ur*(un+2*up+2) > MaxScryptMemory {
		return fmt.Errorf("%w: scrypt parameters need more working memory than the %d bytes this parser will lock", ErrUnsupportedKey, MaxScryptMemory)
	}
	if un*ur*up > MaxScryptWork {
		return fmt.Errorf("%w: scrypt cost N*r*p exceeds the maximum %d this parser will run", ErrUnsupportedKey, MaxScryptWork)
	}
	f.n, f.r, f.p = n, r, p
	// keyLength, if present, is redundant with the scheme, as PBKDF2's is.
	if kdfParams.PeekASN1Tag(cbasn1.INTEGER) {
		var keyLen int
		if !kdfParams.ReadASN1Integer(&keyLen) {
			return errMalformed
		}
		if keyLen != f.keyLen {
			return fmt.Errorf("%w: scrypt keyLength disagrees with the encryption scheme", errMalformed)
		}
	}
	if !kdfParams.Empty() {
		return errMalformed
	}
	return nil
}

// readASN1Count reads a non-negative INTEGER as a count. over reports one
// that does not fit in 31 bits (an int on every platform), which the caller
// treats as exceeding its cap rather than as malformed: it is a well-formed
// integer the file is entitled to write, just not one this parser will run.
func readASN1Count(s *cryptobyte.String) (n int, over, ok bool) {
	var raw cryptobyte.String
	if !s.ReadASN1(&raw, cbasn1.INTEGER) || len(raw) == 0 || raw[0]&0x80 != 0 {
		return 0, false, false
	}
	// DER: a leading zero byte is allowed only to keep the top bit clear.
	if len(raw) > 1 && raw[0] == 0 && raw[1]&0x80 == 0 {
		return 0, false, false
	}
	if raw[0] == 0 {
		raw = raw[1:]
	}
	if len(raw) > 4 {
		return 0, true, true
	}
	var v uint64
	for _, b := range raw {
		v = v<<8 | uint64(b)
	}
	if v > math.MaxInt32 {
		return 0, true, true
	}
	return int(v), false, true
}

// prfByOID maps a PBKDF2 PRF identifier to the in-place hash that computes
// it: hmacWithSHA1 (7) .. hmacWithSHA512-256 (13) under the digestAlgorithm
// arc, RFC 8018 §B.1.1.
func prfByOID(oid asn1.ObjectIdentifier) inPlaceHash {
	if len(oid) != len(oidHMACArc)+1 || !oid[:len(oidHMACArc)].Equal(oidHMACArc) {
		return hashNone
	}
	switch oid[len(oidHMACArc)] {
	case 7:
		return hashSHA1
	case 8:
		return hashSHA224
	case 9:
		return hashSHA256
	case 10:
		return hashSHA384
	case 11:
		return hashSHA512
	case 12:
		return hashSHA512_224
	case 13:
		return hashSHA512_256
	}
	return hashNone
}

// oidIsRetiredPBE reports whether oid names one of the password-based
// encryption schemes refused for good: PBES1's six (pbeWithMD2AndDES-CBC,
// pbeWithMD2AndRC2-CBC, pbeWithMD5AndDES-CBC, pbeWithMD5AndRC2-CBC,
// pbeWithSHA1AndDES-CBC, pbeWithSHA1AndRC2-CBC: 1.2.840.113549.1.5.{1,4,3,6,10,11})
// and the PKCS#12 six (SHA-1 with 128- or 40-bit RC4, 3- or 2-key 3DES,
// 128- or 40-bit RC2: 1.2.840.113549.1.12.1.{1..6}). Every one of them
// derives its key with a single pass of MD2, MD5 or SHA-1 and encrypts with
// a cipher this module does not run, so there is nothing here to keep.
func oidIsRetiredPBE(oid asn1.ObjectIdentifier) bool {
	switch {
	case len(oid) == len(oidPBES1Arc)+1 && oid[:len(oidPBES1Arc)].Equal(oidPBES1Arc):
		switch oid[len(oidPBES1Arc)] {
		case 1, 3, 4, 6, 10, 11:
			return true
		}
	case len(oid) == len(oidPKCS12PBEArc)+1 && oid[:len(oidPKCS12PBEArc)].Equal(oidPKCS12PBEArc):
		last := oid[len(oidPKCS12PBEArc)]
		return last >= 1 && last <= 6
	}
	return false
}

// pbes2Decrypt derives the key from passphrase with the file's KDF and
// decrypts f.ct into dst, which must be len(f.ct) bytes. Every byte of
// secret state it creates — the derived key, the KDF's working region, the
// cipher's chaining blocks — is in one SecureBuffer allocated for the call
// and wiped before return; for a scrypt file that region is V and the rest
// of scryptRegionSize, up to MaxScryptMemory, and a host that will not lock
// that much fails the call here, as itself. The AES round keys, which
// crypto/aes puts on the heap, are wiped through aeswipe.go, whose failure
// is this function's failure. As in opensshCrypt, what the hashes' and
// AES's assembly leave in the vector registers is the caller's Scrub
// window's to clear.
func pbes2Decrypt(b bufferOptions, dst []byte, f pbes2File, passphrase []byte) error {
	kdfRegion := pbkdf2RegionSize(f.prf, len(f.salt))
	if f.scrypt {
		kdfRegion = scryptRegionSize(len(f.salt), f.n, f.r, f.p)
	}
	return withScratch(b, kdfRegion+f.keyLen+cipherScratch, func(mem []byte) (err error) {
		// The KDF's region leads: scrypt views it as 32-bit words, and the
		// start of the mapping is what is known to be aligned. Its capacity
		// stops where the key starts, so a KDF that slices past the region
		// it was sized for panics instead of running on into the key.
		region := mem[:kdfRegion:kdfRegion]
		key := mem[kdfRegion : kdfRegion+f.keyLen]
		cipherMem := mem[kdfRegion+f.keyLen:]
		if f.scrypt {
			scryptCompute(key, region, passphrase, f.salt, f.n, f.r, f.p)
		} else {
			pbkdf2Compute(f.prf, key, region, passphrase, f.salt, f.iter)
		}
		blk, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		defer func() {
			if werr := wipeAESBlock(blk); werr != nil {
				err = errors.Join(err, werr)
			}
		}()
		cbcDecrypt(blk, f.iv, dst, f.ct, cipherMem)
		return nil
	})
}

// pkcs7Unpad checks the PKCS#7 padding on a decrypted block-multiple p and
// returns the plaintext length. The check reads the whole last block
// whatever the pad byte says and reports one bit, so it does not leak
// which byte disagreed; the caller folds its failure into errPBES2Decrypt
// with every other post-decryption failure.
func pkcs7Unpad(p []byte) (int, bool) {
	n := len(p)
	padByte := p[n-1]
	pad := int(padByte)
	good := subtle.ConstantTimeLessOrEq(1, pad) & subtle.ConstantTimeLessOrEq(pad, opensshAESBlock)
	for i := 1; i <= opensshAESBlock; i++ {
		claimed := subtle.ConstantTimeLessOrEq(i, pad)
		good &= subtle.ConstantTimeByteEq(p[n-i], padByte) | (claimed ^ 1)
	}
	if good != 1 {
		return 0, false
	}
	return n - pad, true
}

// parsePKCS8Encrypted opens an EncryptedPrivateKeyInfo held in blob and
// returns the signer. blob is destroyed on every path.
//
// The ordering rule is parseOpenSSHEncrypted's: every refusal that needs no
// passphrase is decided in readPBES2, before the KDF runs, and every
// failure after it is errPBES2Decrypt. One thing the OpenSSH path decides
// before its KDF cannot be decided here: the key's type, and with it the
// heap-transients gate for RSA and EC keys. PKCS#8 puts the algorithm
// identifier inside the ciphertext, so the gate runs after decryption, in
// parsePKCS8 and the constructors it calls — still before any signer is
// built and before the standard library sees a byte of the key, which is
// what the gate is for. That refusal, and an algorithm this package has no
// signer for, are reported as themselves: both are reached only through a
// plaintext that parsed as a complete PrivateKeyInfo, which a wrong
// passphrase or a damaged file cannot produce, so neither says anything
// about where damage landed.
func parsePKCS8Encrypted(blob *secmem.SecureBuffer, passphrase []byte, o options) (Signer, error) {
	var (
		plain *secmem.SecureBuffer
		n     int
	)
	err := blob.WithBytesErr(func(b []byte) error {
		f, err := readPBES2(b)
		if err != nil {
			return err
		}
		plain, err = o.buf.newEmptyBuffer(len(f.ct))
		if err != nil {
			return fmt.Errorf("allocate key buffer: %w", err)
		}
		return plain.WithBytesErr(func(p []byte) error {
			if err := pbes2Decrypt(o.buf, p, f, passphrase); err != nil {
				// Not a verdict on the file: the parameters were checked
				// above, so this is the workspace failing to lock or the
				// AES schedule wipe failing closed, which the caller must
				// see as itself.
				return err
			}
			var ok bool
			if n, ok = pkcs7Unpad(p); !ok {
				return errPBES2Decrypt
			}
			return nil
		})
	})
	_ = blob.Destroy()
	if err == nil {
		err = plain.Truncate(n) // wipes the pad
	}
	if err != nil {
		if plain != nil {
			_ = plain.Destroy()
		}
		return nil, err
	}
	s, err := parsePKCS8(plain, o) // destroys plain, or keeps it for an RSA signer
	if err != nil {
		if errors.Is(err, ErrHeapTransients) || errors.Is(err, ErrUnsupportedKey) {
			return nil, err
		}
		return nil, errPBES2Decrypt
	}
	return s, nil
}
