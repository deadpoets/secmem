// parse.go is the ingress counterpart of MarshalOpenSSHPrivateKey: it turns a
// private-key file into one of this package's signers with the key material
// written straight into locked memory. The common route — pem.Decode, then
// ssh.ParseRawPrivateKey or crypto/x509 — materialises the whole key on the
// Go heap twice over (the decoded DER, then the parsed *PrivateKey with its
// big.Int limbs), and nothing can wipe either copy. Here the base64 body is
// decoded into a SecureBuffer, the structure is read in place with
// zero-copy cursors, and the secret is copied once, into the buffer the
// signer will own. The only key type that still touches the heap is an
// OpenSSH-format RSA key, whose CRT exponents have to be computed; see
// pkcs1DER in parse_openssh.go for exactly what and why.
package secmemcrypto

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/deadpoets/secmem"
)

// ErrEncryptedKey is returned by [ParsePrivateKey] for a passphrase-protected
// key: an OpenSSH file with a cipher or KDF other than "none", a PKCS#8
// "ENCRYPTED PRIVATE KEY" block, or a legacy PEM block with Proc-Type /
// DEK-Info headers. Decrypting one needs the passphrase and a KDF whose
// working state this package does not yet control (bcrypt_pbkdf for OpenSSH,
// PBKDF2/scrypt for PKCS#8), so it is refused rather than done leakily.
// Decrypt the file with ssh-keygen -p / openssl pkey first.
var ErrEncryptedKey = errors.New("secmemcrypto: private key is passphrase-protected")

// ErrUnsupportedKey is returned by [ParsePrivateKey] for a well-formed key of
// a kind this package has no signer for: DSA, FIDO (sk-*) keys, certificates,
// X25519/X448 (agreement keys, not signers — see [NewX25519Key]), RSA-PSS
// parameterised PKCS#8, and curves other than P-224/256/384/521.
var ErrUnsupportedKey = errors.New("secmemcrypto: unsupported private key type")

// errMalformed is the inner error for every structural failure. It carries no
// detail on purpose: the detail would be bytes of a private-key file.
var errMalformed = errors.New("malformed private key")

// Signer is what every signing key type in this package satisfies:
// [Ed25519Signer], [ECDSASigner] and [RSASigner]. It is the static type
// [ParsePrivateKey] returns; type-switch on it when the algorithm matters.
type Signer interface {
	crypto.Signer
	// Destroy wipes and releases the key material. Idempotent.
	Destroy() error
}

var (
	_ Signer = (*Ed25519Signer)(nil)
	_ Signer = (*ECDSASigner)(nil)
	_ Signer = (*RSASigner)(nil)
)

// ParsePrivateKey parses an unencrypted private key and returns a signer that
// holds it in a [secmem.SecureBuffer]. The caller owns the result and must
// call Destroy.
//
// Accepted encodings, PEM-armoured or as raw bytes:
//   - OpenSSH ("OPENSSH PRIVATE KEY", ssh-keygen's default since 7.8) holding
//     an ssh-ed25519, ecdsa-sha2-nistp{256,384,521}, or ssh-rsa key;
//   - PKCS#8 ("PRIVATE KEY") holding an RSA, EC (named curve), or Ed25519 key;
//   - SEC 1 ("EC PRIVATE KEY") with a named curve;
//   - PKCS#1 ("RSA PRIVATE KEY").
//
// Where the file carries the public key as well (every OpenSSH file, SEC 1
// and PKCS#8 v2 optionally), it is checked against the one derived from the
// private half and a mismatch is an error. Passphrase-protected keys return
// an error wrapping [ErrEncryptedKey]; other kinds, [ErrUnsupportedKey].
// Errors never quote the input.
//
// What touches the heap: the PEM type, the algorithm identifiers, the public
// key, and the returned error — none secret. The decoded key structure lives
// in a SecureBuffer for the duration of the call and is wiped before return;
// the seed, scalar, or DER the signer keeps is copied into it directly. The
// one exception is an OpenSSH-format RSA key: its CRT exponents dp and dq are
// not in the file and are computed with math/big on the heap, then wiped
// limb by limb; the standard library's own scratch for that arithmetic is
// out of reach and is left to [secmem.ScrubErr] (the whole parse runs inside
// one) and the collector. Every RSA key is additionally parsed once more by
// crypto/x509 inside [NewRSASigner], with the transient wiped as that
// function documents.
//
// data is the caller's: it is neither wiped nor retained. Read the file into a
// SecureBuffer with [secmem.NewBufferFromReader] and call this from inside its
// WithBytesErr, then Destroy it — or, for an ordinary []byte, wipe it with
// [secmem.SecureWipe] afterwards.
func ParsePrivateKey(data []byte) (Signer, error) {
	if len(data) == 0 {
		return nil, errors.New("secmemcrypto: parse private key: empty input")
	}
	var s Signer
	err := secmem.ScrubErr(func() error {
		var perr error
		s, perr = parsePrivateKey(data)
		return perr
	})
	if err != nil {
		return nil, fmt.Errorf("secmemcrypto: parse private key: %w", err)
	}
	return s, nil
}

//nolint:gochecknoglobals // immutable format constants and OIDs.
var (
	pemBegin       = []byte("-----BEGIN ")
	pemEnd         = []byte("-----END ")
	pemDashes      = []byte("-----")
	opensshMagic   = []byte("openssh-key-v1\x00")
	oidRSA         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidEd25519     = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidX25519      = asn1.ObjectIdentifier{1, 3, 101, 110}
	oidP224        = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidP256        = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384        = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidP521        = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// parsePrivateKey is ParsePrivateKey's body, run inside a Scrub window.
//
// Container detection, in order: the OpenSSH magic; a DER SEQUENCE whose
// length field spans exactly the input (so a text file that happens to
// start with '0', which is 0x30, is not mistaken for DER); and otherwise a
// PEM block anywhere in the input, as encoding/pem finds it — tools do write
// text before the block.
func parsePrivateKey(data []byte) (Signer, error) {
	switch {
	case bytes.HasPrefix(data, opensshMagic):
		blob, err := copyToBuffer(data)
		if err != nil {
			return nil, err
		}
		return parseOpenSSH(blob)
	case looksLikeDER(data):
		blob, err := copyToBuffer(data)
		if err != nil {
			return nil, err
		}
		return parseDER(blob)
	case bytes.Contains(data, pemBegin):
		typ, body, err := pemBlock(data)
		if err != nil {
			return nil, err
		}
		blob, err := decodePEMBody(body)
		if err != nil {
			return nil, err
		}
		switch string(typ) { // comparison only: no string is allocated
		case "OPENSSH PRIVATE KEY":
			return parseOpenSSH(blob)
		case "PRIVATE KEY":
			return parsePKCS8(blob)
		case "EC PRIVATE KEY":
			return parseSEC1(blob)
		case "RSA PRIVATE KEY":
			return rsaFromDER(blob)
		case "ENCRYPTED PRIVATE KEY":
			_ = blob.Destroy()
			return nil, ErrEncryptedKey
		default:
			_ = blob.Destroy()
			return nil, fmt.Errorf("%w: PEM block type %q", ErrUnsupportedKey, typ)
		}
	default:
		return nil, fmt.Errorf("%w: not PEM, OpenSSH, or DER", errMalformed)
	}
}

// looksLikeDER reports whether data is exactly one DER SEQUENCE: tag 0x30
// followed by a length field that accounts for the rest of the input. This
// is the shape of every bare-DER private key, and nothing else that is
// handed to ParsePrivateKey has it.
func looksLikeDER(data []byte) bool {
	if len(data) < 2 || data[0] != 0x30 {
		return false
	}
	var seq cryptobyte.String
	in := cryptobyte.String(data)
	return in.ReadASN1Element(&seq, cbasn1.SEQUENCE) && in.Empty()
}

// pemBlock finds the first PEM block in data and returns its type and its
// base64 body, aliasing data (line breaks included). It is a locator, not
// encoding/pem: it never decodes, because the decode has to land in locked
// memory (decodePEMBody). Encryption headers are detected here.
func pemBlock(data []byte) (typ, body []byte, err error) {
	i := bytes.Index(data, pemBegin)
	if i < 0 {
		return nil, nil, fmt.Errorf("%w: no PEM block", errMalformed)
	}
	rest := data[i+len(pemBegin):]
	j := bytes.Index(rest, pemDashes)
	if j < 0 {
		return nil, nil, fmt.Errorf("%w: unterminated PEM header", errMalformed)
	}
	typ = rest[:j] // the block label, aliasing data; compared, never copied
	rest = rest[j+len(pemDashes):]
	rest, ok := nextLine(rest)
	if !ok {
		return nil, nil, fmt.Errorf("%w: truncated PEM block", errMalformed)
	}

	// RFC 1421 headers: "Name: value" lines, terminated by a blank line. A
	// base64 line never contains ':', so the first line without one is the
	// body. Only two headers are meaningful — both mean encryption.
	encrypted := false
	headers := 0
	for {
		line, after, ok := splitLine(rest)
		if !ok {
			return nil, nil, fmt.Errorf("%w: truncated PEM block", errMalformed)
		}
		if k := bytes.IndexByte(line, ':'); k >= 0 {
			name := bytes.TrimSpace(line[:k])
			if bytes.EqualFold(name, []byte("Proc-Type")) || bytes.EqualFold(name, []byte("DEK-Info")) {
				encrypted = true
			}
			headers++
			rest = after
			continue
		}
		if headers > 0 && len(bytes.TrimSpace(line)) == 0 {
			rest = after // the blank line closing the header block
		}
		break
	}
	if encrypted {
		return nil, nil, ErrEncryptedKey
	}
	if headers > 0 {
		return nil, nil, fmt.Errorf("%w: PEM headers", ErrUnsupportedKey)
	}

	e := bytes.Index(rest, pemEnd)
	if e < 0 {
		return nil, nil, fmt.Errorf("%w: no PEM footer", errMalformed)
	}
	body = rest[:e]
	footer := rest[e+len(pemEnd):]
	if !bytes.HasPrefix(footer, typ) || !bytes.HasPrefix(footer[len(typ):], pemDashes) {
		return nil, nil, fmt.Errorf("%w: PEM footer does not match header", errMalformed)
	}
	return typ, body, nil
}

// splitLine returns the first line of b (without its terminator) and what
// follows. ok is false when b has no line terminator at all.
func splitLine(b []byte) (line, after []byte, ok bool) {
	k := bytes.IndexByte(b, '\n')
	if k < 0 {
		return nil, nil, false
	}
	return bytes.TrimRight(b[:k], "\r"), b[k+1:], true
}

// nextLine skips the remainder of the current line.
func nextLine(b []byte) ([]byte, bool) {
	_, after, ok := splitLine(b)
	return after, ok
}

// decodePEMBody base64-decodes a PEM body straight into a new SecureBuffer,
// sized to the encoding's upper bound and truncated to the decoded length.
// The standard decoder skips line breaks, so the body is passed as it sits
// in the file. On any failure the buffer is destroyed (which wipes whatever
// partial output the decoder produced).
func decodePEMBody(body []byte) (*secmem.SecureBuffer, error) {
	body = bytes.TrimSpace(body)
	n := base64.StdEncoding.DecodedLen(len(body))
	if n == 0 {
		return nil, fmt.Errorf("%w: empty PEM body", errMalformed)
	}
	blob, err := secmem.NewEmptyBuffer(n)
	if err != nil {
		return nil, fmt.Errorf("allocate key buffer: %w", err)
	}
	var m int
	err = blob.WithBytesErr(func(dst []byte) error {
		var derr error
		m, derr = base64.StdEncoding.Decode(dst, body)
		return derr
	})
	if err == nil && m == 0 {
		err = fmt.Errorf("%w: empty PEM body", errMalformed)
	}
	if err == nil {
		err = blob.Truncate(m)
	}
	if err != nil {
		_ = blob.Destroy()
		if errors.Is(err, errMalformed) {
			return nil, err
		}
		// A base64 CorruptInputError names an offset, not content; it is
		// safe to surface but callers match on errMalformed, so wrap that.
		return nil, fmt.Errorf("%w: %w", errMalformed, err)
	}
	return blob, nil
}

// copyToBuffer copies raw key bytes into a new SecureBuffer. The source is
// the caller's and is left alone (see ParsePrivateKey).
func copyToBuffer(data []byte) (*secmem.SecureBuffer, error) {
	blob, err := secmem.NewEmptyBuffer(len(data))
	if err != nil {
		return nil, fmt.Errorf("allocate key buffer: %w", err)
	}
	if _, err := blob.CopyIn(data, 0); err != nil {
		_ = blob.Destroy()
		return nil, err
	}
	return blob, nil
}

// parseDER tells the three bare-DER shapes apart by the element that follows
// the version integer — SEQUENCE (AlgorithmIdentifier) for PKCS#8, OCTET
// STRING (the scalar) for SEC 1, INTEGER (the modulus) for PKCS#1 — and
// dispatches. The version alone cannot: PKCS#8 v2 and SEC 1 both use 1.
func parseDER(blob *secmem.SecureBuffer) (Signer, error) {
	var next cbasn1.Tag
	err := blob.WithBytesErr(func(der []byte) error {
		in := cryptobyte.String(der)
		var seq cryptobyte.String
		var version int64
		if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1Integer(&version) {
			return errMalformed
		}
		var elem cryptobyte.String
		if !seq.ReadAnyASN1Element(&elem, &next) {
			return errMalformed
		}
		return nil
	})
	if err != nil {
		_ = blob.Destroy()
		return nil, err
	}
	switch next {
	case cbasn1.SEQUENCE:
		return parsePKCS8(blob)
	case cbasn1.OCTET_STRING:
		return parseSEC1(blob)
	case cbasn1.INTEGER:
		return rsaFromDER(blob)
	default:
		_ = blob.Destroy()
		return nil, fmt.Errorf("%w: unrecognised DER structure", errMalformed)
	}
}

// rsaFromDER hands a PKCS#1 or PKCS#8 RSA DER buffer to NewRSASigner, which
// takes ownership; the DER is the durable form an RSASigner keeps.
func rsaFromDER(blob *secmem.SecureBuffer) (Signer, error) {
	s, err := NewRSASigner(blob)
	if err != nil {
		_ = blob.Destroy()
		return nil, err
	}
	return s, nil
}

// parsePKCS8 reads a PKCS#8 PrivateKeyInfo (RFC 5208, v2 per RFC 5958) in
// place. RSA keys keep the whole buffer (NewRSASigner wants the DER); EC and
// Ed25519 keys have their scalar or seed copied into a fresh buffer and the
// structure is then destroyed.
func parsePKCS8(blob *secmem.SecureBuffer) (Signer, error) {
	var (
		s     Signer
		isRSA bool
	)
	err := blob.WithBytesErr(func(der []byte) error {
		in := cryptobyte.String(der)
		var seq cryptobyte.String
		if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() {
			return errMalformed
		}
		var version int64
		if !seq.ReadASN1Integer(&version) || version < 0 || version > 1 {
			return errMalformed
		}
		var alg cryptobyte.String
		var oid asn1.ObjectIdentifier
		if !seq.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) {
			return errMalformed
		}
		var priv cryptobyte.String
		if !seq.ReadASN1(&priv, cbasn1.OCTET_STRING) {
			return errMalformed
		}
		// attributes [0] IMPLICIT Attributes OPTIONAL — skipped.
		if !seq.SkipOptionalASN1(cbasn1.Tag(0).ContextSpecific().Constructed()) {
			return errMalformed
		}
		// publicKey [1] IMPLICIT BIT STRING OPTIONAL (v2 only).
		var pub []byte
		var pubBits cryptobyte.String
		var havePub bool
		if !seq.ReadOptionalASN1(&pubBits, &havePub, cbasn1.Tag(1).ContextSpecific()) {
			return errMalformed
		}
		if havePub {
			if version != 1 {
				return errMalformed
			}
			var padBits uint8
			if !pubBits.ReadUint8(&padBits) || padBits != 0 {
				return errMalformed
			}
			pub = pubBits
		}

		switch {
		case oid.Equal(oidRSA):
			isRSA = true
			return nil
		case oid.Equal(oidECPublicKey):
			var curveOID asn1.ObjectIdentifier
			if !alg.ReadASN1ObjectIdentifier(&curveOID) {
				return fmt.Errorf("%w: EC key without a named curve", ErrUnsupportedKey)
			}
			curve := curveFromOID(curveOID)
			if curve == nil {
				return fmt.Errorf("%w: EC curve %v", ErrUnsupportedKey, curveOID)
			}
			var err error
			s, err = ecdsaFromSEC1(priv, curve, pub)
			return err
		case oid.Equal(oidEd25519):
			// CurvePrivateKey ::= OCTET STRING — the seed, wrapped once more.
			var seed cryptobyte.String
			if !priv.ReadASN1(&seed, cbasn1.OCTET_STRING) || !priv.Empty() {
				return errMalformed
			}
			var err error
			s, err = ed25519FromSeed(seed, pub)
			return err
		case oid.Equal(oidX25519):
			return fmt.Errorf("%w: X25519 is an agreement key, not a signer (use NewX25519Key)", ErrUnsupportedKey)
		default:
			return fmt.Errorf("%w: PKCS#8 algorithm %v", ErrUnsupportedKey, oid)
		}
	})
	if err != nil {
		_ = blob.Destroy()
		return nil, err
	}
	if isRSA {
		return rsaFromDER(blob)
	}
	_ = blob.Destroy()
	return s, nil
}

// parseSEC1 reads a bare SEC 1 ECPrivateKey; the curve must be named in its
// parameters field.
func parseSEC1(blob *secmem.SecureBuffer) (Signer, error) {
	var s Signer
	err := blob.WithBytesErr(func(der []byte) error {
		var err error
		s, err = ecdsaFromSEC1(der, nil, nil)
		return err
	})
	_ = blob.Destroy()
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ecdsaFromSEC1 parses an ECPrivateKey (RFC 5915) from der. curve is the
// curve named by an enclosing PKCS#8 AlgorithmIdentifier, or nil when the
// structure stands alone and must name its own; when both name one they must
// agree. outerPub is the PKCS#8 v2 public key, if any; it and the SEC 1
// publicKey field are both checked against the derived public key.
func ecdsaFromSEC1(der []byte, curve elliptic.Curve, outerPub []byte) (Signer, error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	var version int64
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() || !seq.ReadASN1Integer(&version) || version != 1 {
		return nil, errMalformed
	}
	var d cryptobyte.String
	if !seq.ReadASN1(&d, cbasn1.OCTET_STRING) {
		return nil, errMalformed
	}
	var params cryptobyte.String
	var haveParams bool
	if !seq.ReadOptionalASN1(&params, &haveParams, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, errMalformed
	}
	if haveParams {
		var curveOID asn1.ObjectIdentifier
		if !params.ReadASN1ObjectIdentifier(&curveOID) {
			return nil, fmt.Errorf("%w: EC parameters are not a named curve", ErrUnsupportedKey)
		}
		named := curveFromOID(curveOID)
		if named == nil {
			return nil, fmt.Errorf("%w: EC curve %v", ErrUnsupportedKey, curveOID)
		}
		if curve != nil && curve != named {
			return nil, fmt.Errorf("%w: curve in PKCS#8 header disagrees with SEC 1 parameters", errMalformed)
		}
		curve = named
	}
	if curve == nil {
		return nil, fmt.Errorf("%w: EC key names no curve", ErrUnsupportedKey)
	}
	var pubWrap cryptobyte.String
	var havePub bool
	if !seq.ReadOptionalASN1(&pubWrap, &havePub, cbasn1.Tag(1).ContextSpecific().Constructed()) {
		return nil, errMalformed
	}
	var innerPub []byte
	if havePub && !pubWrap.ReadASN1BitStringAsBytes(&innerPub) {
		return nil, errMalformed
	}
	s, err := ecdsaFromScalar(d, curve, innerPub)
	if err != nil {
		return nil, err
	}
	if outerPub != nil && !ecdsaPubMatches(s, outerPub) {
		_ = s.Destroy()
		return nil, fmt.Errorf("%w: public key does not match private key", errMalformed)
	}
	return s, nil
}

// ecdsaFromScalar copies a big-endian scalar into a fresh buffer, left-padded
// to the curve's fixed width (files may carry it with leading zeros or, in
// OpenSSH mpint form, a sign byte), builds the signer — NewECDSASigner
// validates the range and derives the public key — and, when pub is given,
// checks it against the derived one.
func ecdsaFromScalar(d []byte, curve elliptic.Curve, pub []byte) (*ECDSASigner, error) {
	for len(d) > 0 && d[0] == 0 {
		d = d[1:]
	}
	size := scalarSize(curve)
	if len(d) == 0 || len(d) > size {
		return nil, fmt.Errorf("%w: scalar out of range", errMalformed)
	}
	out, err := secmem.NewEmptyBuffer(size)
	if err != nil {
		return nil, fmt.Errorf("allocate scalar buffer: %w", err)
	}
	if _, err := out.CopyIn(d, size-len(d)); err != nil {
		_ = out.Destroy()
		return nil, err
	}
	s, err := NewECDSASigner(curve, out)
	if err != nil {
		_ = out.Destroy()
		return nil, err
	}
	if pub != nil && !ecdsaPubMatches(s, pub) {
		_ = s.Destroy()
		return nil, fmt.Errorf("%w: public key does not match private key", errMalformed)
	}
	return s, nil
}

// ecdsaPubMatches compares an encoded public point from the file with the
// signer's derived one. Uncompressed points compare byte for byte; a
// compressed point (rare in files, legal in SEC 1) is checked by x
// coordinate and y parity, without decoding it.
func ecdsaPubMatches(s *ECDSASigner, pub []byte) bool {
	derived := s.pubBytes // 0x04 || X || Y
	if len(pub) == 0 {
		return false
	}
	switch pub[0] {
	case 0x04:
		return bytes.Equal(pub, derived)
	case 0x02, 0x03:
		size := scalarSize(s.curve)
		if len(pub) != 1+size || len(derived) != 1+2*size {
			return false
		}
		yParity := derived[len(derived)-1] & 1
		return bytes.Equal(pub[1:], derived[1:1+size]) && pub[0]-0x02 == yParity
	default:
		return false
	}
}

// ed25519FromSeed copies a 32-byte seed into a fresh buffer and builds the
// signer, checking the file's public key (if any) against the derived one.
func ed25519FromSeed(seed, pub []byte) (*Ed25519Signer, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("%w: got %d, want 32", ErrBadSeedLength, len(seed))
	}
	out, err := secmem.NewEmptyBuffer(len(seed))
	if err != nil {
		return nil, fmt.Errorf("allocate seed buffer: %w", err)
	}
	if _, err := out.CopyIn(seed, 0); err != nil {
		_ = out.Destroy()
		return nil, err
	}
	s, err := NewEd25519Signer(out)
	if err != nil {
		_ = out.Destroy()
		return nil, err
	}
	if pub != nil && !bytes.Equal(pub, s.pubKey) {
		_ = s.Destroy()
		return nil, fmt.Errorf("%w: public key does not match private key", errMalformed)
	}
	return s, nil
}

// curveFromOID maps the four named-curve OIDs this package signs with; nil
// for anything else.
func curveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidP256):
		return elliptic.P256()
	case oid.Equal(oidP384):
		return elliptic.P384()
	case oid.Equal(oidP521):
		return elliptic.P521()
	case oid.Equal(oidP224):
		return elliptic.P224()
	}
	return nil
}
