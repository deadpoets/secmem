// parse_openssh.go reads the OpenSSH private-key container (PROTOCOL.key in
// openssh-portable) in place and, for RSA, assembles the PKCS#1 DER that
// RSASigner keeps — directly into locked memory. parse_encrypted.go opens
// the passphrase-protected form and feeds the decrypted block to the same
// private-block parser.

package secmemcrypto

import (
	"bytes"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/deadpoets/secmem"
)

// sshReader is a zero-copy cursor over the SSH wire encoding (RFC 4251 §5):
// uint32 big-endian, and string / mpint as uint32-length-prefixed bytes that
// alias the input.
type sshReader struct{ b []byte }

func (r *sshReader) uint32() (uint32, bool) {
	if len(r.b) < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v, true
}

func (r *sshReader) str() ([]byte, bool) {
	n, ok := r.uint32()
	if !ok || uint64(n) > uint64(len(r.b)) {
		return nil, false
	}
	s := r.b[:n]
	r.b = r.b[n:]
	return s, true
}

// opensshHeader is the outer container, every field aliasing the input.
// rest is whatever follows the private block: for an AEAD cipher the
// authenticator, which PROTOCOL.key places after the string rather than in
// it; for "none" and the AES modes, which have none, nothing at all — a
// non-empty rest there is trailing junk, and the callers refuse it once
// they know which cipher they are looking at.
type opensshHeader struct {
	cipher, kdf, kdfOpts []byte
	numKeys              uint32
	pubBlob, privBlock   []byte
	rest                 []byte
}

// readOpenSSHHeader reads the "openssh-key-v1" container's outer fields
// from b and checks that the fields are present and that the header agrees
// with itself about encryption — the cipher and the KDF are both "none" or
// neither is, and a "none" KDF carries no options. Which encryption, whether
// the key count is one, whether the private block is a multiple of the
// cipher's block size, and whether anything may follow it (see rest) are the
// caller's questions.
//
// The consistency rule matters to the two entry points more than it looks:
// a file naming aes256-ctr with KDF none, or none with bcrypt, is neither
// "passphrase-protected" nor "not protected", and without the rule each
// parser would send the caller to the other one. OpenSSH's own reader
// (sshkey.c) refuses a cipher without a KDF as an invalid format; refusing a
// KDF without a cipher, and options on a "none" KDF, is this parser's rule —
// the latter shared with x/crypto/ssh — adopted for the two entry points'
// sake.
func readOpenSSHHeader(b []byte) (opensshHeader, error) {
	var h opensshHeader
	if !bytes.HasPrefix(b, opensshMagic) {
		return h, errMalformed
	}
	r := sshReader{b[len(opensshMagic):]}
	var ok1, ok2, ok3, ok4, ok5, ok6 bool
	h.cipher, ok1 = r.str()
	h.kdf, ok2 = r.str()
	h.kdfOpts, ok3 = r.str() // empty for "none"; string salt | uint32 rounds for bcrypt
	h.numKeys, ok4 = r.uint32()
	h.pubBlob, ok5 = r.str()
	h.privBlock, ok6 = r.str()
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return h, errMalformed
	}
	h.rest = r.b
	cipherNone := string(h.cipher) == opensshCipherNone // comparison only: no string is allocated
	kdfNone := string(h.kdf) == opensshKDFNone
	if cipherNone != kdfNone {
		return h, fmt.Errorf("%w: OpenSSH cipher and KDF disagree about encryption", errMalformed)
	}
	if kdfNone && len(h.kdfOpts) != 0 {
		return h, fmt.Errorf("%w: KDF options with KDF none", errMalformed)
	}
	return h, nil
}

// errCheckMismatch is the private block's two check integers disagreeing:
// corruption in an unencrypted file, a wrong passphrase in an encrypted one.
// The encrypted path does not single it out: there every failure after
// decryption, this one included, is reported as errOpenSSHDecrypt
// (parse_encrypted.go), so nothing in the error says how far the block
// parsed.
var errCheckMismatch = fmt.Errorf("%w: check integers disagree", errMalformed)

// parseOpenSSH reads an unencrypted "openssh-key-v1" container held in blob
// and returns the signer. blob is destroyed on every path: the seed or
// scalar is copied out of it, and for RSA the DER is assembled into a
// separate buffer.
func parseOpenSSH(blob *secmem.SecureBuffer, o options) (Signer, error) {
	var (
		s   Signer
		der *secmem.SecureBuffer // RSA only: PKCS#1 DER built from the file's integers
	)
	err := blob.WithBytesErr(func(b []byte) error {
		h, err := readOpenSSHHeader(b)
		if err != nil {
			return err
		}
		if string(h.cipher) != opensshCipherNone { // the header guarantees the KDF agrees
			return ErrEncryptedKey
		}
		if len(h.rest) != 0 { // "none" carries no authenticator: the file ends with the block
			return fmt.Errorf("%w: trailing bytes after the OpenSSH container", errMalformed)
		}
		if h.numKeys != 1 {
			return fmt.Errorf("%w: OpenSSH file holds %d keys, want 1", ErrUnsupportedKey, h.numKeys)
		}
		// OpenSSH pads the plaintext block to the "none" cipher's 8-byte
		// block and refuses a block that is not a multiple of it.
		if len(h.privBlock) == 0 || len(h.privBlock)%opensshNoneBlock != 0 {
			return fmt.Errorf("%w: private block is not a multiple of the cipher block size", errMalformed)
		}
		s, der, err = parseOpenSSHPrivateBlock(h.privBlock, h.pubBlob, opensshNoneBlock, o)
		return err
	})
	_ = blob.Destroy()
	if err != nil {
		return nil, err
	}
	if der != nil {
		return rsaFromDER(der, o)
	}
	return s, nil
}

// parseOpenSSHPrivateBlock reads a plaintext private block (check1, check2,
// key type, the per-type fields, comment, padding) and builds the signer;
// for RSA it returns the assembled PKCS#1 DER buffer instead, for the caller
// to hand to NewRSASigner. pubBlob is the container's public-key block and
// blockSize the cipher's block size, which bounds the padding.
//
// The public-key block is compared field by field with the private block
// (OpenSSH itself does this on load), so a file whose halves disagree is
// rejected rather than yielding a signer whose Public() is not what the
// file advertises.
func parseOpenSSHPrivateBlock(privBlock, pubBlob []byte, blockSize int, o options) (Signer, *secmem.SecureBuffer, error) {
	var (
		s   Signer
		der *secmem.SecureBuffer
	)
	err := func() error {
		p := sshReader{privBlock}
		check1, ok1 := p.uint32()
		check2, ok2 := p.uint32()
		if !ok1 || !ok2 {
			return errMalformed
		}
		if check1 != check2 {
			// Compared before anything else is read: after a wrong
			// passphrase the rest of the block is noise whose lengths fail
			// in arbitrary ways, and the caller must see the passphrase
			// verdict, not one of those.
			return errCheckMismatch
		}
		keyType, ok3 := p.str()
		if !ok3 {
			return errMalformed
		}
		pub := sshReader{pubBlob}
		pubType, ok := pub.str()
		if !ok || !bytes.Equal(pubType, keyType) {
			return fmt.Errorf("%w: public and private key blocks disagree", errMalformed)
		}

		switch string(keyType) {
		case "ssh-ed25519":
			// string pub(32) | string priv(64 = seed || pub) | string comment | pad
			pk, ok1 := p.str()
			sk, ok2 := p.str()
			_, ok3 := p.str()
			if !ok1 || !ok2 || !ok3 || len(pk) != 32 || len(sk) != 64 {
				return errMalformed
			}
			if err := checkOpenSSHPadding(p.b, blockSize); err != nil {
				return err
			}
			pubKey, ok := pub.str()
			if !ok || !bytes.Equal(pubKey, pk) || !bytes.Equal(sk[32:], pk) {
				return fmt.Errorf("%w: public and private key blocks disagree", errMalformed)
			}
			var err error
			s, err = ed25519FromSeed(sk[:32], pk, o)
			return err

		case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
			// string curve | string Q | mpint d | string comment | pad
			curveName, ok1 := p.str()
			q, ok2 := p.str()
			d, ok3 := p.str()
			_, ok4 := p.str()
			if !ok1 || !ok2 || !ok3 || !ok4 {
				return errMalformed
			}
			if err := checkOpenSSHPadding(p.b, blockSize); err != nil {
				return err
			}
			if !bytes.Equal(curveName, keyType[len("ecdsa-sha2-"):]) {
				return errMalformed
			}
			var curve elliptic.Curve
			switch string(curveName) {
			case "nistp256":
				curve = elliptic.P256()
			case "nistp384":
				curve = elliptic.P384()
			case "nistp521":
				curve = elliptic.P521()
			default:
				return fmt.Errorf("%w: curve %s", ErrUnsupportedKey, labelForError(curveName))
			}
			pubCurve, ok1 := pub.str()
			pubQ, ok2 := pub.str()
			if !ok1 || !ok2 || !bytes.Equal(pubCurve, curveName) || !bytes.Equal(pubQ, q) {
				return fmt.Errorf("%w: public and private key blocks disagree", errMalformed)
			}
			var err error
			s, err = ecdsaFromScalar(d, curve, q, o)
			return err

		case "ssh-rsa":
			// mpint n | mpint e | mpint d | mpint iqmp | mpint p | mpint q | string comment | pad
			n, ok1 := p.str()
			e, ok2 := p.str()
			d, ok3 := p.str()
			iqmp, ok4 := p.str()
			prime1, ok5 := p.str()
			prime2, ok6 := p.str()
			_, ok7 := p.str()
			if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 {
				return errMalformed
			}
			if err := checkOpenSSHPadding(p.b, blockSize); err != nil {
				return err
			}
			pubE, ok1 := pub.str()
			pubN, ok2 := pub.str()
			if !ok1 || !ok2 || !bytes.Equal(stripZeros(pubE), stripZeros(e)) || !bytes.Equal(stripZeros(pubN), stripZeros(n)) {
				return fmt.Errorf("%w: public and private key blocks disagree", errMalformed)
			}
			var err error
			der, err = pkcs1DER(o.buf, n, e, d, prime1, prime2, iqmp)
			return err

		default:
			// keyType is the algorithm label, not secret — but it is the
			// file's to choose, so it is bounded on the way out.
			return fmt.Errorf("%w: OpenSSH key type %s", ErrUnsupportedKey, labelForError(keyType))
		}
	}()
	if err != nil {
		return nil, nil, err
	}
	return s, der, nil
}

// checkOpenSSHPadding verifies the private block's trailing pad: the bytes
// 1, 2, 3, … that bring the block up to a multiple of blockSize — 8 for
// "none" and chacha20-poly1305, 16 for the AES ciphers — so fewer than
// blockSize of them. Both
// the sequence and the length are checked: a writer never emits a whole
// block of padding, so a pad of blockSize bytes or more is not a padded
// block, whatever its bytes say. A wrong pad on an unencrypted file means
// corruption.
func checkOpenSSHPadding(pad []byte, blockSize int) error {
	if len(pad) >= blockSize {
		return fmt.Errorf("%w: bad padding", errMalformed)
	}
	for i, b := range pad {
		if int(b) != i+1 {
			return fmt.Errorf("%w: bad padding", errMalformed)
		}
	}
	return nil
}

// stripZeros returns b without leading zero bytes — the magnitude of an SSH
// mpint or a DER INTEGER, sign byte removed.
func stripZeros(b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

// bitLen is big.Int.BitLen for a stripped big-endian magnitude.
func bitLen(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	return (len(b)-1)*8 + bits.Len8(b[0])
}

// pkcs1DER assembles an RSAPrivateKey (RFC 8017 A.1.2) from the six integers
// an OpenSSH file carries and returns it in a new SecureBuffer, ready for
// NewRSASigner. The file does not hold the CRT exponents dp = d mod (p-1) and
// dq = d mod (q-1) that PKCS#1 requires, so those two are computed here with
// reduceMod (modreduce.go) over stack arrays inside the enclosing Scrub
// window — not with math/big, whose division scratch is pooled and returned
// unwiped. Everything else is written from the wire bytes straight into the
// buffer, and dp and dq are copied into their final position in it; no heap
// copy of any integer is made here, which the parser's allocation proof
// (parse_proof_test.go) now covers for this container too. The DER is
// byte-identical to x509.MarshalPKCS1PrivateKey's for the same key
// (parse_openssh_test.go pins that).
func pkcs1DER(b bufferOptions, n, e, d, p, q, iqmp []byte) (*secmem.SecureBuffer, error) {
	n, e, d, p, q, iqmp = stripZeros(n), stripZeros(e), stripZeros(d), stripZeros(p), stripZeros(q), stripZeros(iqmp)
	if len(n) == 0 || len(e) == 0 || len(d) == 0 || len(p) == 0 || len(q) == 0 || len(iqmp) == 0 {
		return nil, errMalformed
	}
	// The size rule every RSA key meets (rsabounds.go), applied here as
	// well as on the assembled DER because the arithmetic below runs first
	// and its stack arrays are sized by the prime cap. iqmp = q⁻¹ mod p is
	// below p by definition and so is bounded like one; without that it is
	// the one integer whose size the file could set freely, and the DER
	// below would be sized by it.
	if err := checkRSAIntegers(n, e, d, p, q, iqmp); err != nil {
		return nil, err
	}

	// p-1, q-1, dp and dq, each the width of its prime, on the stack.
	var pm1, qm1, dpBuf, dqBuf [rsaMaxPrimeBits / 8]byte
	defer func() {
		secmem.SecureWipe(pm1[:])
		secmem.SecureWipe(qm1[:])
		secmem.SecureWipe(dpBuf[:])
		secmem.SecureWipe(dqBuf[:])
	}()
	// A prime below 2 has no p-1 to reduce by; the standard library rejects
	// the key later anyway, but the reduction must not be asked for m = 0.
	if !decrementBE(pm1[:len(p)], p) || !decrementBE(qm1[:len(q)], q) ||
		len(stripZeros(pm1[:len(p)])) == 0 || len(stripZeros(qm1[:len(q)])) == 0 {
		return nil, errMalformed
	}
	if !reduceMod(dpBuf[:len(p)], d, pm1[:len(p)]) || !reduceMod(dqBuf[:len(q)], d, qm1[:len(q)]) {
		return nil, errMalformed
	}
	dp := stripZeros(dpBuf[:len(p)])
	dq := stripZeros(dqBuf[:len(q)])

	fields := [9]derInt{
		{}, // version 0
		{raw: n}, {raw: e}, {raw: d}, {raw: p}, {raw: q},
		{raw: dp}, {raw: dq}, {raw: iqmp},
	}
	content := 0
	for _, f := range fields {
		content += f.encodedLen()
	}
	total := 1 + derLengthLen(content) + content

	out, err := b.newEmptyBuffer(total)
	if err != nil {
		return nil, fmt.Errorf("allocate RSA key buffer: %w", err)
	}
	err = out.WithBytesErr(func(dst []byte) error {
		w := derWriter{b: dst}
		w.putByte(0x30)
		w.putLength(content)
		for _, f := range fields {
			w.putInteger(f)
		}
		if w.off != len(dst) {
			return fmt.Errorf("%w: internal DER size mismatch", errMalformed)
		}
		return nil
	})
	if err != nil {
		_ = out.Destroy()
		return nil, err
	}
	return out, nil
}

// derInt is one INTEGER of the RSAPrivateKey: a stripped big-endian
// magnitude aliasing the file or a stack array. The zero value encodes the
// integer 0.
type derInt struct {
	raw []byte
}

// magnitude returns the byte length of the value and whether its top bit is
// set (which DER's two's-complement INTEGER answers with a leading 0x00).
func (x derInt) magnitude() (nbytes int, high bool) {
	return len(x.raw), len(x.raw) > 0 && x.raw[0]&0x80 != 0
}

func (x derInt) contentLen() int {
	nbytes, high := x.magnitude()
	switch {
	case nbytes == 0:
		return 1
	case high:
		return nbytes + 1
	default:
		return nbytes
	}
}

func (x derInt) encodedLen() int {
	c := x.contentLen()
	return 1 + derLengthLen(c) + c
}

// derLengthLen is the size of a DER length field for a content length n:
// one byte in the short form (n < 0x80), otherwise one byte for the count
// plus the minimum number of octets that hold n — correct for any
// non-negative int, not only the lengths an RSA key can reach. n < 0 is the
// caller's error and is encoded as if it were 0.
func derLengthLen(n int) int {
	if n < 0x80 {
		return 1
	}
	return 1 + derLengthOctets(n)
}

// derLengthOctets is the number of octets in the long-form encoding of n,
// n >= 0x80: the minimal big-endian width of n, so 1 for n < 0x100, 2 for
// n < 0x10000, and so on up to 8 for the largest int.
func derLengthOctets(n int) int {
	k := 0
	for v := uint64(n); v != 0; v >>= 8 { //nolint:gosec // n >= 0x80 here, so the conversion is exact
		k++
	}
	return k
}

// derWriter writes into a fixed slice; sizes are computed beforehand so it
// never grows and never allocates.
type derWriter struct {
	b   []byte
	off int
}

func (w *derWriter) putByte(v byte) {
	w.b[w.off] = v
	w.off++
}

// putLength writes the DER length field for n in exactly derLengthLen(n)
// bytes: the short form below 0x80, otherwise 0x80 | k followed by the k
// octets of n, most significant first, with no leading zero octet.
func (w *derWriter) putLength(n int) {
	if n < 0x80 {
		w.putByte(byte(max(n, 0))) //nolint:gosec // 0 <= n < 0x80 on this branch
		return
	}
	k := derLengthOctets(n)
	w.putByte(0x80 | byte(k)) //nolint:gosec // k is 1..8
	for i := k - 1; i >= 0; i-- {
		w.putByte(byte(n >> (8 * i))) //nolint:gosec // one octet of n, most significant first
	}
}

func (w *derWriter) putInteger(x derInt) {
	w.putByte(0x02)
	w.putLength(x.contentLen())
	nbytes, high := x.magnitude()
	if nbytes == 0 {
		w.putByte(0)
		return
	}
	if high {
		w.putByte(0)
	}
	w.off += copy(w.b[w.off:], x.raw)
}
