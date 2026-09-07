// parse_openssh.go reads the OpenSSH private-key container (PROTOCOL.key in
// openssh-portable) in place and, for RSA, assembles the PKCS#1 DER that
// RSASigner keeps — directly into locked memory.
package secmemcrypto

import (
	"bytes"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"math/big"
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

// parseOpenSSH reads an "openssh-key-v1" container held in blob and returns
// the signer. blob is destroyed on every path: the seed or scalar is copied
// out of it, and for RSA the DER is assembled into a separate buffer.
//
// The public-key block at the front of the file is compared field by field
// with the private block (OpenSSH itself does this on load), so a file whose
// halves disagree is rejected rather than yielding a signer whose Public()
// is not what the file advertises.
func parseOpenSSH(blob *secmem.SecureBuffer) (Signer, error) {
	var (
		s   Signer
		der *secmem.SecureBuffer // RSA only: PKCS#1 DER built from the file's integers
	)
	err := blob.WithBytesErr(func(b []byte) error {
		if !bytes.HasPrefix(b, opensshMagic) {
			return errMalformed
		}
		r := sshReader{b[len(opensshMagic):]}
		cipher, ok1 := r.str()
		kdf, ok2 := r.str()
		_, ok3 := r.str() // KDF options: empty for "none"
		numKeys, ok4 := r.uint32()
		pubBlob, ok5 := r.str()
		privBlock, ok6 := r.str()
		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
			return errMalformed
		}
		if string(cipher) != "none" || string(kdf) != "none" {
			return ErrEncryptedKey
		}
		if numKeys != 1 {
			return fmt.Errorf("%w: OpenSSH file holds %d keys, want 1", ErrUnsupportedKey, numKeys)
		}

		p := sshReader{privBlock}
		check1, ok1 := p.uint32()
		check2, ok2 := p.uint32()
		keyType, ok3 := p.str()
		if !ok1 || !ok2 || !ok3 || check1 != check2 {
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
			if err := checkOpenSSHPadding(p.b); err != nil {
				return err
			}
			pubKey, ok := pub.str()
			if !ok || !bytes.Equal(pubKey, pk) || !bytes.Equal(sk[32:], pk) {
				return fmt.Errorf("%w: public and private key blocks disagree", errMalformed)
			}
			var err error
			s, err = ed25519FromSeed(sk[:32], pk)
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
			if err := checkOpenSSHPadding(p.b); err != nil {
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
				return fmt.Errorf("%w: curve %q", ErrUnsupportedKey, curveName)
			}
			pubCurve, ok1 := pub.str()
			pubQ, ok2 := pub.str()
			if !ok1 || !ok2 || !bytes.Equal(pubCurve, curveName) || !bytes.Equal(pubQ, q) {
				return fmt.Errorf("%w: public and private key blocks disagree", errMalformed)
			}
			var err error
			s, err = ecdsaFromScalar(d, curve, q)
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
			if err := checkOpenSSHPadding(p.b); err != nil {
				return err
			}
			pubE, ok1 := pub.str()
			pubN, ok2 := pub.str()
			if !ok1 || !ok2 || !bytes.Equal(stripZeros(pubE), stripZeros(e)) || !bytes.Equal(stripZeros(pubN), stripZeros(n)) {
				return fmt.Errorf("%w: public and private key blocks disagree", errMalformed)
			}
			var err error
			der, err = pkcs1DER(n, e, d, prime1, prime2, iqmp)
			return err

		default:
			// keyType is the algorithm label, not secret.
			return fmt.Errorf("%w: OpenSSH key type %q", ErrUnsupportedKey, keyType)
		}
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

// checkOpenSSHPadding verifies the private block's trailing pad: the bytes
// 1, 2, 3, … up to the cipher block size, which for "none" is 8. A wrong pad
// on an unencrypted file means corruption.
func checkOpenSSHPadding(pad []byte) error {
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

// Bounds mirrored from x/crypto/ssh's OpenSSH RSA parser: the modulus cap is
// OpenSSH's own maximum, the prime cap bounds the CRT arithmetic below, and
// the exponent rules reject values that would make that arithmetic or the
// later validation expensive or meaningless.
const (
	rsaMaxModulusBits  = 16384
	rsaMaxPrimeBits    = 8192
	rsaMaxExponentBits = 24
)

// pkcs1DER assembles an RSAPrivateKey (RFC 8017 A.1.2) from the six integers
// an OpenSSH file carries and returns it in a new SecureBuffer, ready for
// NewRSASigner. The file does not hold the CRT exponents dp = d mod (p-1) and
// dq = d mod (q-1) that PKCS#1 requires, so those two are computed with
// math/big: the operands and results are heap big.Ints, wiped limb by limb on
// return, while math/big's internal scratch is out of reach and is left to
// the enclosing Scrub window and the collector. Everything else is written
// from the wire bytes straight into the buffer, and dp and dq are filled into
// their final position in it (FillBytes), so no further heap copy of any
// integer is made here. The DER is byte-identical to x509.MarshalPKCS1PrivateKey's
// for the same key (parse_openssh_test.go pins that).
func pkcs1DER(n, e, d, p, q, iqmp []byte) (*secmem.SecureBuffer, error) {
	n, e, d, p, q, iqmp = stripZeros(n), stripZeros(e), stripZeros(d), stripZeros(p), stripZeros(q), stripZeros(iqmp)
	if len(n) == 0 || len(e) == 0 || len(d) == 0 || len(p) == 0 || len(q) == 0 || len(iqmp) == 0 {
		return nil, errMalformed
	}
	switch {
	case bitLen(n) > rsaMaxModulusBits:
		return nil, fmt.Errorf("%w: RSA modulus too large", errMalformed)
	case bitLen(p) > rsaMaxPrimeBits || bitLen(q) > rsaMaxPrimeBits:
		return nil, fmt.Errorf("%w: RSA prime too large", errMalformed)
	case bitLen(e) > rsaMaxExponentBits || bitLen(e) < 2 || e[len(e)-1]&1 == 0:
		return nil, fmt.Errorf("%w: RSA public exponent", errMalformed)
	}

	bd := new(big.Int).SetBytes(d)
	bp := new(big.Int).SetBytes(p)
	bq := new(big.Int).SetBytes(q)
	pm1 := new(big.Int).Sub(bp, big.NewInt(1))
	qm1 := new(big.Int).Sub(bq, big.NewInt(1))
	dp := new(big.Int)
	dq := new(big.Int)
	defer func() {
		for _, x := range []*big.Int{bd, bp, bq, pm1, qm1, dp, dq} {
			wipeBigInt(x)
		}
	}()
	if pm1.Sign() <= 0 || qm1.Sign() <= 0 {
		return nil, errMalformed
	}
	dp.Mod(bd, pm1)
	dq.Mod(bd, qm1)

	fields := [9]derInt{
		{}, // version 0
		{raw: n}, {raw: e}, {raw: d}, {raw: p}, {raw: q},
		{big: dp}, {big: dq}, {raw: iqmp},
	}
	content := 0
	for _, f := range fields {
		content += f.encodedLen()
	}
	total := 1 + derLengthLen(content) + content

	out, err := secmem.NewEmptyBuffer(total)
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

// derInt is one INTEGER of the RSAPrivateKey: either a stripped big-endian
// magnitude aliasing the file, or a computed big.Int. The zero value encodes
// the integer 0.
type derInt struct {
	raw []byte
	big *big.Int
}

// magnitude returns the byte length of the value and whether its top bit is
// set (which DER's two's-complement INTEGER answers with a leading 0x00).
func (x derInt) magnitude() (nbytes int, high bool) {
	if x.big != nil {
		bl := x.big.BitLen()
		return (bl + 7) / 8, bl > 0 && bl%8 == 0
	}
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

// derLengthLen is the size of a DER length field for a content length n.
func derLengthLen(n int) int {
	switch {
	case n < 0x80:
		return 1
	case n < 0x100:
		return 2
	case n < 0x10000:
		return 3
	default:
		return 4
	}
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

func (w *derWriter) putLength(n int) {
	if n < 0x80 {
		w.putByte(byte(n)) //nolint:gosec // n < 0x80 on this branch
		return
	}
	k := derLengthLen(n) - 1
	w.putByte(0x80 | byte(k)) //nolint:gosec // k is 1..3
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
	if x.big != nil {
		x.big.FillBytes(w.b[w.off : w.off+nbytes])
		w.off += nbytes
		return
	}
	w.off += copy(w.b[w.off:], x.raw)
}
