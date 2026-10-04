// rsabounds.go is the one size rule for RSA private keys, applied wherever a
// key reaches an RSASigner: a file in any container, a DER buffer handed to
// NewRSASigner, and a size asked of GenerateRSASigner.
//
// The rule exists because the standard library has none. Parsing an
// RSAPrivateKey validates it (n = p·q, the CRT values) and precomputes its
// Montgomery constants, at a cost quadratic in the size of the integers, and
// every Sign repeats that; a key file with megabyte integers buys minutes of
// CPU per parse from whoever opens it. So the encoded lengths are read first,
// in place, and anything wider than the caps is refused before a single
// multiplication.

package secmemcrypto

import (
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// The caps. The modulus cap is OpenSSH's own maximum (and x/crypto/ssh's);
// a prime, a CRT exponent and a CRT coefficient are each below a prime, so
// they share half of it — which is also the width modreduce.go's stack
// arrays are sized for. The private exponent is below the modulus. The
// public exponent rules are x/crypto/ssh's for OpenSSH keys: wider than 24
// bits makes every verification expensive, and an even or unit exponent is
// not an RSA exponent at all.
//
// rsaMaxOtherPrimes bounds a multi-prime key's otherPrimeInfos list, which
// would otherwise be the one part of the structure a file could size freely.
// Five primes in all is OpenSSL's ceiling (RSA_MAX_PRIME_NUM).
const (
	rsaMaxModulusBits  = 16384
	rsaMaxPrimeBits    = 8192
	rsaMaxExponentBits = 24
	rsaMaxOtherPrimes  = 3
)

// checkRSAIntegers applies the caps to the integers of one key, each a
// stripped big-endian magnitude. crt is whichever of dp, dq and qinv the
// caller has; each is bounded like a prime.
func checkRSAIntegers(n, e, d, p, q []byte, crt ...[]byte) error {
	switch {
	case bitLen(n) > rsaMaxModulusBits:
		return fmt.Errorf("%w: RSA modulus too large", errMalformed)
	case bitLen(d) > rsaMaxModulusBits:
		return fmt.Errorf("%w: RSA private exponent too large", errMalformed)
	case bitLen(p) > rsaMaxPrimeBits || bitLen(q) > rsaMaxPrimeBits:
		return fmt.Errorf("%w: RSA prime too large", errMalformed)
	case bitLen(e) > rsaMaxExponentBits || bitLen(e) < 2 || e[len(e)-1]&1 == 0:
		return fmt.Errorf("%w: RSA public exponent", errMalformed)
	}
	for _, v := range crt {
		if bitLen(v) > rsaMaxPrimeBits {
			return fmt.Errorf("%w: RSA CRT value too large", errMalformed)
		}
	}
	return nil
}

// errNotRSADER is checkRSAKeySize's answer for bytes that are neither
// structure NewRSASigner accepts. It names both, as the constructor's error
// for such input always has.
var errNotRSADER = errors.New("DER is neither a PKCS#1 RSAPrivateKey nor a PKCS#8 PrivateKeyInfo")

// locatePKCS1 finds the RSAPrivateKey (RFC 8017 A.1.2) in der, which is
// either that structure or a PKCS#8 PrivateKeyInfo around it, and returns it
// as a sub-slice of der: nothing is copied.
// A PrivateKeyInfo for another algorithm returns a nil slice and no error —
// there is no RSA key in it to locate, and the caller says so in its own
// words. Anything else is errNotRSADER.
//
// The two are told apart by the element after the version: an INTEGER (the
// modulus) or a SEQUENCE (the AlgorithmIdentifier).
func locatePKCS1(der []byte) (pkcs1 []byte, err error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	var version cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1(&version, cbasn1.INTEGER) {
		return nil, errNotRSADER
	}
	switch {
	case seq.PeekASN1Tag(cbasn1.INTEGER):
		return der, nil
	case seq.PeekASN1Tag(cbasn1.SEQUENCE):
		var alg, oid, priv cryptobyte.String
		if !seq.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1(&oid, cbasn1.OBJECT_IDENTIFIER) ||
			!seq.ReadASN1(&priv, cbasn1.OCTET_STRING) {
			return nil, errNotRSADER
		}
		if !bytes.Equal(oid, oidRSADER) {
			return nil, nil
		}
		return priv, nil
	default:
		return nil, errNotRSADER
	}
}

// oidRSADER is the content of rsaEncryption's OBJECT IDENTIFIER
// (1.2.840.113549.1.1.1), for comparing in place.
var oidRSADER = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01} //nolint:gochecknoglobals // read-only constant

// checkRSAKeySize is checkPKCS1Size for the RSA key in der, PKCS#1 or
// PKCS#8. A PKCS#8 structure for another algorithm passes — it holds no RSA
// key to measure.
func checkRSAKeySize(der []byte) error {
	pkcs1, err := locatePKCS1(der)
	if err != nil || pkcs1 == nil {
		return err
	}
	return checkPKCS1Size(pkcs1)
}

// checkPKCS1Size reads the lengths of the integers of an RSAPrivateKey and
// applies the caps. It reads the structure in place and copies nothing:
// every value below is a sub-slice of it, and only its length and its first
// and last bytes are looked at.
func checkPKCS1Size(pkcs1 []byte) error {
	in := cryptobyte.String(pkcs1)
	var seq, version cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1(&version, cbasn1.INTEGER) {
		return errNotRSADER
	}
	// modulus, publicExponent, privateExponent, prime1, prime2, then
	// exponent1, exponent2 and coefficient — which the standard library
	// treats as optional and recomputes, so their absence is not refused
	// here either.
	var ints [8][]byte
	have := 0
	for have < len(ints) && seq.PeekASN1Tag(cbasn1.INTEGER) {
		var v cryptobyte.String
		if !seq.ReadASN1(&v, cbasn1.INTEGER) {
			return errMalformed
		}
		ints[have] = stripZeros(v)
		have++
	}
	if have < 5 {
		return fmt.Errorf("%w: RSA key without its five defining integers", errMalformed)
	}
	if err := checkRSAIntegers(ints[0], ints[1], ints[2], ints[3], ints[4], ints[5:have]...); err != nil {
		return err
	}
	if seq.Empty() {
		return nil
	}

	// otherPrimeInfos: SEQUENCE OF SEQUENCE { prime, exponent, coefficient }.
	var others cryptobyte.String
	if !seq.ReadASN1(&others, cbasn1.SEQUENCE) || !seq.Empty() {
		return errMalformed
	}
	for count := 0; !others.Empty(); count++ {
		if count == rsaMaxOtherPrimes {
			return fmt.Errorf("%w: RSA key with more than %d primes", errMalformed, 2+rsaMaxOtherPrimes)
		}
		var info cryptobyte.String
		if !others.ReadASN1(&info, cbasn1.SEQUENCE) {
			return errMalformed
		}
		for range 3 {
			var v cryptobyte.String
			if !info.ReadASN1(&v, cbasn1.INTEGER) {
				return errMalformed
			}
			if bitLen(stripZeros(v)) > rsaMaxPrimeBits {
				return fmt.Errorf("%w: RSA prime too large", errMalformed)
			}
		}
		if !info.Empty() {
			return errMalformed
		}
	}
	return nil
}
