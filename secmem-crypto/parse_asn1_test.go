package secmemcrypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// The standard library never writes PKCS#8 v2 or compressed SEC 1 points,
// so the structures that exercise the public-key cross-checks and the
// parameter rules are built here with cryptobyte.

func pkcs8Ed25519(version int64, seed, pub []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(version)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oidEd25519) })
		b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddASN1OctetString(seed) })
		if pub != nil {
			b.AddASN1(cbasn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddUint8(0) // no unused bits
				b.AddBytes(pub)
			})
		}
	})
	return b.BytesOrPanic()
}

// sec1 builds an ECPrivateKey; curveOID nil omits the parameters, pub nil
// omits the public key.
func sec1(d []byte, curveOID asn1.ObjectIdentifier, pub []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1OctetString(d)
		if curveOID != nil {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(curveOID)
			})
		}
		if pub != nil {
			b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1BitString(pub)
			})
		}
	})
	return b.BytesOrPanic()
}

// pkcs8EC wraps a SEC 1 body in PKCS#8 with the given algorithm parameters
// (curveOID nil omits them).
func pkcs8EC(curveOID asn1.ObjectIdentifier, sec1Body []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidECPublicKey)
			if curveOID != nil {
				b.AddASN1ObjectIdentifier(curveOID)
			}
		})
		b.AddASN1OctetString(sec1Body)
	})
	return b.BytesOrPanic()
}

func pkcs8Alg(oid asn1.ObjectIdentifier, priv []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oid) })
		b.AddASN1OctetString(priv)
	})
	return b.BytesOrPanic()
}

func TestParsePKCS8_Ed25519V2(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	seed := priv.Seed()

	s, err := ParsePrivateKey(pkcs8Ed25519(1, seed, pub))
	if err != nil {
		t.Fatalf("v2 with matching public key: %v", err)
	}
	verifySigner(t, s, pub)
	s.Destroy()

	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"v2-wrong-pub", pkcs8Ed25519(1, seed, otherPub), errMalformed},
		{"v1-with-pub", pkcs8Ed25519(0, seed, pub), errMalformed},
		{"version-2", pkcs8Ed25519(2, seed, nil), errMalformed},
		{"short-seed", pkcs8Ed25519(0, seed[:31], nil), ErrBadSeedLength},
		{"long-seed", pkcs8Ed25519(0, append(seed, 0), nil), ErrBadSeedLength},
		{"trailing-bytes", append(pkcs8Ed25519(0, seed, nil), 0), errMalformed},
		{"dsa-oid", pkcs8Alg(asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}, seed), ErrUnsupportedKey},
		{"rsa-pss-oid", pkcs8Alg(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}, seed), ErrUnsupportedKey},
		{"x25519-oid", pkcs8Alg(oidX25519, pkcs8Ed25519(0, seed, nil)[:0]), ErrUnsupportedKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ParsePrivateKey(tc.data)
			if err == nil {
				s.Destroy()
				t.Fatal("expected an error")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseSEC1_Variants(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := must(k.Bytes())                      // fixed-width scalar
	uncompressed := must(k.PublicKey.Bytes()) // 0x04 || X || Y
	compressed := make([]byte, 33)
	compressed[0] = 0x02 + uncompressed[64]&1 // y parity
	copy(compressed[1:], uncompressed[1:33])
	wrongParity := append([]byte{}, compressed...)
	wrongParity[0] ^= 1
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherPub := must(other.PublicKey.Bytes())
	secp256k1 := asn1.ObjectIdentifier{1, 3, 132, 0, 10}

	good := []struct {
		name string
		data []byte
	}{
		{"sec1-uncompressed-pub", sec1(d, oidP256, uncompressed)},
		{"sec1-compressed-pub", sec1(d, oidP256, compressed)},
		{"sec1-no-pub", sec1(d, oidP256, nil)},
		{"sec1-leading-zero-scalar", sec1(append([]byte{0}, d...), oidP256, nil)},
		{"pkcs8-with-sec1-params", pkcs8EC(oidP256, sec1(d, oidP256, uncompressed))},
		{"pkcs8-without-sec1-params", pkcs8EC(oidP256, sec1(d, nil, nil))},
	}
	for _, tc := range good {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ParsePrivateKey(tc.data)
			if err != nil {
				t.Fatalf("ParsePrivateKey: %v", err)
			}
			defer s.Destroy()
			verifySigner(t, s, &k.PublicKey)
		})
	}

	bad := []struct {
		name string
		data []byte
		want error
	}{
		{"sec1-pub-other-key", sec1(d, oidP256, otherPub), errMalformed},
		{"sec1-compressed-wrong-parity", sec1(d, oidP256, wrongParity), errMalformed},
		{"sec1-no-curve-anywhere", sec1(d, nil, nil), ErrUnsupportedKey},
		{"sec1-unknown-curve", sec1(d, secp256k1, nil), ErrUnsupportedKey},
		{"pkcs8-no-curve-anywhere", pkcs8EC(nil, sec1(d, nil, nil)), ErrUnsupportedKey},
		{"pkcs8-curve-disagrees", pkcs8EC(oidP384, sec1(d, oidP256, nil)), errMalformed},
		{"pkcs8-unknown-curve", pkcs8EC(secp256k1, sec1(d, nil, nil)), ErrUnsupportedKey},
		{"sec1-scalar-too-long", sec1(append([]byte{1}, d...), oidP256, nil), errMalformed},
		{"sec1-scalar-zero", sec1(make([]byte, 32), oidP256, nil), errMalformed},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ParsePrivateKey(tc.data)
			if err == nil {
				s.Destroy()
				t.Fatal("expected an error")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}
