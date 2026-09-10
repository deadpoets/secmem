package secmemcrypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The OpenSSH container, built by hand so each field can be corrupted on
// its own. Shapes mirror x/crypto/ssh's unexported openSSH* structs.
type sshOuter struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
}

type sshInner struct {
	Check1  uint32
	Check2  uint32
	Keytype string
	Rest    []byte `ssh:"rest"`
}

type sshEd25519Fields struct {
	Pub     []byte
	Priv    []byte
	Comment string
}

type sshECDSAFields struct {
	Curve   string
	Pub     []byte
	D       *big.Int
	Comment string
}

type sshRSAFields struct {
	N, E, D, Iqmp, P, Q *big.Int
	Comment             string
}

// opensshContainer assembles a raw (non-PEM) container. pad, when nil, is
// the correct 1,2,3… padding to the 8-byte block of cipher "none".
func opensshContainer(pubBlob []byte, inner sshInner, cipher string, numKeys uint32, pad []byte) []byte {
	priv := ssh.Marshal(inner)
	if pad == nil {
		for i := byte(1); len(priv)%8 != 0; i++ {
			priv = append(priv, i)
		}
	} else {
		priv = append(priv, pad...)
	}
	outer := sshOuter{CipherName: cipher, KdfName: "none", NumKeys: numKeys, PubKey: pubBlob, PrivKeyBlock: priv}
	return append([]byte("openssh-key-v1\x00"), ssh.Marshal(outer)...)
}

func sshPubBlob(t *testing.T, pub any) []byte {
	t.Helper()
	p, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return p.Marshal()
}

func TestParseOpenSSH_Ed25519Variants(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	fields := func(p ed25519.PublicKey, sk ed25519.PrivateKey) []byte {
		return ssh.Marshal(sshEd25519Fields{Pub: p, Priv: sk, Comment: "c"})
	}
	good := sshInner{Check1: 7, Check2: 7, Keytype: "ssh-ed25519", Rest: fields(pub, priv)}
	pubBlob := sshPubBlob(t, pub)

	// Sanity: the hand-built container parses and is the right key.
	s, err := ParsePrivateKey(opensshContainer(pubBlob, good, "none", 1, nil))
	if err != nil {
		t.Fatalf("hand-built container: %v", err)
	}
	verifySigner(t, s, pub)
	s.Destroy()

	wrongPriv := append([]byte{}, priv...)
	copy(wrongPriv[32:], otherPub) // seed || WRONG pub

	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"check-mismatch", opensshContainer(pubBlob, sshInner{Check1: 7, Check2: 8, Keytype: "ssh-ed25519", Rest: good.Rest}, "none", 1, nil), errMalformed},
		{"two-keys", opensshContainer(pubBlob, good, "none", 2, nil), ErrUnsupportedKey},
		{"zero-keys", opensshContainer(pubBlob, good, "none", 0, nil), ErrUnsupportedKey},
		{"encrypted-cipher", opensshContainer(pubBlob, good, "aes256-ctr", 1, nil), ErrEncryptedKey},
		{"bad-padding", opensshContainer(pubBlob, good, "none", 1, []byte{1, 2, 3, 3}), errMalformed},
		{"pub-blob-other-key", opensshContainer(sshPubBlob(t, otherPub), good, "none", 1, nil), errMalformed},
		{"pub-blob-wrong-type", opensshContainer(sshPubBlob(t, &testRSAKey().PublicKey), good, "none", 1, nil), errMalformed},
		{"priv-tail-not-pub", opensshContainer(pubBlob, sshInner{Check1: 1, Check2: 1, Keytype: "ssh-ed25519", Rest: fields(pub, wrongPriv)}, "none", 1, nil), errMalformed},
		{"pub-field-other-key", opensshContainer(pubBlob, sshInner{Check1: 1, Check2: 1, Keytype: "ssh-ed25519", Rest: fields(otherPub, priv)}, "none", 1, nil), errMalformed},
		{"short-priv", opensshContainer(pubBlob, sshInner{Check1: 1, Check2: 1, Keytype: "ssh-ed25519", Rest: fields(pub, priv[:63])}, "none", 1, nil), errMalformed},
		{"dss", opensshContainer(pubBlob, sshInner{Check1: 1, Check2: 1, Keytype: "ssh-dss", Rest: good.Rest}, "none", 1, nil), errMalformed}, // pub blob type disagrees first
		{"sk-ed25519", opensshContainer(ssh.Marshal(struct{ T string }{"sk-ssh-ed25519@openssh.com"}), sshInner{Check1: 1, Check2: 1, Keytype: "sk-ssh-ed25519@openssh.com", Rest: good.Rest}, "none", 1, nil), ErrUnsupportedKey},
		{"cert", opensshContainer(ssh.Marshal(struct{ T string }{"ssh-ed25519-cert-v01@openssh.com"}), sshInner{Check1: 1, Check2: 1, Keytype: "ssh-ed25519-cert-v01@openssh.com", Rest: good.Rest}, "none", 1, nil), ErrUnsupportedKey},
		{"magic-only", []byte("openssh-key-v1\x00"), errMalformed},
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

func TestParseOpenSSH_ECDSAVariants(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	q := must(k.PublicKey.Bytes()) // the SSH wire form is the uncompressed point
	otherQ := must(other.PublicKey.Bytes())
	kd := new(big.Int).SetBytes(must(k.Bytes())) // the wire mpint
	pubBlob := sshPubBlob(t, &k.PublicKey)
	inner := func(curve string, pub []byte, d *big.Int) sshInner {
		return sshInner{Check1: 3, Check2: 3, Keytype: "ecdsa-sha2-nistp256", Rest: ssh.Marshal(sshECDSAFields{Curve: curve, Pub: pub, D: d, Comment: "c"})}
	}

	s, err := ParsePrivateKey(opensshContainer(pubBlob, inner("nistp256", q, kd), "none", 1, nil))
	if err != nil {
		t.Fatalf("hand-built container: %v", err)
	}
	verifySigner(t, s, &k.PublicKey)
	s.Destroy()

	cases := []struct {
		name string
		data []byte
		want error // nil: any error
	}{
		{"curve-name-mismatch", opensshContainer(pubBlob, inner("nistp384", q, kd), "none", 1, nil), errMalformed},
		{"q-other-key", opensshContainer(sshPubBlob(t, &other.PublicKey), inner("nistp256", otherQ, kd), "none", 1, nil), errMalformed},
		{"q-disagrees-with-pub-blob", opensshContainer(pubBlob, inner("nistp256", otherQ, kd), "none", 1, nil), errMalformed},
		{"scalar-is-order", opensshContainer(pubBlob, inner("nistp256", q, elliptic.P256().Params().N), "none", 1, nil), nil},
		{"scalar-zero", opensshContainer(pubBlob, inner("nistp256", q, new(big.Int)), "none", 1, nil), errMalformed},
		{"scalar-too-long", opensshContainer(pubBlob, inner("nistp256", q, new(big.Int).Lsh(big.NewInt(1), 300)), "none", 1, nil), errMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ParsePrivateKey(tc.data)
			if err == nil {
				s.Destroy()
				t.Fatal("expected an error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseOpenSSH_RSAVariants(t *testing.T) {
	k := testRSAKey()
	pubBlob := sshPubBlob(t, &k.PublicKey)
	e := big.NewInt(int64(k.E))
	inner := func(f sshRSAFields) sshInner {
		return sshInner{Check1: 5, Check2: 5, Keytype: "ssh-rsa", Rest: ssh.Marshal(f)}
	}
	good := sshRSAFields{N: k.N, E: e, D: k.D, Iqmp: k.Precomputed.Qinv, P: k.Primes[0], Q: k.Primes[1], Comment: "c"}

	s, err := ParsePrivateKey(opensshContainer(pubBlob, inner(good), "none", 1, nil))
	if err != nil {
		t.Fatalf("hand-built container: %v", err)
	}
	verifySigner(t, s, &k.PublicKey)
	s.Destroy()

	// Swapped primes: iqmp is q^-1 mod p and no longer matches, which the
	// standard library's validation in NewRSASigner must catch.
	swapped := good
	swapped.P, swapped.Q = good.Q, good.P
	evenE := good
	evenE.E = big.NewInt(65536)
	hugeE := good
	hugeE.E = new(big.Int).Lsh(big.NewInt(1), 30)
	otherN := good
	otherN.N = new(big.Int).Add(k.N, big.NewInt(2))
	zeroP := good
	zeroP.P = new(big.Int)
	oneP := good
	oneP.P = big.NewInt(1)

	cases := []struct {
		name string
		data []byte
		want error // nil: any error
	}{
		{"swapped-primes", opensshContainer(pubBlob, inner(swapped), "none", 1, nil), nil},
		{"even-exponent", opensshContainer(pubBlob, inner(evenE), "none", 1, nil), errMalformed},
		{"huge-exponent", opensshContainer(pubBlob, inner(hugeE), "none", 1, nil), errMalformed},
		{"n-disagrees-with-pub-blob", opensshContainer(pubBlob, inner(otherN), "none", 1, nil), errMalformed},
		{"zero-prime", opensshContainer(pubBlob, inner(zeroP), "none", 1, nil), errMalformed},
		{"prime-one", opensshContainer(pubBlob, inner(oneP), "none", 1, nil), errMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ParsePrivateKey(tc.data)
			if err == nil {
				s.Destroy()
				t.Fatal("expected an error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// TestPKCS1DER_MatchesX509 pins the hand-rolled DER writer to the standard
// library's encoder, byte for byte, for a real key — both from clean
// magnitudes and from mpint-style operands carrying a sign byte. The
// 2048-bit key exercises the two-byte (0x82) length form; the small
// synthetic key below exercises the short form and the zero integer.
func TestPKCS1DER_MatchesX509(t *testing.T) {
	k := testRSAKey()
	want := x509.MarshalPKCS1PrivateKey(k)
	e := big.NewInt(int64(k.E))
	signed := func(x *big.Int) []byte { return append([]byte{0}, x.Bytes()...) }

	for _, tc := range []struct {
		name                string
		n, e, d, p, q, iqmp []byte
	}{
		{"magnitudes", k.N.Bytes(), e.Bytes(), k.D.Bytes(), k.Primes[0].Bytes(), k.Primes[1].Bytes(), k.Precomputed.Qinv.Bytes()},
		{"with-sign-bytes", signed(k.N), signed(e), signed(k.D), signed(k.Primes[0]), signed(k.Primes[1]), signed(k.Precomputed.Qinv)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf, err := pkcs1DER(tc.n, tc.e, tc.d, tc.p, tc.q, tc.iqmp)
			if err != nil {
				t.Fatal(err)
			}
			defer buf.Destroy()
			if err := buf.WithBytesErr(func(got []byte) error {
				if !bytes.Equal(got, want) {
					return errors.New("DER differs from x509.MarshalPKCS1PrivateKey")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestDERWriter_Lengths checks the length encoder at its boundaries and the
// INTEGER encoder's sign-byte and zero rules against known DER.
func TestDERWriter_Lengths(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}}, {127, []byte{0x7f}}, {128, []byte{0x81, 0x80}}, {255, []byte{0x81, 0xff}},
		{256, []byte{0x82, 0x01, 0x00}}, {65535, []byte{0x82, 0xff, 0xff}}, {65536, []byte{0x83, 0x01, 0x00, 0x00}},
	} {
		buf := make([]byte, 4)
		w := derWriter{b: buf}
		w.putLength(tc.n)
		if got := buf[:w.off]; !bytes.Equal(got, tc.want) {
			t.Errorf("length %d: got %x want %x", tc.n, got, tc.want)
		}
		if derLengthLen(tc.n) != len(tc.want) {
			t.Errorf("derLengthLen(%d) = %d, want %d", tc.n, derLengthLen(tc.n), len(tc.want))
		}
	}
	for _, tc := range []struct {
		x    derInt
		want []byte
	}{
		{derInt{}, []byte{0x02, 0x01, 0x00}},
		{derInt{raw: []byte{0x7f}}, []byte{0x02, 0x01, 0x7f}},
		{derInt{raw: []byte{0x80}}, []byte{0x02, 0x02, 0x00, 0x80}},
		{derInt{raw: []byte{0x01, 0x00}}, []byte{0x02, 0x02, 0x01, 0x00}},
	} {
		buf := make([]byte, 8)
		w := derWriter{b: buf}
		w.putInteger(tc.x)
		if got := buf[:w.off]; !bytes.Equal(got, tc.want) {
			t.Errorf("integer %+v: got %x want %x", tc.x, got, tc.want)
		}
		if tc.x.encodedLen() != len(tc.want) {
			t.Errorf("encodedLen(%+v) = %d, want %d", tc.x, tc.x.encodedLen(), len(tc.want))
		}
	}
}
