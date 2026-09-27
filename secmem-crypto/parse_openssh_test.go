package secmemcrypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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
// the correct 1,2,3… padding to the 8-byte block of cipher "none". A cipher
// other than "none" gets a matching bcrypt KDF with well-formed options, so
// the header is one the parser classifies as encrypted rather than refuses
// as inconsistent (the private block is then left in the clear, which such
// a test never reads).
func opensshContainer(pubBlob []byte, inner sshInner, cipher string, numKeys uint32, pad []byte) []byte {
	priv := ssh.Marshal(inner)
	if pad == nil {
		for i := byte(1); len(priv)%8 != 0; i++ {
			priv = append(priv, i)
		}
	} else {
		priv = append(priv, pad...)
	}
	kdf, kdfOpts := opensshKDFNone, ""
	if cipher != opensshCipherNone {
		kdf, kdfOpts = opensshKDFBcrypt, string(testKDFOpts(opensshSaltLen, 1))
	}
	outer := sshOuter{CipherName: cipher, KdfName: kdf, KdfOpts: kdfOpts, NumKeys: numKeys, PubKey: pubBlob, PrivKeyBlock: priv}
	return append([]byte("openssh-key-v1\x00"), ssh.Marshal(outer)...)
}

// ed25519Container is a fresh Ed25519 key in a hand-built unencrypted
// container whose key type, padding and comment the test chooses; the
// public-key block names the same type, so a parse reaches the private
// block's type switch. pad nil means correct padding (see opensshContainer).
func ed25519Container(t *testing.T, keyType string, pad []byte, comment string) (data []byte, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inner := sshInner{Check1: 0x11223344, Check2: 0x11223344, Keytype: keyType,
		Rest: ssh.Marshal(sshEd25519Fields{Pub: pub, Priv: priv, Comment: comment})}
	pubBlob := ssh.Marshal(struct {
		Type string
		Pub  []byte
	}{keyType, pub})
	return opensshContainer(pubBlob, inner, opensshCipherNone, 1, pad), pub
}

// armourRaw is the PEM form of a raw container, for handing the same bytes
// to x/crypto/ssh, which reads only PEM.
func armourRaw(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: opensshPEMType, Bytes: raw})
}

// TestParseOpenSSH_HeaderConsistency: a header that names a cipher without
// a KDF, or a KDF without a cipher, is malformed to both entry points.
// Before this rule ParsePrivateKey called such a file passphrase-protected
// and ParsePrivateKeyWithPassphrase called it unprotected, each sending the
// caller to the other; OpenSSH refuses it as an invalid format. The two
// consistent headers keep their classifications.
func TestParseOpenSSH_HeaderConsistency(t *testing.T) {
	kdfOpts := testKDFOpts(opensshSaltLen, 1)
	for _, tc := range []struct {
		name, cipher, kdf string
		opts              []byte
	}{
		{"cipher without kdf", opensshCipherCTR, opensshKDFNone, nil},
		{"kdf without cipher", opensshCipherNone, opensshKDFBcrypt, kdfOpts},
		{"cbc without kdf", opensshCipherCBC, opensshKDFNone, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := testContainer(tc.cipher, tc.kdf, tc.opts, 16)
			for name, parse := range map[string]func([]byte) (Signer, error){
				"ParsePrivateKey": func(d []byte) (Signer, error) { return ParsePrivateKey(d, AllowHeapTransients()) },
				"ParsePrivateKeyWithPassphrase": func(d []byte) (Signer, error) {
					return ParsePrivateKeyWithPassphrase(d, []byte(testPassphrase), AllowHeapTransients())
				},
			} {
				for form, in := range map[string][]byte{"raw": data, "pem": armourRaw(data)} {
					s, err := parse(in)
					if err == nil {
						s.Destroy()
						t.Fatalf("%s/%s accepted a half-encrypted header", name, form)
					}
					if !errors.Is(err, errMalformed) {
						t.Errorf("%s/%s: %v, want errMalformed", name, form, err)
					}
					if errors.Is(err, ErrEncryptedKey) || errors.Is(err, ErrNotEncrypted) {
						t.Errorf("%s/%s classified a half-encrypted header: %v", name, form, err)
					}
				}
			}
		})
	}

	// The consistent headers still classify, in both directions.
	if _, err := ParsePrivateKey(testContainer(opensshCipherCTR, opensshKDFBcrypt, kdfOpts, 16), AllowHeapTransients()); !errors.Is(err, ErrEncryptedKey) {
		t.Errorf("ParsePrivateKey on ctr/bcrypt: %v, want ErrEncryptedKey", err)
	}
	if _, err := ParsePrivateKeyWithPassphrase(testContainer(opensshCipherNone, opensshKDFNone, nil, 16), []byte("x"), AllowHeapTransients()); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("ParsePrivateKeyWithPassphrase on none/none: %v, want ErrNotEncrypted", err)
	}
}

// TestParseOpenSSH_FormatStrictness pins the container rules PROTOCOL.key
// implies and OpenSSH's sshkey.c enforces, which the parser used to let
// through: (a) the pad is shorter than the cipher block, (b) an unencrypted
// private block is a multiple of the "none" cipher's 8-byte block, (c)
// nothing follows the container's last field, (d) a "none" KDF carries no
// options. For each, the well-formed neighbour of the refused input is
// parsed too, so the refusal is shown to be the rule and not the
// construction.
//
// golang.org/x/crypto/ssh is compared where it agrees: it refuses (d) and
// the parsers must keep agreeing there. It accepts (a), (b) and (c) — its
// container struct takes trailing bytes as a "rest" field, and its pad check
// looks at the sequence but not its length — so those are asserted against
// this parser alone, with OpenSSH's own reader as the authority. (a) is
// stricter than both: neither ever writes a pad of a whole block, so
// nothing well-formed is lost.
func TestParseOpenSSH_FormatStrictness(t *testing.T) {
	sequence := func(n int) []byte {
		pad := make([]byte, n)
		for i := range pad {
			pad[i] = byte(i + 1)
		}
		return pad
	}
	accepts := func(t *testing.T, data []byte, pub ed25519.PublicKey) {
		t.Helper()
		s, err := ParsePrivateKey(data, AllowHeapTransients())
		if err != nil {
			t.Fatalf("well-formed neighbour refused: %v", err)
		}
		verifySigner(t, s, pub)
		s.Destroy()
		if _, err := ssh.ParseRawPrivateKey(armourRaw(data)); err != nil {
			t.Fatalf("x/crypto refuses the well-formed neighbour: %v", err)
		}
	}
	refuses := func(t *testing.T, data []byte) {
		t.Helper()
		s, err := ParsePrivateKey(data, AllowHeapTransients())
		if err == nil {
			s.Destroy()
			t.Fatal("accepted")
		}
		if !errors.Is(err, errMalformed) {
			t.Fatalf("%v, want errMalformed", err)
		}
	}

	t.Run("a: pad length", func(t *testing.T) {
		// The Ed25519 private block is 131 bytes plus the comment; a 6-byte
		// comment wants the longest legal pad, 7, and a 5-byte one falls on
		// the boundary, where a writer emits no pad at all.
		data, pub := ed25519Container(t, opensshKeyEd25519, sequence(7), "cccccc")
		accepts(t, data, pub)
		data, _ = ed25519Container(t, opensshKeyEd25519, sequence(8), "ccccc")
		refuses(t, data) // a whole block of pad: aligned and in sequence, and still not a padded block
		data, _ = ed25519Container(t, opensshKeyEd25519, sequence(200), "c")
		refuses(t, data)
	})
	t.Run("b: block alignment", func(t *testing.T) {
		data, pub := ed25519Container(t, opensshKeyEd25519, nil, "cc")
		accepts(t, data, pub)
		data, _ = ed25519Container(t, opensshKeyEd25519, sequence(1), "cc") // 134 bytes: in sequence, not a multiple of 8
		refuses(t, data)
	})
	t.Run("c: trailing bytes", func(t *testing.T) {
		data, pub := ed25519Container(t, opensshKeyEd25519, nil, "c")
		accepts(t, data, pub)
		refuses(t, append(data, 0xde, 0xad, 0xbe, 0xef))
		refuses(t, append(data, 0))
		// The passphrase path reads the same header: a protected file with
		// bytes after it is malformed, not a wrong passphrase.
		_, raw, _ := fixture(t, "ed25519-a1")
		_, err := ParsePrivateKeyWithPassphrase(append(append([]byte(nil), raw...), 0), []byte(testPassphrase), AllowHeapTransients())
		if !errors.Is(err, errMalformed) || errors.Is(err, x509.IncorrectPasswordError) {
			t.Errorf("protected file with trailing bytes: %v, want errMalformed", err)
		}
	})
	t.Run("d: kdf options with none", func(t *testing.T) {
		data, pub := ed25519Container(t, opensshKeyEd25519, nil, "c")
		accepts(t, data, pub)
		h, err := readOpenSSHHeader(data)
		if err != nil {
			t.Fatal(err)
		}
		outer := sshOuter{CipherName: opensshCipherNone, KdfName: opensshKDFNone, KdfOpts: "junkjunk", NumKeys: 1, PubKey: h.pubBlob, PrivKeyBlock: h.privBlock}
		bad := append([]byte("openssh-key-v1\x00"), ssh.Marshal(outer)...)
		refuses(t, bad)
		if _, err := ssh.ParseRawPrivateKey(armourRaw(bad)); err == nil {
			t.Error("x/crypto accepts KDF options with KDF none; the parsers no longer agree")
		}
	})
}

// TestPKCS1DER_RejectsOversizedIqmp: iqmp = q⁻¹ mod p is below p, so a
// value wider than the prime cap is not a CRT coefficient of any key this
// parser accepts. Without the bound it was the one integer whose size the
// file set freely, and the assembled DER's length field was sized by it.
func TestPKCS1DER_RejectsOversizedIqmp(t *testing.T) {
	k := testRSAKey()
	e := big.NewInt(int64(k.E))
	huge := new(big.Int).Lsh(big.NewInt(1), rsaMaxPrimeBits) // rsaMaxPrimeBits+1 bits
	if buf, err := pkcs1DER(k.N.Bytes(), e.Bytes(), k.D.Bytes(), k.Primes[0].Bytes(), k.Primes[1].Bytes(), huge.Bytes()); err == nil {
		buf.Destroy()
		t.Fatal("pkcs1DER accepted an iqmp wider than the prime cap")
	} else if !errors.Is(err, errMalformed) {
		t.Fatalf("%v, want errMalformed", err)
	}
	// Exactly at the cap it is a size question for the standard library,
	// not a bound question for this parser.
	atCap := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), rsaMaxPrimeBits), big.NewInt(1))
	if buf, err := pkcs1DER(k.N.Bytes(), e.Bytes(), k.D.Bytes(), k.Primes[0].Bytes(), k.Primes[1].Bytes(), atCap.Bytes()); err != nil {
		t.Fatalf("pkcs1DER refused an iqmp at the prime cap: %v", err)
	} else {
		buf.Destroy()
	}

	// Through the container: the file is refused as malformed before the
	// standard library sees anything.
	fields := sshRSAFields{N: k.N, E: e, D: k.D, Iqmp: huge, P: k.Primes[0], Q: k.Primes[1], Comment: "c"}
	inner := sshInner{Check1: 5, Check2: 5, Keytype: "ssh-rsa", Rest: ssh.Marshal(fields)}
	data := opensshContainer(sshPubBlob(t, &k.PublicKey), inner, opensshCipherNone, 1, nil)
	if s, err := ParsePrivateKey(data, AllowHeapTransients()); err == nil {
		s.Destroy()
		t.Fatal("container with an oversized iqmp parsed")
	} else if !errors.Is(err, errMalformed) {
		t.Fatalf("%v, want errMalformed", err)
	}
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
	s, err := ParsePrivateKey(opensshContainer(pubBlob, good, "none", 1, nil), AllowHeapTransients())
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
			s, err := ParsePrivateKey(tc.data, AllowHeapTransients())
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

	s, err := ParsePrivateKey(opensshContainer(pubBlob, inner("nistp256", q, kd), "none", 1, nil), AllowHeapTransients())
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
			s, err := ParsePrivateKey(tc.data, AllowHeapTransients())
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

	s, err := ParsePrivateKey(opensshContainer(pubBlob, inner(good), "none", 1, nil), AllowHeapTransients())
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
			s, err := ParsePrivateKey(tc.data, AllowHeapTransients())
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
// INTEGER encoder's sign-byte and zero rules against known DER. The length
// cases run past 2^24, where the encoder used to write the count of a
// three-octet field and the low three octets of a four-octet value — a
// length modulo 2^24 — and up to a five-octet value, and every case is
// decoded back by the DER rule.
func TestDERWriter_Lengths(t *testing.T) {
	// The two largest cases do not fit a 32-bit int; the table is int64 so
	// the file compiles on 386, and those cases are skipped there (the
	// encoder takes an int, so no such length can be asked for on 32-bit).
	const maxInt = int64(int(^uint(0) >> 1))
	for _, tc := range []struct {
		n    int64
		want []byte
	}{
		{0, []byte{0x00}}, {127, []byte{0x7f}}, {128, []byte{0x81, 0x80}}, {255, []byte{0x81, 0xff}},
		{256, []byte{0x82, 0x01, 0x00}}, {65535, []byte{0x82, 0xff, 0xff}}, {65536, []byte{0x83, 0x01, 0x00, 0x00}},
		{0xffffff, []byte{0x83, 0xff, 0xff, 0xff}}, {0x1000000, []byte{0x84, 0x01, 0x00, 0x00, 0x00}},
		{0x1234567, []byte{0x84, 0x01, 0x23, 0x45, 0x67}}, {0xffffffff, []byte{0x84, 0xff, 0xff, 0xff, 0xff}},
		{0x100000000, []byte{0x85, 0x01, 0x00, 0x00, 0x00, 0x00}},
	} {
		if tc.n > maxInt {
			t.Logf("length %#x: not representable as int on this platform, skipped", tc.n)
			continue
		}
		n := int(tc.n)
		buf := make([]byte, 9)
		w := derWriter{b: buf}
		w.putLength(n)
		got := buf[:w.off]
		if !bytes.Equal(got, tc.want) {
			t.Errorf("length %d: got %x want %x", tc.n, got, tc.want)
		}
		if derLengthLen(n) != len(tc.want) {
			t.Errorf("derLengthLen(%d) = %d, want %d", tc.n, derLengthLen(n), len(tc.want))
		}
		// Decode the field back by the DER rule, and require the minimal
		// form DER demands: no leading zero octet in the long form.
		var decoded int64
		if got[0] < 0x80 {
			decoded = int64(got[0])
		} else {
			for _, b := range got[1:] {
				decoded = decoded<<8 | int64(b)
			}
			if got[1] == 0 {
				t.Errorf("length %d: leading zero octet in %x", tc.n, got)
			}
		}
		if decoded != tc.n {
			t.Errorf("length %d: %x decodes to %d", tc.n, got, decoded)
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
