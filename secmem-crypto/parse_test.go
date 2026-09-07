package secmemcrypto

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/deadpoets/secmem"
)

// testRSAKey is generated once per test binary: 2048-bit generation is the
// slowest thing in this file and every RSA case can share one key.
var testRSAKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

// parseTestKey is a standard-library key plus which containers can hold it.
type parseTestKey struct {
	name    string
	priv    crypto.PrivateKey
	pub     crypto.PublicKey
	openssh bool // x/crypto/ssh can marshal it (no P-224 in SSH)
	sec1    bool
	pkcs1   bool
}

func parseTestKeys(t testing.TB) []parseTestKey {
	t.Helper()
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := []parseTestKey{{name: "ed25519", priv: edPriv, pub: edPub, openssh: true}}
	for _, c := range []struct {
		name  string
		curve elliptic.Curve
		ssh   bool
	}{{"p224", elliptic.P224(), false}, {"p256", elliptic.P256(), true}, {"p384", elliptic.P384(), true}, {"p521", elliptic.P521(), true}} {
		k, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, parseTestKey{name: c.name, priv: k, pub: &k.PublicKey, openssh: c.ssh, sec1: true})
	}
	r := testRSAKey()
	keys = append(keys, parseTestKey{name: "rsa2048", priv: r, pub: &r.PublicKey, openssh: true, pkcs1: true})
	return keys
}

type parseEncoding struct {
	name string
	data []byte
}

// encodings renders k in every container ParsePrivateKey accepts, PEM and
// raw. The standard library and x/crypto are the encoders, so the parser is
// tested against what real tools write, not against its own marshaller.
func encodings(t testing.TB, k parseTestKey) []parseEncoding {
	t.Helper()
	var out []parseEncoding
	add := func(name string, block *pem.Block) {
		out = append(out,
			parseEncoding{name + "-pem", pem.EncodeToMemory(block)},
			parseEncoding{name + "-raw", block.Bytes})
	}
	if k.openssh {
		block, err := ssh.MarshalPrivateKey(k.priv, "a comment")
		if err != nil {
			t.Fatal(err)
		}
		add("openssh", block)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(k.priv)
	if err != nil {
		t.Fatal(err)
	}
	add("pkcs8", &pem.Block{Type: "PRIVATE KEY", Bytes: p8})
	if k.sec1 {
		s1, err := x509.MarshalECPrivateKey(k.priv.(*ecdsa.PrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		add("sec1", &pem.Block{Type: "EC PRIVATE KEY", Bytes: s1})
	}
	if k.pkcs1 {
		add("pkcs1", &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k.priv.(*rsa.PrivateKey))})
	}
	return out
}

// must unwraps the error-returning key encoders used to build test inputs;
// a failure there is a broken test, not a finding.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// verifySigner proves the parsed signer is the same key as pub: Public()
// must equal it and a signature must verify under it with the standard
// library.
func verifySigner(t *testing.T, s Signer, pub crypto.PublicKey) {
	t.Helper()
	msg := []byte("the quick brown fox")
	switch p := pub.(type) {
	case ed25519.PublicKey:
		if _, ok := s.(*Ed25519Signer); !ok {
			t.Fatalf("got %T, want *Ed25519Signer", s)
		}
		got, ok := s.Public().(ed25519.PublicKey)
		if !ok || !bytes.Equal(got, p) {
			t.Fatal("Public() does not match the original key")
		}
		sig, err := s.Sign(nil, msg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(p, msg, sig) {
			t.Fatal("signature does not verify")
		}
	case *ecdsa.PublicKey:
		if _, ok := s.(*ECDSASigner); !ok {
			t.Fatalf("got %T, want *ECDSASigner", s)
		}
		if !p.Equal(s.Public()) {
			t.Fatal("Public() does not match the original key")
		}
		h := sha256.Sum256(msg)
		sig, err := s.Sign(rand.Reader, h[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.VerifyASN1(p, h[:], sig) {
			t.Fatal("signature does not verify")
		}
	case *rsa.PublicKey:
		if _, ok := s.(*RSASigner); !ok {
			t.Fatalf("got %T, want *RSASigner", s)
		}
		if !p.Equal(s.Public()) {
			t.Fatal("Public() does not match the original key")
		}
		h := sha256.Sum256(msg)
		sig, err := s.Sign(rand.Reader, h[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if err := rsa.VerifyPKCS1v15(p, crypto.SHA256, h[:], sig); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unhandled public key %T", pub)
	}
}

func TestParsePrivateKey_RoundTrip(t *testing.T) {
	for _, k := range parseTestKeys(t) {
		for _, enc := range encodings(t, k) {
			t.Run(k.name+"/"+enc.name, func(t *testing.T) {
				s, err := ParsePrivateKey(enc.data)
				if err != nil {
					t.Fatalf("ParsePrivateKey: %v", err)
				}
				verifySigner(t, s, k.pub)
				if err := s.Destroy(); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err == nil {
					t.Fatal("Sign after Destroy succeeded")
				}
			})
		}
	}
}

// TestParsePrivateKey_FromSecureBuffer is the documented usage: the file is
// read into a SecureBuffer and parsed from inside its borrow, which nests a
// second (newer, higher LockOrder) buffer's lock inside the first.
func TestParsePrivateKey_FromSecureBuffer(t *testing.T) {
	k := parseTestKeys(t)[0]
	data := encodings(t, k)[0].data
	buf, _, err := secmem.NewBufferFromReader(bytes.NewReader(data), len(data))
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Destroy()
	var s Signer
	err = buf.WithBytesErr(func(b []byte) error {
		var perr error
		s, perr = ParsePrivateKey(b)
		return perr
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()
	verifySigner(t, s, k.pub)
}

// TestParsePrivateKey_PEMVariants covers what real files look like: CRLF
// line endings, surrounding whitespace, text before the block.
func TestParsePrivateKey_PEMVariants(t *testing.T) {
	k := parseTestKeys(t)[0]
	data := encodings(t, k)[0].data // openssh-pem
	variants := map[string][]byte{
		"crlf":       bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n")),
		"leading-ws": append([]byte("\n\n  \t"), data...),
		"trailing":   append(append([]byte{}, data...), []byte("\n\n")...),
		"preamble":   append([]byte("some text a tool wrote first\n"), data...),
	}
	for name, v := range variants {
		t.Run(name, func(t *testing.T) {
			s, err := ParsePrivateKey(v)
			if err != nil {
				t.Fatalf("ParsePrivateKey: %v", err)
			}
			defer s.Destroy()
			verifySigner(t, s, k.pub)
		})
	}
}

func TestParsePrivateKey_Rejects(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = edPub
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x25519DER, err := x509.MarshalPKCS8PrivateKey(x25519)
	if err != nil {
		t.Fatal(err)
	}
	encBlock, err := ssh.MarshalPrivateKeyWithPassphrase(edPriv, "c", []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte("not a key"))
	// PEM armour is assembled from parts so no test line carries a literal
	// private-key header for a secret scanner to flag.
	begin := func(typ string) string { return "-----BEGIN " + typ + "-----\n" }
	end := func(typ string) string { return "-----END " + typ + "-----\n" }
	pemOf := func(typ, body string) []byte { return []byte(begin(typ) + body + "\n" + end(typ)) }
	const pk, rsaPK = "PRIVATE KEY", "RSA PRIVATE KEY"
	legacyEncrypted := []byte(begin(rsaPK) +
		"Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\n" +
		b64 + "\n" + end(rsaPK))

	cases := []struct {
		name string
		data []byte
		want error // nil: any error
	}{
		{"empty", nil, nil},
		{"whitespace", []byte("  \n\t"), nil},
		{"text", []byte("hello"), nil},
		{"der-garbage", []byte{0x30, 0x05, 0x02, 0x01, 0x00, 0xff, 0xff}, errMalformed},
		{"openssh-encrypted", pem.EncodeToMemory(encBlock), ErrEncryptedKey},
		{"pkcs8-encrypted-block", pemOf("ENCRYPTED PRIVATE KEY", b64), ErrEncryptedKey},
		{"legacy-pem-headers", legacyEncrypted, ErrEncryptedKey},
		{"dsa-block", pemOf("DSA PRIVATE KEY", b64), ErrUnsupportedKey},
		{"certificate-block", pemOf("CERTIFICATE", b64), ErrUnsupportedKey},
		{"x25519-pkcs8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x25519DER}), ErrUnsupportedKey},
		{"footer-mismatch", []byte(begin(pk) + b64 + "\n" + end(rsaPK)), errMalformed},
		{"no-footer", []byte(begin(pk) + b64 + "\n"), errMalformed},
		{"empty-body", []byte(begin(pk) + end(pk)), errMalformed},
		{"bad-base64", pemOf(pk, "!!!!"), errMalformed},
		{"unsupported-header", []byte(begin(pk) + "X-Foo: bar\n\n" + b64 + "\n" + end(pk)), ErrUnsupportedKey},
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
			if !strings.HasPrefix(err.Error(), "secmemcrypto: parse private key: ") {
				t.Fatalf("error not prefixed: %q", err)
			}
		})
	}
}

// TestParsePrivateKey_Truncations: every proper prefix of a valid raw
// container must be rejected, never accepted and never panic.
func TestParsePrivateKey_Truncations(t *testing.T) {
	k := parseTestKeys(t)[0]
	for _, enc := range encodings(t, k) {
		if !strings.HasSuffix(enc.name, "-raw") {
			continue
		}
		for i := 1; i < len(enc.data); i++ {
			if s, err := ParsePrivateKey(enc.data[:i]); err == nil {
				s.Destroy()
				t.Fatalf("%s: prefix of %d/%d bytes parsed", enc.name, i, len(enc.data))
			}
		}
	}
}

// TestParsePrivateKey_ErrorsCarryNoKeyBytes: rejections must not quote the
// input. A hex or base64 fragment of the key in an error string would end up
// in a log.
func TestParsePrivateKey_ErrorsCarryNoKeyBytes(t *testing.T) {
	k := parseTestKeys(t)[0]
	data := encodings(t, k)[1].data // openssh-raw
	corrupt := append([]byte{}, data...)
	corrupt[len(corrupt)-1] ^= 0xff // breaks the padding
	_, err := ParsePrivateKey(corrupt)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for i := 0; i+8 <= len(corrupt); i += 8 {
		if strings.Contains(msg, string(corrupt[i:i+8])) {
			t.Fatalf("error text contains key bytes: %q", msg)
		}
	}
}
