package secmemcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// legacyPEM builds an RSA PEM block carrying the RFC 1421 encryption
// headers openssl and old ssh-keygen wrote. The body is filler: every
// entry point refuses the file on the headers alone, before any base64 is
// decoded and without looking at the passphrase, which is the behaviour
// these tests are pinning.
func legacyPEM(dekInfo string) []byte {
	return []byte(pemOfType("RSA PRIVATE KEY",
		"Proc-Type: 4,ENCRYPTED\nDEK-Info: "+dekInfo+"\n\n", "AAAA"))
}

// TestLegacyPEMEncryption_RefusedAsPolicy pins a decision, not an
// implementation detail: this package will not learn to open PEM files
// encrypted with EVP_BytesToKey, so the refusal carries ErrRetiredAlgorithm
// and a caller can tell it from a feature that has not arrived yet. If
// support for these files is ever added, this test is the thing that has to
// be deleted deliberately, with the reasoning in ErrRetiredAlgorithm's doc
// reopened — which is the point of writing it down as a test.
//
// The full range of DEK-Info ciphers is covered because the refusal is on
// the headers, not on the cipher: a future reader must not be tempted to
// admit "just AES-256-CBC", which shares the same single-pass MD5 key
// derivation and the same unauthenticated mode as the DES variants.
func TestLegacyPEMEncryption_RefusedAsPolicy(t *testing.T) {
	deks := []string{
		"DES-CBC,0123456789ABCDEF",
		"DES-EDE3-CBC,0123456789ABCDEF",
		"AES-128-CBC,00112233445566778899AABBCCDDEEFF",
		"AES-256-CBC,00112233445566778899AABBCCDDEEFF",
	}
	for _, dek := range deks {
		name, _, _ := strings.Cut(dek, ",")
		data := legacyPEM(dek)
		t.Run(name, func(t *testing.T) {
			// The plain entry point: encrypted, and retired with it.
			s, err := ParsePrivateKey(data)
			if s != nil {
				s.Destroy()
				t.Fatal("a legacy encrypted PEM was parsed")
			}
			if !errors.Is(err, ErrEncryptedKey) {
				t.Errorf("ParsePrivateKey: %v does not wrap ErrEncryptedKey", err)
			}
			plainErr := err

			// The passphrase entry point: unsupported, and retired with it.
			// A caller who followed ErrEncryptedKey here must not be told to
			// keep waiting for a release that will open the file.
			s, err = ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase))
			if s != nil {
				s.Destroy()
				t.Fatal("a legacy encrypted PEM was decrypted")
			}
			if !errors.Is(err, ErrUnsupportedKey) {
				t.Errorf("ParsePrivateKeyWithPassphrase: %v does not wrap ErrUnsupportedKey", err)
			}

			// Both refusals carry the marker, and both say what to do
			// instead — a refusal without a remedy is a dead end for
			// whoever holds the file, whichever entry point they tried.
			refusals := map[string]error{"ParsePrivateKey": plainErr, "ParsePrivateKeyWithPassphrase": err}
			for name, refusal := range refusals {
				if !errors.Is(refusal, ErrRetiredAlgorithm) {
					t.Errorf("%s: %v does not wrap ErrRetiredAlgorithm", name, refusal)
				}
				if !strings.Contains(refusal.Error(), "ssh-keygen -p") {
					t.Errorf("%s: the refusal %q does not say how to convert the file", name, refusal)
				}
			}
		})
	}
}

// TestErrRetiredAlgorithm_NotUsedForUnimplemented is what gives the marker
// its meaning. Everything below is refused today and may well be supported
// later — the OpenSSH ciphers this package has not written yet, and PKCS#8
// PBES2 — so none of them may claim to be retired. Without this test
// ErrRetiredAlgorithm would decay into a synonym for ErrUnsupportedKey and
// stop telling a caller anything.
func TestErrRetiredAlgorithm_NotUsedForUnimplemented(t *testing.T) {
	container := func(cipher, kdf string) []byte {
		return testContainer(cipher, kdf, testKDFOpts(16, 1), 16)
	}
	// Any key will do for the unencrypted PKCS#8 case; it only has to parse.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		data []byte
	}{
		{"chacha20-poly1305", container("chacha20-poly1305@openssh.com", "bcrypt")},
		{"aes128-ctr", container("aes128-ctr", "bcrypt")},
		{"aes192-ctr", container("aes192-ctr", "bcrypt")},
		{"unknown kdf", container("aes256-ctr", "scrypt")},
		{"pkcs8 pbes2", []byte(pemOfType("ENCRYPTED PRIVATE KEY", "", "MAAA"))},
		{"pkcs8 pbes2 der", []byte{0x30, 0x04, 0x30, 0x02, 0x05, 0x00}},
		{"pkcs8 unencrypted", []byte(pemOfType("PRIVATE KEY", "", base64.StdEncoding.EncodeToString(p8)))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := ParsePrivateKeyWithPassphrase(c.data, []byte(testPassphrase))
			if s != nil {
				s.Destroy()
				t.Fatal("want a refusal")
			}
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			if errors.Is(err, ErrRetiredAlgorithm) {
				t.Errorf("%q claims to be retired, but it is unimplemented and may yet be supported", err)
			}
		})
	}
}
