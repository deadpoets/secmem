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
			s, err := ParsePrivateKey(data, AllowHeapTransients())
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
			s, err = ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase), AllowHeapTransients())
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
// later — an OpenSSH cipher this package does not run (the AES-GCM pair),
// an unknown KDF, and the AES-GCM schemes of PKCS#8 PBES2 — or is refused
// for what it would cost rather than for what it is: RFC 7914's own example
// file, scrypt at sixteen times MaxScryptMemory. None of them may claim to
// be retired. Without this test ErrRetiredAlgorithm would decay into a
// synonym for ErrUnsupportedKey and stop telling a caller anything. PBES2
// itself opens now, under PBKDF2 and under scrypt (pbes2_test.go).
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
	scryptPEM, scryptRaw := pkcs8RefusedFixture(t, "scrypt-rfc7914")

	cases := []struct {
		name string
		data []byte
	}{
		{"aes256-gcm", container("aes256-gcm@openssh.com", "bcrypt")},
		{"aes128-gcm", container("aes128-gcm@openssh.com", "bcrypt")},
		{"unknown kdf", container("aes256-ctr", "scrypt")},
		{"pkcs8 pbes2 scrypt over the memory cap", scryptPEM},
		{"pkcs8 pbes2 scrypt over the memory cap, der", scryptRaw},
		{"pkcs8 pbes2 aes-gcm", encryptPKCS8(t, p8, pbes2Spec{scheme: oidAES256GCM})},
		{"pkcs8 unencrypted", []byte(pemOfType("PRIVATE KEY", "", base64.StdEncoding.EncodeToString(p8)))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := ParsePrivateKeyWithPassphrase(c.data, []byte(testPassphrase), AllowHeapTransients())
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

// TestPKCS8LegacyPBE_RefusedAsPolicy is the PKCS#8 counterpart of the
// legacy-PEM test above, on real files openssl wrote: PBES1
// (pbeWithMD5AndDES-CBC), the PKCS#12 PBEs (SHA-1 with 3DES and with 40-bit
// RC2 — the default openssl pkcs8 -topk8 wrote before 1.1.0) and PBES2
// over 3DES or RC2. Every one derives its key with a single-pass MD5 or
// SHA-1 construction and encrypts with a cipher this package does not run,
// and each entry point's refusal carries ErrRetiredAlgorithm alongside its
// usual sentinel and names the command that converts the file. As above,
// adding support would mean deleting this test on purpose.
func TestPKCS8LegacyPBE_RefusedAsPolicy(t *testing.T) {
	for _, name := range []string{"pbe-md5-des", "pbe-sha1-3des", "pbe-sha1-rc2-40", "pbes2-des-ede3-cbc", "pbes2-rc2-cbc"} {
		t.Run(name, func(t *testing.T) {
			pemBytes, raw := pkcs8RefusedFixture(t, name)
			for form, data := range map[string][]byte{"pem": pemBytes, "raw": raw} {
				s, err := ParsePrivateKey(data, AllowHeapTransients())
				if s != nil {
					s.Destroy()
					t.Fatalf("%s: a retired PBE file was parsed", form)
				}
				if !errors.Is(err, ErrEncryptedKey) {
					t.Errorf("%s: ParsePrivateKey: %v does not wrap ErrEncryptedKey", form, err)
				}
				plainErr := err

				s, err = ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase), AllowHeapTransients())
				if s != nil {
					s.Destroy()
					t.Fatalf("%s: a retired PBE file was decrypted", form)
				}
				if !errors.Is(err, ErrUnsupportedKey) {
					t.Errorf("%s: ParsePrivateKeyWithPassphrase: %v does not wrap ErrUnsupportedKey", form, err)
				}
				refusals := map[string]error{"ParsePrivateKey": plainErr, "ParsePrivateKeyWithPassphrase": err}
				for entry, refusal := range refusals {
					if !errors.Is(refusal, ErrRetiredAlgorithm) {
						t.Errorf("%s/%s: %v does not wrap ErrRetiredAlgorithm", form, entry, refusal)
					}
					if !strings.Contains(refusal.Error(), "openssl pkcs8 -topk8") {
						t.Errorf("%s/%s: the refusal %q does not say how to convert the file", form, entry, refusal)
					}
				}
			}
		})
	}
}
