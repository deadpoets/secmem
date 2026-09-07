package secmemcrypto

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/deadpoets/secmem"
)

// pemEncodeToMemory is encoding/pem's, named so the tests read as what they
// hand to the parser.
func pemEncodeToMemory(block *pem.Block) []byte { return pem.EncodeToMemory(block) }

// mustBuffer copies b into a SecureBuffer, skipping when the platform
// refuses to lock memory (an environment condition, not a finding).
func mustBuffer(t testing.TB, b []byte) *secmem.SecureBuffer {
	t.Helper()
	buf, err := secmem.NewBuffer(append([]byte(nil), b...))
	if err != nil {
		t.Skipf("NewBuffer: %v", err)
	}
	return buf
}

// checkSignerConsistent requires a parsed signer to verify under its own
// Public(), whatever its algorithm.
func checkSignerConsistent(t *testing.T, s Signer) {
	t.Helper()
	msg := []byte("fuzz")
	switch p := s.Public().(type) {
	case ed25519.PublicKey:
		sig, err := s.Sign(nil, msg, nil)
		if err != nil || !ed25519.Verify(p, msg, sig) {
			t.Fatalf("ed25519 signer from parsed key is inconsistent: %v", err)
		}
	case *ecdsa.PublicKey:
		h := sha256.Sum256(msg)
		sig, err := s.Sign(rand.Reader, h[:], crypto.SHA256)
		if err != nil || !ecdsa.VerifyASN1(p, h[:], sig) {
			t.Fatalf("ecdsa signer from parsed key is inconsistent: %v", err)
		}
	case *rsa.PublicKey:
		h := sha256.Sum256(msg)
		sig, err := s.Sign(rand.Reader, h[:], crypto.SHA256)
		if err != nil || rsa.VerifyPKCS1v15(p, crypto.SHA256, h[:], sig) != nil {
			t.Fatalf("rsa signer from parsed key is inconsistent: %v", err)
		}
	default:
		t.Fatalf("unexpected public key type %T", p)
	}
}

// testPassphrase protects every fixture in testdata/openssh-encrypted and
// every key the tests here encrypt.
const testPassphrase = "secmem-test-passphrase"

// armour wraps a base64 body in the OpenSSH PEM header and footer,
// assembled from the parser's own constants so no literal armour appears
// in the source.
func armour(body []byte) []byte {
	var b bytes.Buffer
	b.Write(pemBegin)
	b.WriteString(opensshPEMType)
	b.Write(pemDashes)
	b.WriteByte('\n')
	b.Write(body)
	if len(body) > 0 && body[len(body)-1] != '\n' {
		b.WriteByte('\n')
	}
	b.Write(pemEnd)
	b.WriteString(opensshPEMType)
	b.Write(pemDashes)
	b.WriteByte('\n')
	return b.Bytes()
}

// fixture returns one ssh-keygen-written file as PEM and raw bytes, and the
// public key from its .pub.
func fixture(t testing.TB, name string) (pemBytes, raw []byte, pub crypto.PublicKey) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "openssh-encrypted", name+".b64"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), ""))
	if err != nil {
		t.Fatal(err)
	}
	pubLine, err := os.ReadFile(filepath.Join("testdata", "openssh-encrypted", name+".pub"))
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _, _, _, err := ssh.ParseAuthorizedKey(pubLine)
	if err != nil {
		t.Fatal(err)
	}
	cp, ok := sshPub.(ssh.CryptoPublicKey)
	if !ok {
		t.Fatalf("%s: public key %T has no crypto.PublicKey", name, sshPub)
	}
	return armour(body), raw, cp.CryptoPublicKey()
}

// TestParsePrivateKeyWithPassphrase_SSHKeygenFixtures opens files a real
// ssh-keygen wrote — the default profile, one round, CBC, and every key
// type — and proves each parsed signer is the key the .pub advertises.
// The chacha20-poly1305 file must be refused by name.
func TestParsePrivateKeyWithPassphrase_SSHKeygenFixtures(t *testing.T) {
	for _, name := range []string{"ed25519-a16", "ed25519-a1", "ed25519-cbc-a1", "ecdsa-a1", "rsa-a1"} {
		t.Run(name, func(t *testing.T) {
			pemBytes, raw, pub := fixture(t, name)
			for form, data := range map[string][]byte{"pem": pemBytes, "raw": raw} {
				s, err := ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase))
				if err != nil {
					t.Fatalf("%s: %v", form, err)
				}
				verifySigner(t, s, pub)
				s.Destroy()

				// The plain parser must still name the condition.
				if _, err := ParsePrivateKey(data); !errors.Is(err, ErrEncryptedKey) {
					t.Errorf("%s: ParsePrivateKey = %v, want ErrEncryptedKey", form, err)
				}
			}
		})
	}
	t.Run("ed25519-chacha-a1", func(t *testing.T) {
		pemBytes, _, _ := fixture(t, "ed25519-chacha-a1")
		s, err := ParsePrivateKeyWithPassphrase(pemBytes, []byte(testPassphrase))
		if err == nil {
			s.Destroy()
			t.Fatal("chacha20-poly1305 file was accepted")
		}
		if !errors.Is(err, ErrUnsupportedKey) || !strings.Contains(err.Error(), "chacha20-poly1305@openssh.com") {
			t.Fatalf("got %v, want ErrUnsupportedKey naming the cipher", err)
		}
	})
}

// TestParsePrivateKeyWithPassphrase_XCryptoRoundTrip parses what
// x/crypto/ssh encrypts (aes256-ctr, 16 rounds) for every key type it can
// marshal, PEM and raw.
func TestParsePrivateKeyWithPassphrase_XCryptoRoundTrip(t *testing.T) {
	for _, k := range parseTestKeys(t) {
		if !k.openssh {
			continue
		}
		t.Run(k.name, func(t *testing.T) {
			block, err := ssh.MarshalPrivateKeyWithPassphrase(k.priv, "a comment", []byte(testPassphrase))
			if err != nil {
				t.Fatal(err)
			}
			for form, data := range map[string][]byte{"pem": pemEncodeToMemory(block), "raw": block.Bytes} {
				s, err := ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase))
				if err != nil {
					t.Fatalf("%s: %v", form, err)
				}
				verifySigner(t, s, k.pub)
				s.Destroy()
			}
		})
	}
}

// TestParsePrivateKeyWithPassphrase_Rejects pins every refusal and its
// error identity: the wrong passphrase is x509.IncorrectPasswordError as in
// x/crypto; a file that is not protected is ErrNotEncrypted, whatever its
// container; the encryption schemes this parser does not run are named as
// unsupported; and hostile KDF parameters are refused before any work.
func TestParsePrivateKeyWithPassphrase_Rejects(t *testing.T) {
	pemBytes, raw, _ := fixture(t, "ed25519-a1")
	plain := parseTestKeys(t)[0]
	plainBlock, err := ssh.MarshalPrivateKey(plain.priv, "")
	if err != nil {
		t.Fatal(err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(plain.priv)
	if err != nil {
		t.Fatal(err)
	}
	const pk, epk, rsaPK = "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY"
	legacy := []byte(pemOfType(rsaPK, "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\n", "AAAA"))

	// Containers with a bad header, built by hand; the private block is
	// never reached, so it is filler of a valid length.
	container := func(cipher, kdf string, kdfOpts []byte, privLen int) []byte {
		outer := sshOuter{CipherName: cipher, KdfName: kdf, KdfOpts: string(kdfOpts), NumKeys: 1, PubKey: []byte("pub"), PrivKeyBlock: make([]byte, privLen)}
		return append([]byte("openssh-key-v1\x00"), ssh.Marshal(outer)...)
	}
	kdfOpts := func(saltLen int, rounds uint32) []byte {
		return ssh.Marshal(struct {
			Salt   []byte
			Rounds uint32
		}{make([]byte, saltLen), rounds})
	}

	cases := []struct {
		name string
		data []byte
		pass string
		want error
	}{
		{"wrong passphrase pem", pemBytes, "not it", x509.IncorrectPasswordError},
		{"wrong passphrase raw", raw, "not it", x509.IncorrectPasswordError},
		{"unencrypted openssh pem", pemEncodeToMemory(plainBlock), testPassphrase, ErrNotEncrypted},
		{"unencrypted openssh raw", plainBlock.Bytes, testPassphrase, ErrNotEncrypted},
		{"pkcs8 pem", []byte(pemOfType(pk, "", base64.StdEncoding.EncodeToString(p8))), testPassphrase, ErrNotEncrypted},
		{"pkcs8 raw", p8, testPassphrase, ErrNotEncrypted},
		{"pkcs8 encrypted pem", []byte(pemOfType(epk, "", "MAAA")), testPassphrase, ErrUnsupportedKey},
		{"pkcs8 encrypted raw", []byte{0x30, 0x04, 0x30, 0x02, 0x05, 0x00}, testPassphrase, ErrUnsupportedKey},
		{"legacy pem encryption", legacy, testPassphrase, ErrUnsupportedKey},
		{"kdf none", container("aes256-ctr", "none", nil, 16), testPassphrase, ErrNotEncrypted},
		{"cipher none", container("none", "bcrypt", kdfOpts(16, 1), 16), testPassphrase, ErrNotEncrypted},
		{"unknown kdf", container("aes256-ctr", "scrypt", kdfOpts(16, 1), 16), testPassphrase, ErrUnsupportedKey},
		{"aes128", container("aes128-ctr", "bcrypt", kdfOpts(16, 1), 16), testPassphrase, ErrUnsupportedKey},
		{"rounds over cap", container("aes256-ctr", "bcrypt", kdfOpts(16, opensshMaxRounds+1), 16), testPassphrase, ErrUnsupportedKey},
		{"rounds zero", container("aes256-ctr", "bcrypt", kdfOpts(16, 0), 16), testPassphrase, errMalformed},
		{"empty salt", container("aes256-ctr", "bcrypt", kdfOpts(0, 1), 16), testPassphrase, errMalformed},
		{"kdf options trailing bytes", container("aes256-ctr", "bcrypt", append(kdfOpts(16, 1), 0), 16), testPassphrase, errMalformed},
		{"block not multiple of 16", container("aes256-ctr", "bcrypt", kdfOpts(16, 1), 24), testPassphrase, errMalformed},
		{"empty block", container("aes256-ctr", "bcrypt", kdfOpts(16, 1), 0), testPassphrase, errMalformed},
		{"not a key", []byte("hello"), testPassphrase, errMalformed},
		{"truncated container", raw[:40], testPassphrase, errMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ParsePrivateKeyWithPassphrase(tc.data, []byte(tc.pass))
			if err == nil {
				s.Destroy()
				t.Fatal("expected an error")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	if _, err := ParsePrivateKeyWithPassphrase(pemBytes, nil); err == nil || !strings.Contains(err.Error(), "empty passphrase") {
		t.Errorf("empty passphrase: got %v", err)
	}
	if _, err := ParsePrivateKeyWithPassphrase(nil, []byte("x")); err == nil || !strings.Contains(err.Error(), "empty input") {
		t.Errorf("empty input: got %v", err)
	}
}

// pemOfType renders a PEM block with optional header lines from parts, so
// no literal armour appears in the source.
func pemOfType(typ, headers, body string) string {
	return string(pemBegin) + typ + string(pemDashes) + "\n" + headers + body + "\n" + string(pemEnd) + typ + string(pemDashes) + "\n"
}

// TestParsePrivateKeyWithPassphrase_ErrorsCarryNoSecret: neither the
// passphrase nor any byte of the file may appear in an error.
func TestParsePrivateKeyWithPassphrase_ErrorsCarryNoSecret(t *testing.T) {
	pemBytes, raw, _ := fixture(t, "ed25519-a1")
	const wrong = "a-distinctive-wrong-passphrase"
	body := strings.Join(strings.Fields(string(pemBytes[bytes.IndexByte(pemBytes, '\n')+1:])), "")
	for _, data := range [][]byte{pemBytes, raw, raw[:60]} {
		_, err := ParsePrivateKeyWithPassphrase(data, []byte(wrong))
		if err == nil {
			t.Fatal("expected an error")
		}
		msg := err.Error()
		if strings.Contains(msg, wrong) {
			t.Fatalf("error quotes the passphrase: %q", msg)
		}
		for i := 0; i+16 <= len(body); i += 16 {
			if strings.Contains(msg, body[i:i+16]) {
				t.Fatalf("error quotes the file: %q", msg)
			}
		}
		if bytes.Contains([]byte(msg), raw[len(raw)-16:]) {
			t.Fatalf("error carries raw file bytes: %q", msg)
		}
	}
}

// TestParsePrivateKeyWithPassphrase_WipesAESBlock wraps the package's wipe
// var to alias the round keys at the moment the decrypt path wipes them,
// and asserts that exact backing array is zero once the parse has
// returned. Must not call t.Parallel(): it swaps a package var.
func TestParsePrivateKeyWithPassphrase_WipesAESBlock(t *testing.T) {
	pemBytes, _, pub := fixture(t, "ed25519-a1")
	var fired int
	var aliased [][]byte
	orig := wipeAESBlock
	wipeAESBlock = func(b cipher.Block) error {
		fired++
		for _, f := range aesRoundKeyFields {
			if keys, err := aesRoundKeys(b, f); err == nil {
				aliased = append(aliased, keys)
			}
		}
		return orig(b)
	}
	defer func() { wipeAESBlock = orig }()

	s, err := ParsePrivateKeyWithPassphrase(pemBytes, []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	verifySigner(t, s, pub)
	s.Destroy()
	if fired != 1 {
		t.Fatalf("wipeAESBlock fired %d times, want 1", fired)
	}
	if len(aliased) != len(aesRoundKeyFields) {
		t.Fatalf("aliased %d schedules, want %d", len(aliased), len(aesRoundKeyFields))
	}
	for i, keys := range aliased {
		if !bytes.Equal(keys, make([]byte, len(keys))) {
			t.Fatalf("round keys %q live after the parse returned", aesRoundKeyFields[i])
		}
	}
}

// TestParsePrivateKeyWithPassphrase_FailsClosedWhenWipeCannot pins the
// stance for toolchains where the schedule cannot be located: the parse
// fails rather than returning a signer with the schedule left on the heap.
func TestParsePrivateKeyWithPassphrase_FailsClosedWhenWipeCannot(t *testing.T) {
	pemBytes, _, _ := fixture(t, "ed25519-a1")
	orig := wipeAESBlock
	wipeAESBlock = func(cipher.Block) error { return errors.New("simulated: round keys NOT wiped") }
	defer func() { wipeAESBlock = orig }()
	s, err := ParsePrivateKeyWithPassphrase(pemBytes, []byte(testPassphrase))
	if err == nil {
		s.Destroy()
		t.Fatal("parse succeeded although the AES schedule could not be wiped")
	}
	if !strings.Contains(err.Error(), "NOT wiped") {
		t.Fatalf("error does not carry the wipe failure: %v", err)
	}
}

// TestParsePrivateKeyWithPassphrase_FromSecureBuffer is the documented
// calling shape: file and passphrase both borrowed from SecureBuffers.
func TestParsePrivateKeyWithPassphrase_FromSecureBuffer(t *testing.T) {
	pemBytes, _, pub := fixture(t, "ed25519-a1")
	file := mustBuffer(t, pemBytes)
	defer file.Destroy()
	pass := mustBuffer(t, []byte(testPassphrase))
	defer pass.Destroy()
	var s Signer
	err := file.WithBytesErr(func(f []byte) error {
		return pass.WithBytesErr(func(p []byte) error {
			var perr error
			s, perr = ParsePrivateKeyWithPassphrase(f, p)
			return perr
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()
	verifySigner(t, s, pub)
}

// FuzzParsePrivateKeyWithPassphrase: no input may panic, hang, or leak a
// buffer, and any input that opens must yield a self-consistent signer.
// Files that name more than four KDF rounds are skipped — cost is linear in
// rounds and the mutator would otherwise spend its time in bcrypt.
func FuzzParsePrivateKeyWithPassphrase(f *testing.F) {
	for _, name := range []string{"ed25519-a1", "ed25519-cbc-a1", "ecdsa-a1", "rsa-a1", "ed25519-chacha-a1"} {
		pemBytes, raw, _ := fixture(f, name)
		f.Add(pemBytes)
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if rounds, ok := fuzzRounds(data); ok && rounds > 4 {
			t.Skip("rounds > 4")
		}
		s, err := ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase))
		if err != nil {
			if s != nil {
				t.Fatal("error with a non-nil signer")
			}
			return
		}
		defer s.Destroy()
		checkSignerConsistent(t, s)
	})
}

// fuzzRounds reads the bcrypt round count out of a container, PEM or raw,
// for the fuzz target's cost cap; ok is false when there is none to read.
func fuzzRounds(data []byte) (uint32, bool) {
	raw := data
	if !bytes.HasPrefix(data, opensshMagic) {
		_, body, err := pemBlock(data)
		if err != nil {
			return 0, false
		}
		raw, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), ""))
		if err != nil {
			return 0, false
		}
	}
	h, err := readOpenSSHHeader(raw)
	if err != nil || string(h.kdf) != opensshKDFBcrypt {
		return 0, false
	}
	o := sshReader{h.kdfOpts}
	if _, ok := o.str(); !ok {
		return 0, false
	}
	return o.uint32()
}
