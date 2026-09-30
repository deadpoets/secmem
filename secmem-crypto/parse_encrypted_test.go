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
	"github.com/deadpoets/secmem/secmem-crypto/internal/bcryptpbkdf"
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

// encryptedFixtures lists every ssh-keygen fixture under
// testdata/openssh-encrypted, so a file added to the directory is parsed,
// seeded into the fuzzer and, if it names an AES cipher, has its schedule
// wipe observed, without a list to keep in step. A fixture left out of the
// corpus by accident is what this replaces.
func encryptedFixtures(t testing.TB) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join("testdata", "openssh-encrypted", "*.b64"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) < 11 {
		t.Fatalf("found %d fixtures under testdata/openssh-encrypted, want at least 11", len(matches))
	}
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, strings.TrimSuffix(filepath.Base(m), ".b64"))
	}
	return names
}

// TestParsePrivateKeyWithPassphrase_SSHKeygenFixtures opens files a real
// ssh-keygen wrote — the default profile, one round, every AES key size in
// both modes, and every key type — and proves each parsed signer is the key
// the .pub advertises. The aes128 and aes192 files matter because OpenSSH
// derives exactly key||IV from the KDF, so a shorter key is a shorter
// derivation: a parser that always asked for 32+16 bytes would decrypt them
// to nothing that parses. The two chacha20-poly1305 files must open; the
// second one's private block is 136 bytes, a multiple of 8 but not of 16,
// so it opens only under the cipher's own block granularity
// (TestParsePrivateKeyWithPassphrase_ChaChaBlockGranularity pins that).
func TestParsePrivateKeyWithPassphrase_SSHKeygenFixtures(t *testing.T) {
	for _, name := range encryptedFixtures(t) {
		t.Run(name, func(t *testing.T) {
			pemBytes, raw, pub := fixture(t, name)
			for form, data := range map[string][]byte{"pem": pemBytes, "raw": raw} {
				s, err := ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase), AllowHeapTransients())
				if err != nil {
					t.Fatalf("%s: %v", form, err)
				}
				verifySigner(t, s, pub)
				s.Destroy()

				// The plain parser must still name the condition.
				if _, err := ParsePrivateKey(data, AllowHeapTransients()); !errors.Is(err, ErrEncryptedKey) {
					t.Errorf("%s: ParsePrivateKey = %v, want ErrEncryptedKey", form, err)
				}
			}
		})
	}
	// chacha20-poly1305 authenticates the ciphertext, so a wrong passphrase
	// fails at the tag rather than at the format's check integers, and a
	// corrupted tag fails the same way. Both must look like a bad passphrase
	// to the caller, not like a malformed file.
	t.Run("ed25519-chacha-a1/wrong passphrase", func(t *testing.T) {
		pemBytes, _, _ := fixture(t, "ed25519-chacha-a1")
		if s, err := ParsePrivateKeyWithPassphrase(pemBytes, []byte("not it"), AllowHeapTransients()); err == nil {
			s.Destroy()
			t.Fatal("a wrong passphrase was accepted")
		} else if !errors.Is(err, x509.IncorrectPasswordError) {
			t.Fatalf("got %v, want IncorrectPasswordError", err)
		}
	})
	t.Run("ed25519-chacha-a1/corrupted tag", func(t *testing.T) {
		_, raw, _ := fixture(t, "ed25519-chacha-a1")
		bad := bytes.Clone(raw)
		bad[len(bad)-1] ^= 1 // the last byte of the trailing authenticator
		if s, err := ParsePrivateKeyWithPassphrase(bad, []byte(testPassphrase), AllowHeapTransients()); err == nil {
			s.Destroy()
			t.Fatal("a corrupted authenticator was accepted")
		} else if !errors.Is(err, x509.IncorrectPasswordError) {
			t.Fatalf("got %v, want IncorrectPasswordError", err)
		}
	})
	// The authenticator's length is part of the container's shape, judged
	// with the header before the KDF runs: one byte too few or too many
	// after the block is a malformed file, not a wrong passphrase, and the
	// error names what it wanted.
	t.Run("ed25519-chacha-a1/authenticator length", func(t *testing.T) {
		_, raw, _ := fixture(t, "ed25519-chacha-a1")
		if h, err := readOpenSSHHeader(raw); err != nil || len(h.rest) != chachaTagLen {
			t.Fatalf("fixture: header %v, %d bytes after the block, want %d", err, len(h.rest), chachaTagLen)
		}
		for name, data := range map[string][]byte{
			"none":  raw[:len(raw)-chachaTagLen],
			"short": raw[:len(raw)-1],
			"long":  append(bytes.Clone(raw), 0),
		} {
			s, err := ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase), AllowHeapTransients())
			if err == nil {
				s.Destroy()
				t.Fatalf("%s: a mis-sized authenticator was accepted", name)
			}
			if !errors.Is(err, errMalformed) || errors.Is(err, x509.IncorrectPasswordError) {
				t.Errorf("%s: %v, want errMalformed before the KDF", name, err)
			}
			if !strings.Contains(err.Error(), "authenticator") {
				t.Errorf("%s: %v does not say what it wanted", name, err)
			}
		}
	})
	// The same rule for the AES modes, which authenticate nothing: any byte
	// after the block is a malformed file, judged before the KDF. This used
	// to be accepted, as x/crypto/ssh still accepts it; OpenSSH refuses it.
	t.Run("ed25519-a1/bytes after the block", func(t *testing.T) {
		_, raw, _ := fixture(t, "ed25519-a1")
		for name, data := range map[string][]byte{
			"one byte":      append(bytes.Clone(raw), 0),
			"half a block":  append(bytes.Clone(raw), make([]byte, opensshAESBlock/2)...),
			"a tag's worth": append(bytes.Clone(raw), make([]byte, chachaTagLen)...),
		} {
			s, err := ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase), AllowHeapTransients())
			if err == nil {
				s.Destroy()
				t.Fatalf("%s: trailing bytes after an AES block were accepted", name)
			}
			if !errors.Is(err, errMalformed) || errors.Is(err, x509.IncorrectPasswordError) {
				t.Errorf("%s: %v, want errMalformed before the KDF", name, err)
			}
			if !strings.Contains(err.Error(), "authenticator") {
				t.Errorf("%s: %v does not say what it wanted", name, err)
			}
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
				s, err := ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase), AllowHeapTransients())
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
// unsupported; what follows the private block must be exactly the cipher's
// authenticator (nothing for AES, 16 bytes for chacha20-poly1305); and
// hostile KDF parameters are refused before any work.
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
		{"pkcs8 encrypted pem, empty", []byte(pemOfType(epk, "", "MAAA")), testPassphrase, errMalformed},         // PBES2 opens now (pbes2_test.go); an empty SEQUENCE is not a file
		{"pkcs8 encrypted raw, empty", []byte{0x30, 0x04, 0x30, 0x02, 0x05, 0x00}, testPassphrase, errMalformed}, // likewise
		{"legacy pem encryption", legacy, testPassphrase, ErrUnsupportedKey},
		{"kdf none", testContainer("aes256-ctr", "none", nil, 16), testPassphrase, errMalformed},               // half-encrypted: see TestParseOpenSSH_HeaderConsistency
		{"cipher none", testContainer("none", "bcrypt", testKDFOpts(16, 1), 16), testPassphrase, errMalformed}, // likewise
		{"unknown kdf", testContainer("aes256-ctr", "scrypt", testKDFOpts(16, 1), 16), testPassphrase, ErrUnsupportedKey},
		{"unsupported cipher", testContainer("aes256-gcm@openssh.com", "bcrypt", testKDFOpts(16, 1), 16), testPassphrase, ErrUnsupportedKey},
		{"rounds over cap", testContainer("aes256-ctr", "bcrypt", testKDFOpts(16, opensshMaxRounds+1), 16), testPassphrase, ErrUnsupportedKey},
		{"rounds zero", testContainer("aes256-ctr", "bcrypt", testKDFOpts(16, 0), 16), testPassphrase, errMalformed},
		{"empty salt", testContainer("aes256-ctr", "bcrypt", testKDFOpts(0, 1), 16), testPassphrase, errMalformed},
		{"kdf options trailing bytes", testContainer("aes256-ctr", "bcrypt", append(testKDFOpts(16, 1), 0), 16), testPassphrase, errMalformed},
		{"block not multiple of 16", testContainer("aes256-ctr", "bcrypt", testKDFOpts(16, 1), 24), testPassphrase, errMalformed},
		{"empty block", testContainer("aes256-ctr", "bcrypt", testKDFOpts(16, 1), 0), testPassphrase, errMalformed},
		{"aes: bytes after the block", append(testContainer("aes256-ctr", "bcrypt", testKDFOpts(16, 1), 16), 0), testPassphrase, errMalformed},
		{"aes128: bytes after the block", append(testContainer(opensshCipher128C, "bcrypt", testKDFOpts(16, 1), 16), make([]byte, 16)...), testPassphrase, errMalformed}, // a tag-sized tail is still junk for AES
		{"chacha: no authenticator", testContainer(opensshCipherChaCha, "bcrypt", testKDFOpts(16, 1), 16), testPassphrase, errMalformed},
		{"chacha: short authenticator", append(testContainer(opensshCipherChaCha, "bcrypt", testKDFOpts(16, 1), 16), make([]byte, chachaTagLen-1)...), testPassphrase, errMalformed},
		{"chacha: long authenticator", append(testContainer(opensshCipherChaCha, "bcrypt", testKDFOpts(16, 1), 16), make([]byte, chachaTagLen+1)...), testPassphrase, errMalformed},
		{"chacha: block not multiple of 8", append(testContainer(opensshCipherChaCha, "bcrypt", testKDFOpts(16, 1), 12), make([]byte, chachaTagLen)...), testPassphrase, errMalformed},
		{"not a key", []byte("hello"), testPassphrase, errMalformed},
		{"truncated container", raw[:40], testPassphrase, errMalformed},
	}
	// The synthetic containers carry a public-key block of "pub", which the
	// pre-KDF key-type check refuses as malformed too, so for the rows that
	// exist to pin a rule judged before it, the error must also name that
	// rule; otherwise the row would pass with the rule deleted.
	wantText := map[string]string{
		"aes: bytes after the block":      "authenticator",
		"aes128: bytes after the block":   "authenticator",
		"chacha: no authenticator":        "authenticator",
		"chacha: short authenticator":     "authenticator",
		"chacha: long authenticator":      "authenticator",
		"chacha: block not multiple of 8": "block size",
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ParsePrivateKeyWithPassphrase(tc.data, []byte(tc.pass), AllowHeapTransients())
			if err == nil {
				s.Destroy()
				t.Fatal("expected an error")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if text, ok := wantText[tc.name]; ok && !strings.Contains(err.Error(), text) {
				t.Fatalf("got %v, want an error naming the %s", err, text)
			}
		})
	}

	if _, err := ParsePrivateKeyWithPassphrase(pemBytes, nil, AllowHeapTransients()); err == nil || !strings.Contains(err.Error(), "empty passphrase") {
		t.Errorf("empty passphrase: got %v", err)
	}
	if _, err := ParsePrivateKeyWithPassphrase(nil, []byte("x"), AllowHeapTransients()); err == nil || !strings.Contains(err.Error(), "empty input") {
		t.Errorf("empty input: got %v", err)
	}
}

// TestParsePrivateKeyWithPassphrase_SaltBound: the KDF's salt bound is the
// file's error. A salt over bcryptpbkdf.MaxSaltLen used to surface as a
// bare bcrypt_pbkdf error matching no sentinel of this package; now it is
// malformed, refused before the KDF. A salt exactly at the bound goes
// through to the KDF, whose output then fails the block as a wrong
// passphrase would — proving the bound sits where the KDF's does.
func TestParsePrivateKeyWithPassphrase_SaltBound(t *testing.T) {
	// A public-key block the pre-KDF type check admits, so the at-bound
	// case is decided by the KDF and the block, not by the header.
	pubBlob := ssh.Marshal(struct {
		T string
		P []byte
	}{opensshKeyEd25519, make([]byte, ed25519.PublicKeySize)})
	container := func(saltLen int) []byte {
		outer := sshOuter{CipherName: opensshCipherCTR, KdfName: opensshKDFBcrypt, KdfOpts: string(testKDFOpts(saltLen, 1)), NumKeys: 1, PubKey: pubBlob, PrivKeyBlock: make([]byte, 16)}
		return append([]byte("openssh-key-v1\x00"), ssh.Marshal(outer)...)
	}
	_, err := ParsePrivateKeyWithPassphrase(container(bcryptpbkdf.MaxSaltLen+1), []byte(testPassphrase), AllowHeapTransients())
	if !errors.Is(err, errMalformed) {
		t.Fatalf("salt of MaxSaltLen+1: %v, want errMalformed", err)
	}
	if errors.Is(err, bcryptpbkdf.ErrSalt) || errors.Is(err, x509.IncorrectPasswordError) {
		t.Fatalf("salt of MaxSaltLen+1 reached the KDF: %v", err)
	}
	_, err = ParsePrivateKeyWithPassphrase(container(bcryptpbkdf.MaxSaltLen), []byte(testPassphrase), AllowHeapTransients())
	if !errors.Is(err, x509.IncorrectPasswordError) {
		t.Fatalf("salt of MaxSaltLen: %v, want the post-decryption error", err)
	}
}

// TestParsePrivateKeyWithPassphrase_DecidesBeforeKDF: what the cleartext
// public-key block settles is settled before the KDF runs. The proof is the
// passphrase: every case is parsed with a WRONG one, and after decryption
// every failure is the one post-decryption error, so any other verdict can
// only have been reached before the derivation. An unsupported type is
// ErrUnsupportedKey; an RSA or EC key on a build that cannot erase the
// signer's heap copies is ErrHeapTransients, which the plain parser reports
// for the same key, so the two entry points say the same thing; Ed25519 is
// never refused. Swaps the package policy, so no t.Parallel.
func TestParsePrivateKeyWithPassphrase_DecidesBeforeKDF(t *testing.T) {
	const wrong = "not the passphrase"
	t.Run("unsupported type", func(t *testing.T) {
		pubBlob := ssh.Marshal(struct{ T string }{"ssh-dss"})
		outer := sshOuter{CipherName: opensshCipherCTR, KdfName: opensshKDFBcrypt, KdfOpts: string(testKDFOpts(opensshSaltLen, 1)), NumKeys: 1, PubKey: pubBlob, PrivKeyBlock: make([]byte, 64)}
		data := append([]byte("openssh-key-v1\x00"), ssh.Marshal(outer)...)
		_, err := ParsePrivateKeyWithPassphrase(data, []byte(wrong), AllowHeapTransients())
		if !errors.Is(err, ErrUnsupportedKey) || !strings.Contains(err.Error(), `"ssh-dss"`) {
			t.Fatalf("%v, want ErrUnsupportedKey naming ssh-dss", err)
		}
		if errors.Is(err, x509.IncorrectPasswordError) {
			t.Fatal("the KDF ran for an unsupported key type")
		}
	})
	for _, name := range []string{"rsa-a1", "ecdsa-a1"} {
		t.Run(name+" heap gate", func(t *testing.T) {
			pemBytes, raw, pub := fixture(t, name)
			withPolicy(t, false, func() {
				for form, data := range map[string][]byte{"pem": pemBytes, "raw": raw} {
					_, err := ParsePrivateKeyWithPassphrase(data, []byte(wrong), nil)
					if !errors.Is(err, ErrHeapTransients) {
						t.Fatalf("%s: %v, want ErrHeapTransients", form, err)
					}
					if errors.Is(err, x509.IncorrectPasswordError) {
						t.Fatalf("%s: the KDF ran for a refused key", form)
					}
					// The refusal is the constructors' own: the plain parser
					// on the same kind of key reads the same.
					_, perr := ParsePrivateKey(encodings(t, testKeyNamed(t, map[string]string{"rsa-a1": "rsa2048", "ecdsa-a1": "p256"}[name]))[1].data)
					if !errors.Is(perr, ErrHeapTransients) || perr.Error() != err.Error() {
						t.Fatalf("%s: entry points disagree:\n  plain:      %v\n  passphrase: %v", form, perr, err)
					}
				}
				// With the option, the same file opens under the same policy.
				s, err := ParsePrivateKeyWithPassphrase(pemBytes, []byte(testPassphrase), AllowHeapTransients())
				if err != nil {
					t.Fatal(err)
				}
				verifySigner(t, s, pub)
				s.Destroy()
			})
		})
	}
	t.Run("ed25519 never refused", func(t *testing.T) {
		pemBytes, _, pub := fixture(t, "ed25519-a1")
		withPolicy(t, false, func() {
			s, err := ParsePrivateKeyWithPassphrase(pemBytes, []byte(testPassphrase))
			if err != nil {
				t.Fatal(err)
			}
			verifySigner(t, s, pub)
			s.Destroy()
		})
	})
}

// testKeyNamed is the parseTestKeys entry with the given name.
func testKeyNamed(t *testing.T, name string) parseTestKey {
	t.Helper()
	for _, k := range parseTestKeys(t) {
		if k.name == name {
			return k
		}
	}
	t.Fatalf("no test key named %q", name)
	return parseTestKey{}
}

// TestParsePrivateKeyWithPassphrase_PostDecryptionIsBinary is the proof
// behind the entry point's promise that, once the KDF has run, the only
// thing an error says is that the block did not become a key. For each
// ssh-keygen fixture — aes256-cbc and aes256-ctr, Ed25519, ECDSA and RSA —
// the private block's ciphertext is modified one byte at a time, at every
// offset (Ed25519) or a stride of them (the larger keys), and parsed with
// the CORRECT passphrase. Depending on where the damage lands the parser
// sees a check-integer mismatch, a length that overruns, a bad pad, halves
// that disagree, a scalar out of range or an RSA key the standard library
// rejects; every one of those must come back as the same error string, the
// one a wrong passphrase gives, wrapping x509.IncorrectPasswordError.
//
// The comment is the residual: no reader validates it, so under CTR a flip
// inside it leaves a key that opens, and the test requires exactly that —
// success at every comment offset (proving the flips do reach the
// plaintext) and at no other. Under CBC a flip garbles its whole plaintext
// block and one byte of the next, and the fixtures' comments never fill a
// block, so every offset must fail. The comment's position is read from
// the plaintext the test decrypts itself, not assumed.
//
// The chacha20-poly1305 fixture is held to the same string: there the
// authenticator catches every flip, the comment included, so no offset may
// open and every failure must read exactly as the AES files' do — the
// cipher is not visible in the answer.
func TestParsePrivateKeyWithPassphrase_PostDecryptionIsBinary(t *testing.T) {
	_, raw, _ := fixture(t, "ed25519-a1")
	_, wrongErr := ParsePrivateKeyWithPassphrase(raw, []byte("not it"), AllowHeapTransients())
	if !errors.Is(wrongErr, x509.IncorrectPasswordError) {
		t.Fatalf("wrong passphrase: %v", wrongErr)
	}
	want := wrongErr.Error()

	for _, tc := range []struct {
		name   string
		stride int
	}{{"ed25519-cbc-a1", 1}, {"ed25519-a1", 1}, {"ed25519-chacha-a1", 1}, {"ecdsa-a1", 3}, {"rsa-a1", 7}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel() // a few hundred derivations per fixture; the fixtures share nothing
			_, raw, pub := fixture(t, tc.name)
			h, err := readOpenSSHHeader(raw)
			if err != nil {
				t.Fatal(err)
			}
			mode := opensshCipherByName(h.cipher)
			cbc, aead := mode.cbc(), mode.tagLen() != 0
			commentStart, commentEnd := commentRange(t, raw)
			n := len(h.privBlock)
			var opened, failed int
			for off := 0; off < n; off += tc.stride {
				d := append([]byte(nil), raw...)
				hh, _ := readOpenSSHHeader(d)
				hh.privBlock[off] ^= 0x01
				s, err := ParsePrivateKeyWithPassphrase(d, []byte(testPassphrase), AllowHeapTransients())
				inComment := off >= commentStart && off < commentEnd
				if err == nil {
					opened++
					verifySigner(t, s, pub)
					s.Destroy()
					switch {
					case aead:
						t.Errorf("aead: flip at %d opened (the authenticator passed a modified ciphertext)", off)
					case cbc:
						t.Errorf("cbc: flip at %d opened (a garbled block passed every check)", off)
					case !inComment:
						t.Errorf("ctr: flip at %d, outside the comment [%d,%d), opened", off, commentStart, commentEnd)
					}
					continue
				}
				failed++
				if !cbc && !aead && inComment {
					t.Errorf("ctr: flip at %d, inside the comment, failed: %v", off, err)
				}
				if got := err.Error(); got != want {
					t.Errorf("flip at %d: error differs from the wrong-passphrase error:\n  got:  %s\n  want: %s", off, got, want)
				}
				if !errors.Is(err, x509.IncorrectPasswordError) {
					t.Errorf("flip at %d: %v does not wrap x509.IncorrectPasswordError", off, err)
				}
			}
			if failed == 0 {
				t.Fatal("no flip failed; the test is not reaching the block")
			}
			if !cbc && !aead && opened == 0 {
				t.Fatal("ctr: no flip in the comment opened; the comment range is wrong")
			}
			t.Logf("%d offsets: %d opened (comment), %d failed identically", (n+tc.stride-1)/tc.stride, opened, failed)
		})
	}
}

// commentRange decrypts a protected fixture with the test passphrase and
// walks the plaintext to the comment field, returning the offsets of its
// bytes within the private block: [start, end). It reads the type-specific
// field count off the key type, as the parser does.
func commentRange(t *testing.T, raw []byte) (start, end int) {
	t.Helper()
	h, err := readOpenSSHHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	salt, rounds := kdfOptsOf(t, raw)
	plain := make([]byte, len(h.privBlock))
	defer secmem.SecureWipe(plain)
	if err := opensshCrypt(plain, h.privBlock, h.rest, []byte(testPassphrase), salt, int(rounds), opensshCipherByName(h.cipher), true); err != nil {
		t.Fatal(err)
	}
	r := sshReader{plain}
	if _, ok := r.uint32(); !ok {
		t.Fatal("short block")
	}
	if _, ok := r.uint32(); !ok {
		t.Fatal("short block")
	}
	keyType, ok := r.str()
	if !ok {
		t.Fatal("short block")
	}
	var fields int
	switch string(keyType) {
	case "ssh-ed25519":
		fields = 2
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		fields = 3
	case "ssh-rsa":
		fields = 6
	default:
		t.Fatalf("unexpected key type %q in fixture", keyType)
	}
	for range fields {
		if _, ok := r.str(); !ok {
			t.Fatal("short block")
		}
	}
	start = len(plain) - len(r.b) + 4
	comment, ok := r.str()
	if !ok || len(comment) == 0 {
		t.Fatal("fixture has no comment; the test needs one to find the residual")
	}
	return start, start + len(comment)
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
		_, err := ParsePrivateKeyWithPassphrase(data, []byte(wrong), AllowHeapTransients())
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
// returned — for every AES key size and mode a file can name, since a
// 16- or 24-byte key expands to a shorter schedule in the same arrays.
// Must not call t.Parallel(): it swaps a package var.
func TestParsePrivateKeyWithPassphrase_WipesAESBlock(t *testing.T) {
	for _, name := range encryptedFixtures(t) {
		pemBytes, raw, pub := fixture(t, name)
		h, err := readOpenSSHHeader(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(h.cipher), "aes") {
			continue // chacha20-poly1305 has no AES schedule; the fixture loop opens it
		}
		t.Run(name, func(t *testing.T) {
			var fired, blank int
			var aliased [][]byte
			orig := wipeAESBlock
			wipeAESBlock = func(b cipher.Block) error {
				fired++
				for _, f := range aesRoundKeyFields {
					if keys, err := aesRoundKeys(b, f); err == nil {
						if bytes.Equal(keys, make([]byte, len(keys))) {
							blank++ // a schedule that is all zero before the wipe is not the schedule
						}
						aliased = append(aliased, keys)
					}
				}
				return orig(b)
			}
			defer func() { wipeAESBlock = orig }()

			s, err := ParsePrivateKeyWithPassphrase(pemBytes, []byte(testPassphrase), AllowHeapTransients())
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
			if blank != 0 {
				t.Fatalf("%d round-key arrays were all zero before the wipe", blank)
			}
			for i, keys := range aliased {
				if !bytes.Equal(keys, make([]byte, len(keys))) {
					t.Fatalf("round keys %q live after the parse returned", aesRoundKeyFields[i])
				}
			}
		})
	}
}

// TestParsePrivateKeyWithPassphrase_ChaChaBlockGranularity is what makes the
// second chacha fixture earn its place: its private block is a multiple of
// 8 but not of 16, so it opens only if the block and pad rules use
// chacha20-poly1305's own block size (8, as OpenSSH's cipher table gives
// it) rather than AES's. The first fixture's 144-byte block is a multiple of
// both and could not tell the two apart. The length is asserted here so a
// regenerated fixture with a longer comment cannot quietly stop guarding.
func TestParsePrivateKeyWithPassphrase_ChaChaBlockGranularity(t *testing.T) {
	t.Parallel()
	pemBytes, raw, pub := fixture(t, "ed25519-chacha-c3-a1")
	h, err := readOpenSSHHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(h.cipher) != opensshCipherChaCha {
		t.Fatalf("fixture names cipher %q, want %s", h.cipher, opensshCipherChaCha)
	}
	if n := len(h.privBlock); n%8 != 0 || n%16 == 0 {
		t.Fatalf("fixture's private block is %d bytes; want a multiple of 8 that is not a multiple of 16", n)
	}
	s, err := ParsePrivateKeyWithPassphrase(pemBytes, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("a chacha20-poly1305 file whose block is 8 mod 16 did not open: %v", err)
	}
	defer s.Destroy()
	verifySigner(t, s, pub)
}

// TestParsePrivateKeyWithPassphrase_FailsClosedWhenWipeCannot pins the
// stance for toolchains where the schedule cannot be located: the parse
// fails rather than returning a signer with the schedule left on the heap.
func TestParsePrivateKeyWithPassphrase_FailsClosedWhenWipeCannot(t *testing.T) {
	pemBytes, _, _ := fixture(t, "ed25519-a1")
	orig := wipeAESBlock
	wipeAESBlock = func(cipher.Block) error { return errors.New("simulated: round keys NOT wiped") }
	defer func() { wipeAESBlock = orig }()
	s, err := ParsePrivateKeyWithPassphrase(pemBytes, []byte(testPassphrase), AllowHeapTransients())
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
			s, perr = ParsePrivateKeyWithPassphrase(f, p, AllowHeapTransients())
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
	for _, name := range encryptedFixtures(f) {
		pemBytes, raw, _ := fixture(f, name)
		if _, rounds, ok := readKDFOpts(raw); ok && rounds > 4 {
			continue // the body below skips such inputs; seeding one would seed nothing
		}
		f.Add(pemBytes)
		f.Add(raw)
	}
	// The PBES2 fixtures, under the same rule for the cost they name: PBKDF2
	// is cheap per iteration, so the bound is a few thousand rather than
	// four, which admits openssl's 2048 default and excludes the 600 000 file.
	for _, name := range pkcs8Fixtures(f) {
		pemBytes, raw, _ := pkcs8Fixture(f, name)
		if iter, ok := pbes2IterationsOf(raw); ok && iter > fuzzMaxPBKDF2Iterations {
			continue
		}
		f.Add(pemBytes)
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, rounds, ok := readKDFOpts(data); ok && rounds > 4 {
			t.Skip("rounds > 4")
		}
		if iter, ok := pbes2IterationsOf(data); ok && iter > fuzzMaxPBKDF2Iterations {
			t.Skip("PBKDF2 iterations over the fuzzing bound")
		}
		s, err := ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase), AllowHeapTransients())
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

// fuzzMaxPBKDF2Iterations bounds the PBKDF2 count a fuzz input may name.
const fuzzMaxPBKDF2Iterations = 4096

// pbes2IterationsOf reads the PBKDF2 iteration count out of a PKCS#8
// EncryptedPrivateKeyInfo, PEM or raw, as the parser would; ok is false
// for anything that is not one the parser accepts up to that field. It
// allocates freely: it is a fuzzing guard, not the parser.
func pbes2IterationsOf(data []byte) (int, bool) {
	der := data
	if bytes.Contains(data, pemBegin) {
		typ, body, err := pemBlock(data)
		if err != nil || string(typ) != pkcs8PEMType {
			return 0, false
		}
		der, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), ""))
		if err != nil {
			return 0, false
		}
	}
	f, err := readPBES2(der)
	if err != nil {
		return 0, false
	}
	return f.iter, true
}

// testContainer builds an OpenSSH container with a hand-written header,
// for tests whose parse stops in the header: the private block is filler
// of the requested length and is never reached.
func testContainer(cipher, kdf string, kdfOpts []byte, privLen int) []byte {
	outer := sshOuter{CipherName: cipher, KdfName: kdf, KdfOpts: string(kdfOpts), NumKeys: 1, PubKey: []byte("pub"), PrivKeyBlock: make([]byte, privLen)}
	return append([]byte("openssh-key-v1\x00"), ssh.Marshal(outer)...)
}

// testKDFOpts marshals bcrypt's KDF options: a zero salt of saltLen bytes,
// then rounds.
func testKDFOpts(saltLen int, rounds uint32) []byte {
	return ssh.Marshal(struct {
		Salt   []byte
		Rounds uint32
	}{make([]byte, saltLen), rounds})
}

// kdfOptsIn reads the bcrypt salt and round count out of a parsed header
// the way the parser does: the options must be exactly a salt and a count.
func kdfOptsIn(h opensshHeader) (salt []byte, rounds uint32, ok bool) {
	if string(h.kdf) != opensshKDFBcrypt {
		return nil, 0, false
	}
	o := sshReader{h.kdfOpts}
	salt, ok1 := o.str()
	rounds, ok2 := o.uint32()
	if !ok1 || !ok2 || len(o.b) != 0 {
		return nil, 0, false
	}
	return salt, rounds, true
}

// readKDFOpts is kdfOptsIn over a whole container, PEM-armoured or raw. It
// never fails a test, so the fuzz target can use it as a cost estimate.
func readKDFOpts(data []byte) (salt []byte, rounds uint32, ok bool) {
	raw := data
	if !bytes.HasPrefix(data, opensshMagic) {
		_, body, err := pemBlock(data)
		if err != nil {
			return nil, 0, false
		}
		raw, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), ""))
		if err != nil {
			return nil, 0, false
		}
	}
	h, err := readOpenSSHHeader(raw)
	if err != nil {
		return nil, 0, false
	}
	return kdfOptsIn(h)
}

// kdfOptsOf is readKDFOpts for a test that requires the options to be
// there. The count is public: it has to be, since whoever opens the file
// needs it.
func kdfOptsOf(t testing.TB, data []byte) (salt []byte, rounds uint32) {
	t.Helper()
	salt, rounds, ok := readKDFOpts(data)
	if !ok {
		t.Fatal("could not read the bcrypt KDF options")
	}
	return salt, rounds
}
