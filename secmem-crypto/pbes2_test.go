package secmemcrypto

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"hash"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	xscrypt "golang.org/x/crypto/scrypt"

	"github.com/deadpoets/secmem"
)

const pkcs8PEMType = "ENCRYPTED PRIVATE KEY"

// pkcs8Fixture loads a PBES2 fixture from testdata/pkcs8-encrypted: the
// PEM form (armour restored), the raw DER, and the public key from the
// matching .pub, so a parsed signer can be checked against what openssl
// derived.
func pkcs8Fixture(t testing.TB, name string) (pemBytes, raw []byte, pub crypto.PublicKey) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "pkcs8-encrypted", name+".b64"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), ""))
	if err != nil {
		t.Fatal(err)
	}
	pubName := map[string]string{"ed25519": "ed25519", "ecdsa": "ecdsa-p256", "rsa": "rsa-2048"}[strings.SplitN(name, "-", 2)[0]]
	pubPEM, err := os.ReadFile(filepath.Join("testdata", "pkcs8-encrypted", pubName+".pub"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		t.Fatalf("%s.pub: not PEM", pubName)
		return nil, nil, nil // t is an interface; staticcheck cannot see Fatalf never returns
	}
	pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return pemArmour(pkcs8PEMType, body), raw, pub
}

// pemArmour puts the header and footer back on a fixture body.
func pemArmour(typ string, body []byte) []byte {
	return []byte(pemOfType(typ, "", strings.TrimSpace(string(body))))
}

// pkcs8Fixtures lists every openable fixture under testdata/pkcs8-encrypted,
// as encryptedFixtures does for the OpenSSH directory: a file added there
// is parsed, seeded into the fuzzer, has its schedule wipe observed and its
// allocations proved, without a list to keep in step.
func pkcs8Fixtures(t testing.TB) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join("testdata", "pkcs8-encrypted", "*.b64"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) < 19 {
		t.Fatalf("found %d fixtures under testdata/pkcs8-encrypted, want at least 19", len(matches))
	}
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, strings.TrimSuffix(filepath.Base(m), ".b64"))
	}
	return names
}

// pkcs8LockBudget makes sure the host will lock what opening the file takes,
// and skips the test where it will not. A scrypt file locks its whole
// working set for the parse — 16 MiB at openssl's defaults — which is over
// Windows' default working-set quota and can be over a container's
// RLIMIT_MEMLOCK. Raising the budget is what a program opening such files
// does at startup, so the test does the same, and then asks the only
// question that settles it: whether a buffer of that size can be had. A
// host that refuses is the environment's condition, not the parser's. A
// PBKDF2 file needs a page and is not gated.
func pkcs8LockBudget(t testing.TB, raw []byte) {
	t.Helper()
	f, err := readPBES2(raw)
	if err != nil || !f.scrypt {
		return
	}
	need := scryptRegionSize(len(f.salt), f.n, f.r, f.p) + f.keyLen + cipherScratch
	// Asked for with room: the budget is the process's, and other tests
	// hold locked buffers while this one runs.
	_, _ = secmem.EnsureMemlockLimit(uint64(need) + 32<<20)
	probe, err := secmem.NewEmptyBuffer(need)
	if err != nil {
		t.Skipf("the host will not lock the %d bytes a scrypt file at N=%d r=%d p=%d takes: %v", need, f.n, f.r, f.p, err)
	}
	_ = probe.Destroy()
}

// pkcs8RefusedFixture loads one of the real files under refused/.
func pkcs8RefusedFixture(t testing.TB, name string) (pemBytes, raw []byte) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "pkcs8-encrypted", "refused", name+".b64"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), ""))
	if err != nil {
		t.Fatal(err)
	}
	return pemArmour(pkcs8PEMType, body), raw
}

// TestParsePrivateKeyWithPassphrase_PKCS8Fixtures opens files a real
// openssl pkcs8 and ssh-keygen wrote — every PRF OID the parser maps, the
// absent-PRF form that means HMAC-SHA1, every AES key size, one and
// 600 000 iterations, scrypt at openssl's defaults and at r = 1, p = 2 and
// a 16-byte key, and all three key types — and proves each parsed signer is
// the key the .pub advertises. The aes128 and aes192 files matter for the
// same reason the OpenSSH ones do: the scheme decides how much the KDF
// derives, and a parser that always asked for 32 bytes would key the cipher
// wrongly.
func TestParsePrivateKeyWithPassphrase_PKCS8Fixtures(t *testing.T) {
	for _, name := range pkcs8Fixtures(t) {
		t.Run(name, func(t *testing.T) {
			pemBytes, raw, pub := pkcs8Fixture(t, name)
			pkcs8LockBudget(t, raw)
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
				// AES-CBC authenticates nothing: a wrong passphrase is
				// noise that fails the pad or the DER, reported as the
				// value x/crypto/ssh returns for a wrong passphrase.
				s, err = ParsePrivateKeyWithPassphrase(data, []byte("not it"), AllowHeapTransients())
				if err == nil {
					s.Destroy()
					t.Fatalf("%s: a wrong passphrase was accepted", form)
				}
				if !errors.Is(err, x509.IncorrectPasswordError) {
					t.Fatalf("%s: wrong passphrase: %v, want IncorrectPasswordError", form, err)
				}
			}
		})
	}
	// The SHA-1 fixture is the DEFAULT-PRF form only if the field is
	// really absent; assert that, so a regenerated fixture written with
	// the field present cannot quietly stop guarding the default.
	t.Run("sha1 fixture omits the prf", func(t *testing.T) {
		_, raw, _ := pkcs8Fixture(t, "ed25519-aes256-cbc-sha1")
		if bytes.Contains(raw, oidBytes(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7})) {
			t.Fatal("the fixture names hmacWithSHA1 explicitly; the DEFAULT form is what it must cover")
		}
		f, err := readPBES2(raw)
		if err != nil || f.prf != hashSHA1 {
			t.Fatalf("readPBES2: prf %d, err %v; want hashSHA1 from the absent field", f.prf, err)
		}
	})
	// The scrypt fixtures cover what their names say only while the files
	// carry those parameters; a regenerated file must not quietly stop
	// covering r = 1, p > 1, the short key or openssl's defaults.
	t.Run("scrypt fixtures carry their parameters", func(t *testing.T) {
		for name, want := range map[string]pbes2File{
			"ed25519-scrypt":              {n: 16384, r: 8, p: 1, keyLen: 32},
			"ed25519-scrypt-n1024":        {n: 1024, r: 8, p: 1, keyLen: 32},
			"ed25519-scrypt-n1024-p2":     {n: 1024, r: 8, p: 2, keyLen: 32},
			"ed25519-scrypt-n1024-aes128": {n: 1024, r: 8, p: 1, keyLen: 16},
			"ed25519-scrypt-n32768-r1":    {n: 32768, r: 1, p: 1, keyLen: 32},
		} {
			_, raw, _ := pkcs8Fixture(t, name)
			f, err := readPBES2(raw)
			if err != nil || !f.scrypt || f.n != want.n || f.r != want.r || f.p != want.p || f.keyLen != want.keyLen {
				t.Errorf("%s: scrypt %v, N=%d r=%d p=%d, key %d, err %v; want N=%d r=%d p=%d, key %d",
					name, f.scrypt, f.n, f.r, f.p, f.keyLen, err, want.n, want.r, want.p, want.keyLen)
			}
		}
	})
}

// oidBytes is the DER encoding of oid, for searching a file.
func oidBytes(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	b, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestParsePrivateKeyWithPassphrase_PKCS8Refused runs the real files under
// refused/ through the entry point: the PBES1, PKCS#12-PBE and PBES2-over-
// 3DES/RC2 files must be refused as retired, naming the openssl command
// that converts them, and RFC 7914's own example file — scrypt at
// N = 1048576, a 1 GiB derivation — as merely unsupported, naming the
// memory it is over, with the passphrase the RFC gives for it. None may
// wrap IncorrectPasswordError: every one is decided before a KDF runs.
func TestParsePrivateKeyWithPassphrase_PKCS8Refused(t *testing.T) {
	cases := []struct {
		name       string
		retired    bool
		passphrase string
	}{
		{"pbe-md5-des", true, testPassphrase},
		{"pbe-sha1-3des", true, testPassphrase},
		{"pbe-sha1-rc2-40", true, testPassphrase},
		{"pbes2-des-ede3-cbc", true, testPassphrase},
		{"pbes2-rc2-cbc", true, testPassphrase},
		{"scrypt-rfc7914", false, "Rabbit"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pemBytes, raw := pkcs8RefusedFixture(t, c.name)
			for form, data := range map[string][]byte{"pem": pemBytes, "raw": raw} {
				s, err := ParsePrivateKeyWithPassphrase(data, []byte(c.passphrase), AllowHeapTransients())
				if err == nil {
					s.Destroy()
					t.Fatalf("%s: opened", form)
				}
				if !errors.Is(err, ErrUnsupportedKey) {
					t.Errorf("%s: %v does not wrap ErrUnsupportedKey", form, err)
				}
				if errors.Is(err, x509.IncorrectPasswordError) {
					t.Errorf("%s: %v reads as a wrong passphrase; the refusal must come before the KDF", form, err)
				}
				if got := errors.Is(err, ErrRetiredAlgorithm); got != c.retired {
					t.Errorf("%s: wraps ErrRetiredAlgorithm = %v, want %v: %v", form, got, c.retired, err)
				}
				if c.retired && !strings.Contains(err.Error(), "openssl pkcs8 -topk8") {
					t.Errorf("%s: the refusal %q does not say how to convert the file", form, err)
				}
				if !c.retired && !strings.Contains(err.Error(), "working memory") {
					t.Errorf("%s: the refusal %q does not name the memory cap", form, err)
				}
				// The plain entry point names the condition it always did.
				if _, perr := ParsePrivateKey(data, AllowHeapTransients()); !errors.Is(perr, ErrEncryptedKey) {
					t.Errorf("%s: ParsePrivateKey = %v, want ErrEncryptedKey", form, perr)
				}
			}
		})
	}
}

// pbes2Spec describes an EncryptedPrivateKeyInfo for encryptPKCS8 to write.
// The zero value is a valid aes-256-cbc / PBKDF2-HMAC-SHA256 file at one
// iteration; each field overrides one thing, so a test can pin one rule by
// producing a file that differs from a valid one in exactly that field.
// With kdf set to oidScrypt the KDF parameters are scrypt's, and the zero
// value of the scrypt fields is a valid file at N=16, r=8, p=1.
type pbes2Spec struct {
	outer, kdf, scheme asn1.ObjectIdentifier // nil: PBES2, PBKDF2, aes-256-cbc
	prf                asn1.ObjectIdentifier // nil: omitted (the DEFAULT, HMAC-SHA1)
	prfParams          func(*cryptobyte.Builder)
	prfHash            func() hash.Hash // what the test derives with; nil: by prf
	iter               int              // 0: 1
	iterRaw            []byte           // an explicit INTEGER content, overriding iter
	salt               []byte           // nil: 16 random bytes
	saltOtherSource    bool
	keyLength          int // 0: omitted
	keyLen             int // what the test derives; 0: by scheme
	iv                 []byte
	ctLen              int // trim or pad the ciphertext to this; 0: as encrypted
	trailing           []byte

	// scrypt's cost parameters; 0: N=16, r=8, p=1. The Raw forms are an
	// explicit INTEGER content, overriding the value written — and, where
	// the parser must refuse the file anyway, standing in for one that
	// cannot be derived with.
	n, r, p             int
	nRaw, rRaw, pRaw    []byte
	kdfParamsTrailing   func(*cryptobyte.Builder) // appended inside the KDF's parameter SEQUENCE
	kdfParamsStopAfterR bool                      // scrypt: write salt, N and r only
}

// scryptParams is the spec's N, r and p with the defaults applied.
func (spec pbes2Spec) scryptParams() (n, r, p int) {
	n, r, p = spec.n, spec.r, spec.p
	if n == 0 {
		n = 16
	}
	if r == 0 {
		r = 8
	}
	if p == 0 {
		p = 1
	}
	return n, r, p
}

// scryptOpens reports whether the parser would run the spec's parameters:
// the encoder derives a real key only then. For anything else — parameters
// scrypt is not defined for, or over a cap — it keys the cipher with zeros,
// which no test can mistake for a pass: such a file must be refused before
// the KDF, and one that is not reads as a wrong passphrase, which check
// rejects by name.
func (spec pbes2Spec) scryptOpens() bool {
	n, r, p := spec.scryptParams()
	if spec.nRaw != nil || spec.rRaw != nil || spec.pRaw != nil {
		return false
	}
	if n < 2 || n&(n-1) != 0 || (r == 1 && n >= 1<<16) {
		return false
	}
	return 128*uint64(r)*(uint64(n)+2*uint64(p)+2) <= MaxScryptMemory && uint64(n)*uint64(r)*uint64(p) <= MaxScryptWork
}

// encryptPKCS8 writes plain (a PrivateKeyInfo) as an EncryptedPrivateKeyInfo
// per spec, using the standard library for the KDF and the cipher — the
// reference the parser is checked against.
func encryptPKCS8(t *testing.T, plain []byte, spec pbes2Spec) []byte {
	t.Helper()
	orNil := func(oid, def asn1.ObjectIdentifier) asn1.ObjectIdentifier {
		if oid == nil {
			return def
		}
		return oid
	}
	outer, kdf, scheme := orNil(spec.outer, oidPBES2), orNil(spec.kdf, oidPBKDF2), orNil(spec.scheme, oidAES256CBC)
	keyLen := spec.keyLen
	if keyLen == 0 {
		keyLen = map[string]int{oidAES128CBC.String(): 16, oidAES192CBC.String(): 24}[scheme.String()]
		if keyLen == 0 {
			keyLen = 32
		}
	}
	h := spec.prfHash
	if h == nil {
		h = sha1.New
		if spec.prf != nil {
			h = map[string]func() hash.Hash{
				oidHMACSHA256(9).String(): sha256.New,
			}[spec.prf.String()]
			if h == nil {
				h = sha1.New
			}
		}
	}
	iter := spec.iter
	if iter == 0 {
		iter = 1
	}
	salt := spec.salt
	if salt == nil {
		salt = randBytes(t, 16)
	}
	iv := spec.iv
	if iv == nil {
		iv = randBytes(t, 16)
	}
	isScrypt := kdf.Equal(oidScrypt)
	var key []byte
	var err error
	switch {
	case isScrypt && spec.scryptOpens():
		n, r, p := spec.scryptParams()
		key, err = xscrypt.Key([]byte(testPassphrase), salt, n, r, p, keyLen)
	case isScrypt:
		key = make([]byte, keyLen)
	default:
		key, err = pbkdf2.Key(h, testPassphrase, salt, iter, keyLen)
	}
	if err != nil {
		t.Fatal(err)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	pad := 16 - len(plain)%16
	padded := append(bytes.Clone(plain), bytes.Repeat([]byte{byte(pad)}, pad)...)
	ct := make([]byte, len(padded))
	civ := make([]byte, 16)
	copy(civ, iv)
	cipher.NewCBCEncrypter(blk, civ).CryptBlocks(ct, padded)
	if spec.ctLen != 0 {
		if spec.ctLen <= len(ct) {
			ct = ct[:spec.ctLen]
		} else {
			ct = append(ct, make([]byte, spec.ctLen-len(ct))...)
		}
	}

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(outer)
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(kdf)
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						if spec.saltOtherSource {
							b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
								b.AddASN1ObjectIdentifier(oidPBKDF2)
								b.AddASN1NULL()
							})
						} else {
							b.AddASN1OctetString(salt)
						}
						if isScrypt {
							n, r, p := spec.scryptParams()
							count := func(v int, raw []byte) {
								if raw != nil {
									b.AddASN1(cbasn1.INTEGER, func(b *cryptobyte.Builder) { b.AddBytes(raw) })
								} else {
									b.AddASN1Int64(int64(v))
								}
							}
							count(n, spec.nRaw)
							count(r, spec.rRaw)
							if spec.kdfParamsStopAfterR {
								return
							}
							count(p, spec.pRaw)
							if spec.keyLength != 0 {
								b.AddASN1Int64(int64(spec.keyLength))
							}
							if spec.kdfParamsTrailing != nil {
								spec.kdfParamsTrailing(b)
							}
							return
						}
						if spec.iterRaw != nil {
							b.AddASN1(cbasn1.INTEGER, func(b *cryptobyte.Builder) { b.AddBytes(spec.iterRaw) })
						} else {
							b.AddASN1Int64(int64(iter))
						}
						if spec.keyLength != 0 {
							b.AddASN1Int64(int64(spec.keyLength))
						}
						if spec.prf != nil {
							b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
								b.AddASN1ObjectIdentifier(spec.prf)
								if spec.prfParams != nil {
									spec.prfParams(b)
								} else {
									b.AddASN1NULL()
								}
							})
						}
						if spec.kdfParamsTrailing != nil {
							spec.kdfParamsTrailing(b)
						}
					})
				})
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(scheme)
					b.AddASN1OctetString(iv)
				})
			})
		})
		b.AddASN1OctetString(ct)
	})
	der, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return append(der, spec.trailing...)
}

// oidHMACSHA256 is the PRF OID with the given last component under the
// digestAlgorithm arc: 7 SHA-1 .. 13 SHA-512/256, anything else unknown.
func oidHMACSHA256(last int) asn1.ObjectIdentifier {
	return append(append(asn1.ObjectIdentifier{}, oidHMACArc...), last)
}

// testPKCS8Ed25519 is a fresh Ed25519 PrivateKeyInfo and its public key.
func testPKCS8Ed25519(t *testing.T) ([]byte, crypto.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return p8, pub
}

// TestParsePrivateKeyWithPassphrase_PKCS8Encoder proves the encoder above
// writes what the parser reads, so the rejection rows below pin the parser
// and not a broken fixture: the zero spec, the explicit-PRF forms, an
// agreeing keyLength and every key size all open to the right key.
func TestParsePrivateKeyWithPassphrase_PKCS8Encoder(t *testing.T) {
	p8, pub := testPKCS8Ed25519(t)
	specs := map[string]pbes2Spec{
		"default (absent prf = SHA-1)":   {},
		"explicit hmacWithSHA1":          {prf: oidHMACSHA256(7)},
		"explicit hmacWithSHA256":        {prf: oidHMACSHA256(9)},
		"prf params absent":              {prf: oidHMACSHA256(9), prfParams: func(*cryptobyte.Builder) {}},
		"keyLength agreeing":             {keyLength: 32},
		"aes-128-cbc":                    {scheme: oidAES128CBC},
		"aes-192-cbc":                    {scheme: oidAES192CBC},
		"aes-128-cbc keyLength 16":       {scheme: oidAES128CBC, keyLength: 16},
		"iterations 2048":                {iter: 2048},
		"salt of one byte":               {salt: []byte{7}},
		"salt at the bound":              {salt: randBytes(t, maxPBES2Salt)},
		"iteration count in two bytes":   {iterRaw: []byte{0x08, 0x00}, iter: 2048},
		"iteration count with lead zero": {iterRaw: []byte{0x00, 0x80}, iter: 128},

		// scrypt, where the reference is golang.org/x/crypto/scrypt: each r
		// the block arithmetic treats differently, more than one pass over
		// B, every key size, the smallest N, an N whose INTEGER needs a
		// lead zero, the largest N scrypt defines at r = 1 one step down
		// (the real fixture is at it), and both ends of the salt's range —
		// the long salt is longer than B here, so it is what sizes the
		// PBKDF2 region.
		"scrypt":                        {kdf: oidScrypt},
		"scrypt r=1":                    {kdf: oidScrypt, r: 1},
		"scrypt r=2":                    {kdf: oidScrypt, r: 2},
		"scrypt p=2":                    {kdf: oidScrypt, p: 2},
		"scrypt p=3, r=1":               {kdf: oidScrypt, p: 3, r: 1},
		"scrypt N=2":                    {kdf: oidScrypt, n: 2},
		"scrypt N=128 (lead zero)":      {kdf: oidScrypt, n: 128},
		"scrypt N=16384, r=1":           {kdf: oidScrypt, n: 16384, r: 1},
		"scrypt keyLength agreeing":     {kdf: oidScrypt, keyLength: 32},
		"scrypt aes-128-cbc":            {kdf: oidScrypt, scheme: oidAES128CBC},
		"scrypt aes-192-cbc":            {kdf: oidScrypt, scheme: oidAES192CBC},
		"scrypt aes-128-cbc keyLength":  {kdf: oidScrypt, scheme: oidAES128CBC, keyLength: 16},
		"scrypt salt of one byte":       {kdf: oidScrypt, salt: []byte{7}},
		"scrypt salt at the bound, r=1": {kdf: oidScrypt, r: 1, salt: randBytes(t, maxPBES2Salt)},
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			if spec.kdf.Equal(oidScrypt) && !spec.scryptOpens() {
				t.Fatal("the encoder would not derive a key for this spec, so the row would prove nothing")
			}
			data := encryptPKCS8(t, p8, spec)
			pkcs8LockBudget(t, data)
			for form, d := range map[string][]byte{"raw": data, "pem": pemArmour(pkcs8PEMType, []byte(base64.StdEncoding.EncodeToString(data)))} {
				s, err := ParsePrivateKeyWithPassphrase(d, []byte(testPassphrase))
				if err != nil {
					t.Fatalf("%s: %v", form, err)
				}
				verifySigner(t, s, pub)
				s.Destroy()
			}
		})
	}
}

// TestParsePrivateKeyWithPassphrase_PKCS8Rejects pins every refusal the
// parser decides before the KDF, each on a file that differs from a valid
// one in exactly that field, and asserts that none of them reads as a
// wrong passphrase — a refusal wrapping IncorrectPasswordError would mean
// the derivation ran. Where the rule has a name the error must carry it,
// so a row cannot pass through a neighbouring check with the rule deleted.
func TestParsePrivateKeyWithPassphrase_PKCS8Rejects(t *testing.T) {
	p8, _ := testPKCS8Ed25519(t)
	unknown := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	pbes1 := func(last int) asn1.ObjectIdentifier {
		return append(append(asn1.ObjectIdentifier{}, oidPBES1Arc...), last)
	}
	pkcs12 := func(last int) asn1.ObjectIdentifier {
		return append(append(asn1.ObjectIdentifier{}, oidPKCS12PBEArc...), last)
	}
	cases := []struct {
		name string
		spec pbes2Spec
		want error
		text string
	}{
		{"iteration count zero", pbes2Spec{iterRaw: []byte{0}}, errMalformed, ""},
		{"iteration count negative", pbes2Spec{iterRaw: []byte{0xff}}, errMalformed, ""},
		{"iteration count non-minimal", pbes2Spec{iterRaw: []byte{0x00, 0x01}}, errMalformed, ""},
		{"iteration count over the cap", pbes2Spec{iterRaw: []byte{0x1e, 0x84, 0x81}}, ErrUnsupportedKey, "maximum"}, // 2 000 001
		{"iteration count of eight bytes", pbes2Spec{iterRaw: []byte{1, 0, 0, 0, 0, 0, 0, 0}}, ErrUnsupportedKey, "maximum"},
		{"iteration count of twenty bytes", pbes2Spec{iterRaw: append([]byte{1}, make([]byte, 19)...)}, ErrUnsupportedKey, "maximum"},
		{"keyLength disagreeing", pbes2Spec{keyLength: 16}, errMalformed, "keyLength"},
		{"keyLength disagreeing, aes-128", pbes2Spec{scheme: oidAES128CBC, keyLength: 32}, errMalformed, "keyLength"},
		{"salt otherSource", pbes2Spec{saltOtherSource: true}, ErrUnsupportedKey, "otherSource"},
		{"salt empty", pbes2Spec{salt: []byte{}}, errMalformed, ""},
		{"salt over the bound", pbes2Spec{salt: randBytes(t, maxPBES2Salt+1)}, errMalformed, "salt"},
		{"scheme aes-128-gcm", pbes2Spec{scheme: oidAES128GCM}, ErrUnsupportedKey, "AES-GCM"},
		{"scheme aes-256-gcm", pbes2Spec{scheme: oidAES256GCM}, ErrUnsupportedKey, "AES-GCM"},
		{"scheme unknown", pbes2Spec{scheme: unknown}, ErrUnsupportedKey, "scheme"},
		{"scheme des-ede3-cbc", pbes2Spec{scheme: oidDESEDE3CBC}, ErrRetiredAlgorithm, "openssl pkcs8"},
		{"scheme rc2-cbc", pbes2Spec{scheme: oidRC2CBC}, ErrRetiredAlgorithm, "openssl pkcs8"},
		{"scheme des-cbc", pbes2Spec{scheme: oidDESCBC}, ErrRetiredAlgorithm, "openssl pkcs8"},
		{"kdf unknown", pbes2Spec{kdf: unknown}, ErrUnsupportedKey, "KDF"},
		{"pbkdf2 params trailing element", pbes2Spec{prf: oidHMACSHA256(9), kdfParamsTrailing: func(b *cryptobyte.Builder) { b.AddASN1NULL() }}, errMalformed, ""},

		// scrypt's parameters. Shape first: each count is an INTEGER
		// (1..MAX) in minimal DER, and all three are there.
		{"scrypt N zero", pbes2Spec{kdf: oidScrypt, nRaw: []byte{0}}, errMalformed, ""},
		{"scrypt N negative", pbes2Spec{kdf: oidScrypt, nRaw: []byte{0xf0}}, errMalformed, ""},
		{"scrypt N non-minimal", pbes2Spec{kdf: oidScrypt, nRaw: []byte{0x00, 0x10}}, errMalformed, ""},
		{"scrypt r zero", pbes2Spec{kdf: oidScrypt, rRaw: []byte{0}}, errMalformed, ""},
		{"scrypt r negative", pbes2Spec{kdf: oidScrypt, rRaw: []byte{0xff}}, errMalformed, ""},
		{"scrypt r non-minimal", pbes2Spec{kdf: oidScrypt, rRaw: []byte{0x00, 0x08}}, errMalformed, ""},
		{"scrypt p zero", pbes2Spec{kdf: oidScrypt, pRaw: []byte{0}}, errMalformed, ""},
		{"scrypt p negative", pbes2Spec{kdf: oidScrypt, pRaw: []byte{0xff}}, errMalformed, ""},
		{"scrypt p non-minimal", pbes2Spec{kdf: oidScrypt, pRaw: []byte{0x00, 0x01}}, errMalformed, ""},
		{"scrypt p missing", pbes2Spec{kdf: oidScrypt, kdfParamsStopAfterR: true}, errMalformed, ""},
		{"scrypt params trailing element", pbes2Spec{kdf: oidScrypt, kdfParamsTrailing: func(b *cryptobyte.Builder) { b.AddASN1NULL() }}, errMalformed, ""},
		{"scrypt params trailing integer", pbes2Spec{kdf: oidScrypt, keyLength: 32, kdfParamsTrailing: func(b *cryptobyte.Builder) { b.AddASN1Int64(1) }}, errMalformed, ""},
		{"scrypt keyLength disagreeing", pbes2Spec{kdf: oidScrypt, keyLength: 16}, errMalformed, "keyLength"},
		{"scrypt keyLength disagreeing, aes-128", pbes2Spec{kdf: oidScrypt, scheme: oidAES128CBC, keyLength: 32}, errMalformed, "keyLength"},
		{"scrypt salt empty", pbes2Spec{kdf: oidScrypt, salt: []byte{}}, errMalformed, ""},
		{"scrypt salt over the bound", pbes2Spec{kdf: oidScrypt, salt: randBytes(t, maxPBES2Salt+1)}, errMalformed, "salt"},
		{"scrypt salt not an OCTET STRING", pbes2Spec{kdf: oidScrypt, saltOtherSource: true}, errMalformed, ""},
		// Then what scrypt is defined for.
		{"scrypt N one", pbes2Spec{kdf: oidScrypt, n: 1}, errMalformed, "power of two"},
		{"scrypt N three", pbes2Spec{kdf: oidScrypt, n: 3}, errMalformed, "power of two"},
		{"scrypt N not a power of two", pbes2Spec{kdf: oidScrypt, n: 1000}, errMalformed, "power of two"},
		{"scrypt N one over a power of two", pbes2Spec{kdf: oidScrypt, n: 16385}, errMalformed, "power of two"},
		{"scrypt N at 2^(128r/8), r=1", pbes2Spec{kdf: oidScrypt, n: 65536, r: 1}, errMalformed, "2^(128*r/8)"},
		{"scrypt N over 2^(128r/8), r=1", pbes2Spec{kdf: oidScrypt, n: 1 << 17, r: 1}, errMalformed, "2^(128*r/8)"},
		// Then what this parser will run: the memory, by each parameter
		// that can exceed it alone and by a count too wide to read; then
		// the work, on parameters inside the memory cap.
		{"scrypt memory: N=65536, r=8", pbes2Spec{kdf: oidScrypt, n: 65536}, ErrUnsupportedKey, "working memory"},
		{"scrypt memory: N=1048576, r=8", pbes2Spec{kdf: oidScrypt, n: 1 << 20}, ErrUnsupportedKey, "working memory"},
		{"scrypt memory: r alone", pbes2Spec{kdf: oidScrypt, n: 2, r: 1 << 19}, ErrUnsupportedKey, "working memory"},
		{"scrypt memory: r past the overflow guard", pbes2Spec{kdf: oidScrypt, n: 2, r: 1<<19 + 1}, ErrUnsupportedKey, "working memory"},
		{"scrypt memory: r at max int32", pbes2Spec{kdf: oidScrypt, n: 2, r: math.MaxInt32}, ErrUnsupportedKey, "working memory"},
		{"scrypt memory: p alone", pbes2Spec{kdf: oidScrypt, p: 65536}, ErrUnsupportedKey, "working memory"},
		{"scrypt memory: p at max int32", pbes2Spec{kdf: oidScrypt, p: math.MaxInt32}, ErrUnsupportedKey, "working memory"},
		{"scrypt memory: N of eight bytes", pbes2Spec{kdf: oidScrypt, nRaw: []byte{1, 0, 0, 0, 0, 0, 0, 0}}, ErrUnsupportedKey, "working memory"},
		{"scrypt memory: r of eight bytes", pbes2Spec{kdf: oidScrypt, rRaw: []byte{1, 0, 0, 0, 0, 0, 0, 0}}, ErrUnsupportedKey, "working memory"},
		{"scrypt memory: p of twenty bytes", pbes2Spec{kdf: oidScrypt, pRaw: append([]byte{1}, make([]byte, 19)...)}, ErrUnsupportedKey, "working memory"},
		{"scrypt work: p=33 at openssl's N and r", pbes2Spec{kdf: oidScrypt, n: 16384, p: 33}, ErrUnsupportedKey, "N*r*p"},
		{"scrypt work: p=4097 at N=1024, r=1", pbes2Spec{kdf: oidScrypt, n: 1024, r: 1, p: 4097}, ErrUnsupportedKey, "N*r*p"},
		{"prf unknown", pbes2Spec{prf: oidHMACSHA256(99)}, ErrUnsupportedKey, "PRF"},
		{"prf sha3 arc", pbes2Spec{prf: unknown}, ErrUnsupportedKey, "PRF"},
		{"prf params not NULL", pbes2Spec{prf: oidHMACSHA256(9), prfParams: func(b *cryptobyte.Builder) { b.AddASN1Int64(1) }}, errMalformed, ""},
		{"iv of eight bytes", pbes2Spec{iv: make([]byte, 8)}, errMalformed, ""},
		{"iv of thirty-two bytes", pbes2Spec{iv: make([]byte, 32)}, errMalformed, ""},
		{"ciphertext not a block multiple", pbes2Spec{ctLen: 63}, errMalformed, "block size"},
		{"ciphertext empty", pbes2Spec{ctLen: -1}, errMalformed, "block size"},
		{"trailing bytes", pbes2Spec{trailing: []byte{0}}, errMalformed, ""},
		{"outer unknown", pbes2Spec{outer: unknown}, ErrUnsupportedKey, "encryption algorithm"},
		{"outer pbeWithMD2AndDES-CBC", pbes2Spec{outer: pbes1(1)}, ErrRetiredAlgorithm, "openssl pkcs8"},
		{"outer pbeWithMD5AndDES-CBC", pbes2Spec{outer: pbes1(3)}, ErrRetiredAlgorithm, "openssl pkcs8"},
		{"outer pbeWithMD2AndRC2-CBC", pbes2Spec{outer: pbes1(4)}, ErrRetiredAlgorithm, "openssl pkcs8"},
		{"outer pbeWithMD5AndRC2-CBC", pbes2Spec{outer: pbes1(6)}, ErrRetiredAlgorithm, "openssl pkcs8"},
		{"outer pbeWithSHA1AndDES-CBC", pbes2Spec{outer: pbes1(10)}, ErrRetiredAlgorithm, "openssl pkcs8"},
		{"outer pbeWithSHA1AndRC2-CBC", pbes2Spec{outer: pbes1(11)}, ErrRetiredAlgorithm, "openssl pkcs8"},
		{"outer pkcs12 RC4-128", pbes2Spec{outer: pkcs12(1)}, ErrRetiredAlgorithm, "openssl pkcs8"},
		{"outer pkcs12 3DES", pbes2Spec{outer: pkcs12(3)}, ErrRetiredAlgorithm, "openssl pkcs8"},
		{"outer pkcs12 RC2-40", pbes2Spec{outer: pkcs12(6)}, ErrRetiredAlgorithm, "openssl pkcs8"},
		{"outer pbes1 arc, not a member", pbes2Spec{outer: pbes1(2)}, ErrUnsupportedKey, "encryption algorithm"},
		{"outer pkcs12 arc, not a member", pbes2Spec{outer: pkcs12(7)}, ErrUnsupportedKey, "encryption algorithm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := tc.spec
			if spec.ctLen == -1 {
				spec.ctLen = 0
				data := encryptPKCS8(t, p8, spec)
				// An empty OCTET STRING cannot be asked of the encoder;
				// splice it: the last element of the outer SEQUENCE.
				data = emptyCiphertext(t, data)
				check(t, data, tc.want, tc.text)
				return
			}
			check(t, encryptPKCS8(t, p8, spec), tc.want, tc.text)
		})
	}
	// Retired refusals also wrap ErrUnsupportedKey, so a caller's existing
	// check keeps working; unimplemented ones must not claim to be retired.
	for _, tc := range cases {
		if tc.spec.ctLen == -1 {
			continue
		}
		_, err := ParsePrivateKeyWithPassphrase(encryptPKCS8(t, p8, tc.spec), []byte(testPassphrase))
		if errors.Is(tc.want, ErrRetiredAlgorithm) && !errors.Is(err, ErrUnsupportedKey) {
			t.Errorf("%s: retired refusal %v does not also wrap ErrUnsupportedKey", tc.name, err)
		}
		if !errors.Is(tc.want, ErrRetiredAlgorithm) && errors.Is(err, ErrRetiredAlgorithm) {
			t.Errorf("%s: %v claims to be retired", tc.name, err)
		}
	}
}

// check parses data and requires want, and text in the message when given,
// and that the KDF did not run.
func check(t *testing.T, data []byte, want error, text string) {
	t.Helper()
	s, err := ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase), AllowHeapTransients())
	if err == nil {
		s.Destroy()
		t.Fatal("opened")
	}
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
	if errors.Is(err, x509.IncorrectPasswordError) {
		t.Fatalf("%v reads as a wrong passphrase: the KDF ran for a file refused on its parameters", err)
	}
	if text != "" && !strings.Contains(err.Error(), text) {
		t.Fatalf("got %v, want an error naming %q", err, text)
	}
}

// emptyCiphertext rewrites a valid file's encryptedData to an empty OCTET
// STRING.
func emptyCiphertext(t *testing.T, der []byte) []byte {
	t.Helper()
	in := cryptobyte.String(der)
	var seq, alg cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1Element(&alg, cbasn1.SEQUENCE) {
		t.Fatal("not the file the encoder wrote")
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(alg)
		b.AddASN1OctetString(nil)
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestParsePrivateKeyWithPassphrase_PKCS8IterationCap: the cap is a value
// a file may name exactly. A file at MaxPBKDF2Iterations opens; one above
// it is refused before the derivation. The real 600 000-iteration fixture
// is in the fixture loop; this is the boundary.
func TestParsePrivateKeyWithPassphrase_PKCS8IterationCap(t *testing.T) {
	if testing.Short() {
		t.Skip("two million iterations")
	}
	p8, pub := testPKCS8Ed25519(t)
	data := encryptPKCS8(t, p8, pbes2Spec{iter: MaxPBKDF2Iterations, prf: oidHMACSHA256(9)})
	s, err := ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("a file at the cap did not open: %v", err)
	}
	verifySigner(t, s, pub)
	s.Destroy()
	data = encryptPKCS8(t, p8, pbes2Spec{iter: MaxPBKDF2Iterations + 1, prf: oidHMACSHA256(9)})
	check(t, data, ErrUnsupportedKey, "maximum")
}

// TestParsePrivateKeyWithPassphrase_PKCS8ScryptCaps: each cap is a boundary
// a file may sit on. Memory: at N=32768, p=1 the working set is
// 128·r·32772 bytes, which is inside MaxScryptMemory at r=15 by 4 MiB and
// over it at r=16 by 8 KiB — the two files differ in r alone. Work:
// N=16384, r=8, p=32 is N·r·p = MaxScryptWork exactly and opens; p=33 is
// refused. The files at the caps are derived for real, twice (the encoder's
// x/crypto and the parser), which is the cost this test is skipped for
// under -short.
func TestParsePrivateKeyWithPassphrase_PKCS8ScryptCaps(t *testing.T) {
	if testing.Short() {
		t.Skip("derives at both scrypt caps")
	}
	p8, pub := testPKCS8Ed25519(t)
	for _, c := range []struct {
		name          string
		opens, refuse pbes2Spec
		text          string
	}{
		{"memory", pbes2Spec{kdf: oidScrypt, n: 32768, r: 15}, pbes2Spec{kdf: oidScrypt, n: 32768, r: 16}, "working memory"},
		{"work", pbes2Spec{kdf: oidScrypt, n: 16384, p: 32}, pbes2Spec{kdf: oidScrypt, n: 16384, p: 33}, "N*r*p"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if !c.opens.scryptOpens() || c.refuse.scryptOpens() {
				t.Fatal("the pair does not straddle the cap")
			}
			check(t, encryptPKCS8(t, p8, c.refuse), ErrUnsupportedKey, c.text)

			data := encryptPKCS8(t, p8, c.opens)
			pkcs8LockBudget(t, data)
			s, err := ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase))
			if err != nil {
				t.Fatalf("a file inside the cap did not open: %v", err)
			}
			verifySigner(t, s, pub)
			s.Destroy()
		})
	}
	if n, r, p := (pbes2Spec{kdf: oidScrypt, n: 16384, p: 32}).scryptParams(); uint64(n)*uint64(r)*uint64(p) != MaxScryptWork {
		t.Fatalf("N·r·p = %d: the work row is not at MaxScryptWork = %d", n*r*p, MaxScryptWork)
	}
}

// TestParsePrivateKeyWithPassphrase_PKCS8ScryptLockRefusal: a host that will
// not lock the scrypt working set fails the parse as itself. The refusal
// comes after every parameter check and before the KDF, so it must not read
// as a wrong passphrase — a caller would otherwise prompt again for a
// passphrase that was right — and it must not be the parser's own verdict
// on the file either. The allocation is made to fail the way a host does,
// by asking for the working set of a real file from a scratch allocator
// that refuses.
func TestParsePrivateKeyWithPassphrase_PKCS8ScryptLockRefusal(t *testing.T) {
	_, raw, _ := pkcs8Fixture(t, "ed25519-scrypt")
	refused := errors.New("simulated: VirtualLock refused")
	orig := newScratchBuffer
	var asked []int
	newScratchBuffer = func(_ bufferOptions, size int) (*secmem.SecureBuffer, error) {
		asked = append(asked, size)
		return nil, refused
	}
	defer func() { newScratchBuffer = orig }()

	s, err := ParsePrivateKeyWithPassphrase(raw, []byte(testPassphrase))
	if err == nil {
		s.Destroy()
		t.Fatal("parse succeeded although the working set could not be locked")
	}
	if !errors.Is(err, refused) {
		t.Fatalf("the refusal is not in the error: %v", err)
	}
	if errors.Is(err, x509.IncorrectPasswordError) || errors.Is(err, ErrUnsupportedKey) || errors.Is(err, errMalformed) {
		t.Fatalf("a lock refusal was reported as a verdict on the file or the passphrase: %v", err)
	}
	// One scratch, of the size MaxScryptMemory's doc describes for
	// openssl's defaults: 128·8·(16384 + 2 + 2) bytes and under 2 KiB more.
	const counted = 128 * 8 * (16384 + 2 + 2)
	if len(asked) != 1 || asked[0] < counted || asked[0] >= counted+2048 {
		t.Fatalf("scratch allocations %v, want one of [%d, %d)", asked, counted, counted+2048)
	}
}

// TestParsePrivateKeyWithPassphrase_PKCS8HeapGate: an RSA or EC key in a
// PBES2 file hits the same heap-transients gate the constructors apply,
// with the same message as the plain parser on the same kind of key. It
// cannot fire before the KDF here — the algorithm identifier is inside the
// ciphertext — so the derivation runs; what the gate guarantees is that
// the refusal comes before any signer is built, and the test asserts the
// error is the gate's and not the post-decryption one bit.
func TestParsePrivateKeyWithPassphrase_PKCS8HeapGate(t *testing.T) {
	for name, plainKey := range map[string]string{"rsa-2048-aes256-cbc-sha256": "rsa2048", "ecdsa-p256-aes256-cbc-sha256": "p256"} {
		t.Run(name, func(t *testing.T) {
			pemBytes, raw, pub := pkcs8Fixture(t, name)
			withPolicy(t, false, func() {
				for form, data := range map[string][]byte{"pem": pemBytes, "raw": raw} {
					_, err := ParsePrivateKeyWithPassphrase(data, []byte(testPassphrase), nil)
					if !errors.Is(err, ErrHeapTransients) {
						t.Fatalf("%s: %v, want ErrHeapTransients", form, err)
					}
					if errors.Is(err, x509.IncorrectPasswordError) {
						t.Fatalf("%s: the gate's refusal was folded into the post-decryption error", form)
					}
					_, perr := ParsePrivateKey(encodings(t, testKeyNamed(t, plainKey))[1].data)
					if !errors.Is(perr, ErrHeapTransients) || perr.Error() != err.Error() {
						t.Fatalf("%s: entry points disagree:\n  plain:      %v\n  passphrase: %v", form, perr, err)
					}
				}
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
		pemBytes, _, pub := pkcs8Fixture(t, "ed25519-aes256-cbc-sha256")
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

// TestParsePrivateKeyWithPassphrase_PKCS8PostDecryptionIsBinary is the
// PBES2 half of the promise that, once the KDF has run, an error says only
// that the block did not become a key. Every byte of the ciphertext is
// modified in turn and parsed with the CORRECT passphrase; depending on
// where the damage lands the parser sees a bad pad, a plaintext that is
// not DER, a wrong OID, a curve point that does not match, or an RSA key
// the standard library rejects, and every one must come back as the same
// string a wrong passphrase gives.
//
// What stays observable is success, and the test pins exactly where. Under
// CBC a flip in ciphertext block k garbles plaintext block k and one byte
// of block k+1. An Ed25519 v1 PrivateKeyInfo carries no public key, so
// nothing checks the seed: where both land inside its 32 bytes the file
// opens as a different key — required here, and proved not to be the
// fixture's. An RSA file's trailing CRT values are redundant, and the
// standard library recomputes them from p and q when they are damaged or
// missing, so damage confined to them leaves a key that opens — and it
// must be the fixture's own key, which the test requires of every flip
// that opens. An EC file carries its public key, so no flip may open.
func TestParsePrivateKeyWithPassphrase_PKCS8PostDecryptionIsBinary(t *testing.T) {
	_, raw, _ := pkcs8Fixture(t, "ed25519-iter1")
	_, wrongErr := ParsePrivateKeyWithPassphrase(raw, []byte("not it"), AllowHeapTransients())
	if !errors.Is(wrongErr, x509.IncorrectPasswordError) {
		t.Fatalf("wrong passphrase: %v", wrongErr)
	}
	want := wrongErr.Error()

	for _, tc := range []struct {
		name   string
		stride int
	}{{"ed25519-iter1", 1}, {"ecdsa-p256-aes256-cbc-sha256", 3}, {"rsa-2048-aes256-cbc-sha256", 7}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, raw, pub := pkcs8Fixture(t, tc.name)
			f, err := readPBES2(raw)
			if err != nil {
				t.Fatal(err)
			}
			ctStart := bytes.Index(raw, f.ct)
			if ctStart < 0 {
				t.Fatal("ciphertext not found in the file")
			}
			kind := strings.SplitN(tc.name, "-", 2)[0]
			seedStart, seedEnd := -1, -1
			if kind == "ed25519" {
				seedStart, seedEnd = ed25519SeedRange(t, raw)
			}
			var opened, failed int
			for off := 0; off < len(f.ct); off += tc.stride {
				d := bytes.Clone(raw)
				d[ctStart+off] ^= 0x01
				s, err := ParsePrivateKeyWithPassphrase(d, []byte(testPassphrase), AllowHeapTransients())
				// The damage: all of plaintext block k, one byte of k+1.
				k := off / 16
				damageEnd := 16*(k+1) + off%16 + 1
				inSeed := seedStart >= 0 && 16*k >= seedStart && damageEnd <= seedEnd
				if err == nil {
					opened++
					same := signsFor(t, s, pub)
					s.Destroy()
					switch kind {
					case "ecdsa":
						t.Errorf("flip at %d, damaging plaintext [%d,%d), opened although the file carries the public key", off, 16*k, damageEnd)
					case "rsa":
						if !same {
							t.Errorf("flip at %d, damaging plaintext [%d,%d), opened as a different key", off, 16*k, damageEnd)
						}
					default:
						if !inSeed {
							t.Errorf("flip at %d, damaging plaintext [%d,%d) outside the seed, opened", off, 16*k, damageEnd)
						} else if same {
							t.Errorf("flip at %d in the seed opened as the fixture's own key", off)
						}
					}
					continue
				}
				failed++
				if inSeed {
					t.Errorf("flip at %d, inside the seed, failed: %v", off, err)
				}
				if got := err.Error(); got != want {
					t.Errorf("flip at %d: error differs from the wrong-passphrase error:\n  got:  %s\n  want: %s", off, got, want)
				}
			}
			if failed == 0 {
				t.Fatal("no flip failed; the test is not reaching the ciphertext")
			}
			if seedStart >= 0 && opened == 0 {
				t.Fatal("ed25519: no flip in the seed opened; the seed range is wrong")
			}
			t.Logf("%d offsets: %d opened, %d failed identically", (len(f.ct)+tc.stride-1)/tc.stride, opened, failed)
		})
	}
}

// ed25519SeedRange decrypts an Ed25519 fixture with the test passphrase and
// the standard library and returns the seed's offsets within the plaintext,
// read from the structure rather than assumed.
func ed25519SeedRange(t *testing.T, raw []byte) (start, end int) {
	t.Helper()
	f, err := readPBES2(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := map[inPlaceHash]func() hash.Hash{hashSHA1: sha1.New, hashSHA256: sha256.New}[f.prf]
	if h == nil {
		t.Fatalf("fixture PRF %d not in this helper's map", f.prf)
	}
	key, err := pbkdf2.Key(h, testPassphrase, f.salt, f.iter, f.keyLen)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, len(f.ct))
	cipher.NewCBCDecrypter(blk, f.iv).CryptBlocks(plain, f.ct)
	n, ok := pkcs7Unpad(plain)
	if !ok {
		t.Fatal("the test's own decryption did not unpad")
	}
	priv, err := x509.ParsePKCS8PrivateKey(plain[:n])
	if err != nil {
		t.Fatal(err)
	}
	seed := priv.(ed25519.PrivateKey).Seed()
	start = bytes.Index(plain[:n], seed)
	if start < 0 {
		t.Fatal("seed not found in the plaintext")
	}
	return start, start + len(seed)
}

// signsFor reports whether s signs for pub, without failing the test when
// it does not.
func signsFor(t *testing.T, s Signer, pub crypto.PublicKey) bool {
	t.Helper()
	msg := []byte("binary")
	digest := sha256.Sum256(msg)
	switch p := pub.(type) {
	case ed25519.PublicKey:
		sig, err := s.Sign(rand.Reader, msg, crypto.Hash(0))
		return err == nil && ed25519.Verify(p, msg, sig)
	case *ecdsa.PublicKey:
		sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
		return err == nil && ecdsa.VerifyASN1(p, digest[:], sig)
	case *rsa.PublicKey:
		sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
		return err == nil && rsa.VerifyPKCS1v15(p, crypto.SHA256, digest[:], sig) == nil
	}
	t.Fatalf("no verifier for %T", pub)
	return false
}

// TestParsePrivateKeyWithPassphrase_PKCS8ErrorsCarryNoSecret: neither the
// passphrase nor any byte of the file may appear in an error, on a whole
// file, a raw one, and a truncated one.
func TestParsePrivateKeyWithPassphrase_PKCS8ErrorsCarryNoSecret(t *testing.T) {
	pemBytes, raw, _ := pkcs8Fixture(t, "ed25519-iter1")
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

// TestParsePrivateKeyWithPassphrase_PKCS8WipesAESBlock is the OpenSSH
// test's twin: the wipe fires exactly once per parse on a live schedule,
// and that schedule is zero once the parse has returned — for every
// fixture, so every key size. Must not call t.Parallel(): it swaps a
// package var.
func TestParsePrivateKeyWithPassphrase_PKCS8WipesAESBlock(t *testing.T) {
	for _, name := range pkcs8Fixtures(t) {
		t.Run(name, func(t *testing.T) {
			pemBytes, raw, pub := pkcs8Fixture(t, name)
			pkcs8LockBudget(t, raw)
			var fired, blank int
			var aliased [][]byte
			orig := wipeAESBlock
			wipeAESBlock = func(b cipher.Block) error {
				fired++
				for _, f := range aesRoundKeyFields {
					if keys, err := aesRoundKeys(b, f); err == nil {
						if bytes.Equal(keys, make([]byte, len(keys))) {
							blank++
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

// TestParsePrivateKeyWithPassphrase_PKCS8FailsClosedWhenWipeCannot: the
// same stance as the OpenSSH path where the schedule cannot be located.
func TestParsePrivateKeyWithPassphrase_PKCS8FailsClosedWhenWipeCannot(t *testing.T) {
	pemBytes, _, _ := pkcs8Fixture(t, "ed25519-iter1")
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
	if errors.Is(err, x509.IncorrectPasswordError) {
		t.Fatalf("the wipe failure was folded into the wrong-passphrase error: %v", err)
	}
}

// TestParsePrivateKeyWithPassphrase_PKCS8FromSecureBuffer is the documented
// calling shape: file and passphrase both borrowed from SecureBuffers.
func TestParsePrivateKeyWithPassphrase_PKCS8FromSecureBuffer(t *testing.T) {
	pemBytes, _, pub := pkcs8Fixture(t, "ed25519-iter1")
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

// TestPKCS7Unpad pins the pad check: every valid pad length is accepted
// with the right plaintext length, and a pad byte of zero, one over the
// block, or one whose claimed bytes disagree is refused.
func TestPKCS7Unpad(t *testing.T) {
	for pad := 1; pad <= 16; pad++ {
		p := append(bytes.Repeat([]byte{0xAA}, 32-pad), bytes.Repeat([]byte{byte(pad)}, pad)...)
		n, ok := pkcs7Unpad(p)
		if !ok || n != 32-pad {
			t.Errorf("pad %d: (%d, %v), want (%d, true)", pad, n, ok, 32-pad)
		}
	}
	bad := map[string][]byte{
		"zero":             append(bytes.Repeat([]byte{0xAA}, 31), 0),
		"seventeen":        bytes.Repeat([]byte{17}, 32),
		"one byte wrong":   append(append(bytes.Repeat([]byte{0xAA}, 28), 4, 4, 5), 4),
		"first byte wrong": append(append(bytes.Repeat([]byte{0xAA}, 28), 3, 4, 4), 4),
	}
	for name, p := range bad {
		if n, ok := pkcs7Unpad(p); ok {
			t.Errorf("%s: accepted with length %d", name, n)
		}
	}
}

// TestReadASN1Count pins the INTEGER reader: minimal DER only, no negative
// values, and a value too wide for the cap reported as over rather than
// malformed.
func TestReadASN1Count(t *testing.T) {
	enc := func(content ...byte) *cryptobyte.String {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.INTEGER, func(b *cryptobyte.Builder) { b.AddBytes(content) })
		out, err := b.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		s := cryptobyte.String(out)
		return &s
	}
	cases := []struct {
		name    string
		content []byte
		n       int
		over    bool
		ok      bool
	}{
		{"zero", []byte{0}, 0, false, true},
		{"one", []byte{1}, 1, false, true},
		{"2048", []byte{0x08, 0x00}, 2048, false, true},
		{"128 with lead zero", []byte{0x00, 0x80}, 128, false, true},
		{"600000", []byte{0x09, 0x27, 0xc0}, 600000, false, true},
		{"max int32", []byte{0x7f, 0xff, 0xff, 0xff}, math.MaxInt32, false, true},
		{"over int32", []byte{0, 0x80, 0, 0, 0}, 0, true, true},
		{"five bytes", []byte{1, 0, 0, 0, 0}, 0, true, true},
		{"eight bytes", []byte{1, 0, 0, 0, 0, 0, 0, 0}, 0, true, true},
		{"lead zero then eight", []byte{0, 0x80, 0, 0, 0, 0, 0, 0, 0}, 0, true, true},
		{"empty", nil, 0, false, false},
		{"negative", []byte{0xff}, 0, false, false},
		{"non-minimal", []byte{0x00, 0x01}, 0, false, false},
		{"non-minimal zero", []byte{0x00, 0x00}, 0, false, false},
	}
	for _, c := range cases {
		n, over, ok := readASN1Count(enc(c.content...))
		if n != c.n || over != c.over || ok != c.ok {
			t.Errorf("%s: (%d, %v, %v), want (%d, %v, %v)", c.name, n, over, ok, c.n, c.over, c.ok)
		}
	}
	var s cryptobyte.String = []byte{0x04, 0x01, 0x01} // an OCTET STRING, not an INTEGER
	if _, _, ok := readASN1Count(&s); ok {
		t.Error("a non-INTEGER was read as a count")
	}
}
