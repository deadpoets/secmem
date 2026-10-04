package secmemcrypto

import (
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/deadpoets/secmem"
)

// syntheticRSA is a consistent RSA private key whose "primes" are not prime:
// p = 2^pBits − a and q = ¾·2^qBits + b for the smallest offsets that make
// p, q, p−1 and q−1 coprime to what they must be. Finding real 8192-bit
// primes takes minutes; nothing between a key file and a signer tests
// primality (the standard library validates n = p·q and the CRT values, and
// those hold here), so such a key is admitted exactly as a real one of the
// same size is — which is what a size-cap test needs. It cannot make a
// signature that verifies, and no test asks it to.
type syntheticRSA struct {
	N, D, P, Q, Dp, Dq, Qinv *big.Int
	E                        int
}

func newSyntheticRSA(t testing.TB, pBits, qBits int) syntheticRSA {
	t.Helper()
	const e = 65537
	one, bigE := big.NewInt(1), big.NewInt(e)
	coprimeToE := func(x *big.Int) bool {
		return new(big.Int).GCD(nil, nil, new(big.Int).Sub(x, one), bigE).Cmp(one) == 0
	}
	p := new(big.Int).Lsh(one, uint(pBits))
	for p.Sub(p, one); p.Bit(0) == 0 || !coprimeToE(p); p.Sub(p, one) {
	}
	q := new(big.Int).Lsh(big.NewInt(3), uint(qBits-2))
	for q.Add(q, one); q.Bit(0) == 0 || !coprimeToE(q) || new(big.Int).GCD(nil, nil, p, q).Cmp(one) != 0; q.Add(q, one) {
	}
	k := syntheticRSA{P: p, Q: q, E: e, N: new(big.Int).Mul(p, q)}
	pm1, qm1 := new(big.Int).Sub(p, one), new(big.Int).Sub(q, one)
	k.D = new(big.Int).ModInverse(bigE, new(big.Int).Mul(pm1, qm1))
	if k.D == nil {
		t.Fatal("synthetic key: e has no inverse")
	}
	k.Dp = new(big.Int).Mod(k.D, pm1)
	k.Dq = new(big.Int).Mod(k.D, qm1)
	k.Qinv = new(big.Int).ModInverse(q, p)
	if p.BitLen() != pBits || q.BitLen() != qBits || k.N.BitLen() != pBits+qBits {
		t.Fatalf("synthetic key: p, q, n are %d, %d, %d bits, want %d, %d, %d", p.BitLen(), q.BitLen(), k.N.BitLen(), pBits, qBits, pBits+qBits)
	}
	return k
}

func (k syntheticRSA) public() *rsa.PublicKey { return &rsa.PublicKey{N: k.N, E: k.E} }

// pkcs1 is the RSAPrivateKey encoding, written without the standard
// library's key type so that nothing validates it on the way out.
func (k syntheticRSA) pkcs1(t testing.TB) []byte {
	t.Helper()
	der, err := asn1.Marshal(struct {
		Version             int
		N                   *big.Int
		E                   int
		D, P, Q, Dp, Dq, Qi *big.Int
	}{0, k.N, k.E, k.D, k.P, k.Q, k.Dp, k.Dq, k.Qinv})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pkcs8WrapRSA(t testing.TB, pkcs1 []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: oidRSA, Parameters: asn1.NullRawValue}, pkcs1})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (k syntheticRSA) openssh(t *testing.T) []byte {
	t.Helper()
	fields := sshRSAFields{N: k.N, E: big.NewInt(int64(k.E)), D: k.D, Iqmp: k.Qinv, P: k.P, Q: k.Q, Comment: "c"}
	inner := sshInner{Check1: 5, Check2: 5, Keytype: "ssh-rsa", Rest: ssh.Marshal(fields)}
	// The public-key block is written by hand: ssh.NewPublicKey is free to
	// have size opinions of its own.
	pubBlob := ssh.Marshal(struct {
		Type string
		E, N *big.Int
	}{"ssh-rsa", big.NewInt(int64(k.E)), k.N})
	return opensshContainer(pubBlob, inner, opensshCipherNone, 1, nil)
}

// rsaIngressRoutes is every way an RSA private key reaches NewRSASigner.
func rsaIngressRoutes(t *testing.T, k syntheticRSA) map[string]func() (Signer, error) {
	t.Helper()
	p1 := k.pkcs1(t)
	p8 := pkcs8WrapRSA(t, p1)
	toPEM := func(typ string, der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}) }
	open := func(data []byte) func() (Signer, error) {
		return func() (Signer, error) { return ParsePrivateKey(data, AllowHeapTransients()) }
	}
	enc := encryptPKCS8(t, p8, pbes2Spec{})
	osh := k.openssh(t)
	direct := func(der []byte) func() (Signer, error) {
		return func() (Signer, error) {
			buf, err := secmem.NewBuffer(append([]byte(nil), der...))
			if err != nil {
				t.Skipf("no secure memory: %v", err)
			}
			s, err := NewRSASigner(buf, AllowHeapTransients())
			if err != nil {
				_ = buf.Destroy()
				return nil, err
			}
			return s, nil
		}
	}
	return map[string]func() (Signer, error){
		"PKCS#1 PEM":          open(toPEM("RSA PRIVATE KEY", p1)),
		"PKCS#1 DER":          open(p1),
		"PKCS#8 PEM":          open(toPEM("PRIVATE KEY", p8)),
		"PKCS#8 DER":          open(p8),
		"OpenSSH PEM":         open(armourRaw(osh)),
		"OpenSSH raw":         open(osh),
		"NewRSASigner":        direct(p1),
		"NewRSASigner PKCS#8": direct(p8),
		"encrypted PKCS#8": func() (Signer, error) {
			return ParsePrivateKeyWithPassphrase(toPEM("ENCRYPTED PRIVATE KEY", enc), []byte(testPassphrase), AllowHeapTransients())
		},
	}
}

// TestRSASizeCaps_EveryRoute: the modulus and prime caps are one rule, not a
// property of the OpenSSH container. A key exactly at the caps opens on
// every route, and one a single bit over is refused on every route — as
// malformed where the route reports causes, and as the one post-decryption
// error where it does not.
func TestRSASizeCaps_EveryRoute(t *testing.T) {
	atCap := newSyntheticRSA(t, rsaMaxPrimeBits, rsaMaxPrimeBits)
	for name, open := range rsaIngressRoutes(t, atCap) {
		t.Run("at cap/"+name, func(t *testing.T) {
			s, err := open()
			if err != nil {
				t.Fatalf("a %d-bit key was refused: %v", rsaMaxModulusBits, err)
			}
			defer s.Destroy()
			if !atCap.public().Equal(s.Public()) {
				t.Fatal("Public() is not the key that was parsed")
			}
		})
	}

	overCap := newSyntheticRSA(t, rsaMaxPrimeBits+1, rsaMaxPrimeBits)
	for name, open := range rsaIngressRoutes(t, overCap) {
		t.Run("over cap/"+name, func(t *testing.T) {
			s, err := open()
			if err == nil {
				s.Destroy()
				t.Fatalf("a %d-bit key with a %d-bit prime was accepted", rsaMaxModulusBits+1, rsaMaxPrimeBits+1)
			}
			if name == "encrypted PKCS#8" {
				if !errors.Is(err, errPBES2Decrypt) {
					t.Fatalf("%v, want the post-decryption error", err)
				}
				return
			}
			if !errors.Is(err, errMalformed) || !strings.Contains(err.Error(), "too large") {
				t.Fatalf("%v, want errMalformed naming the size", err)
			}
		})
	}
}

// TestRSABounds pins each bound of the in-place scan on its own, with
// integers that are sizes and nothing else: the scan reads lengths, so it
// must refuse these before anything multiplies them.
func TestRSABounds(t *testing.T) {
	ones := func(bits int) *big.Int {
		return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
	}
	base := func() syntheticRSA {
		return syntheticRSA{
			N: ones(rsaMaxModulusBits), E: 65537, D: ones(rsaMaxModulusBits),
			P: ones(rsaMaxPrimeBits), Q: ones(rsaMaxPrimeBits),
			Dp: ones(rsaMaxPrimeBits), Dq: ones(rsaMaxPrimeBits), Qinv: ones(rsaMaxPrimeBits),
		}
	}
	check := func(k syntheticRSA) error {
		p1 := k.pkcs1(t)
		err1 := checkRSAKeySize(p1)
		err8 := checkRSAKeySize(pkcs8WrapRSA(t, p1))
		if (err1 == nil) != (err8 == nil) {
			t.Fatalf("PKCS#1 says %v, the same key in PKCS#8 says %v", err1, err8)
		}
		return err1
	}
	if err := check(base()); err != nil {
		t.Fatalf("every integer at its cap: %v", err)
	}
	for name, mutate := range map[string]func(*syntheticRSA){
		"modulus":         func(k *syntheticRSA) { k.N = ones(rsaMaxModulusBits + 1) },
		"private exp":     func(k *syntheticRSA) { k.D = ones(rsaMaxModulusBits + 1) },
		"prime p":         func(k *syntheticRSA) { k.P = ones(rsaMaxPrimeBits + 1) },
		"prime q":         func(k *syntheticRSA) { k.Q = ones(rsaMaxPrimeBits + 1) },
		"dp":              func(k *syntheticRSA) { k.Dp = ones(rsaMaxPrimeBits + 1) },
		"dq":              func(k *syntheticRSA) { k.Dq = ones(rsaMaxPrimeBits + 1) },
		"qinv":            func(k *syntheticRSA) { k.Qinv = ones(rsaMaxPrimeBits + 1) },
		"public exp wide": func(k *syntheticRSA) { k.E = 1 << rsaMaxExponentBits },
		"public exp even": func(k *syntheticRSA) { k.E = 65536 },
		"public exp one":  func(k *syntheticRSA) { k.E = 1 },
	} {
		k := base()
		mutate(&k)
		if err := check(k); !errors.Is(err, errMalformed) {
			t.Errorf("%s over its bound: %v, want errMalformed", name, err)
		}
	}

	// Multi-prime keys: each further prime's three integers are bounded like
	// a prime, and their number is bounded too — or a file could carry any
	// amount of arithmetic in that list.
	multi := func(extra int, width int) []byte {
		type other struct{ R, D, T *big.Int }
		k := base()
		others := make([]other, extra)
		for i := range others {
			others[i] = other{ones(width), ones(width), ones(width)}
		}
		der, err := asn1.Marshal(struct {
			Version             int
			N                   *big.Int
			E                   int
			D, P, Q, Dp, Dq, Qi *big.Int
			Others              []other
		}{1, k.N, k.E, k.D, k.P, k.Q, k.Dp, k.Dq, k.Qinv, others})
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	if err := checkRSAKeySize(multi(rsaMaxOtherPrimes, rsaMaxPrimeBits)); err != nil {
		t.Errorf("%d further primes at the cap: %v", rsaMaxOtherPrimes, err)
	}
	if err := checkRSAKeySize(multi(rsaMaxOtherPrimes+1, 64)); !errors.Is(err, errMalformed) {
		t.Errorf("%d further primes: %v, want errMalformed", rsaMaxOtherPrimes+1, err)
	}
	if err := checkRSAKeySize(multi(1, rsaMaxPrimeBits+1)); !errors.Is(err, errMalformed) {
		t.Errorf("a further prime over the cap: %v, want errMalformed", err)
	}

	// Anything that is not one of the two structures is refused here rather
	// than handed on unmeasured.
	for name, der := range map[string][]byte{
		"empty":           nil,
		"not DER":         []byte("not DER at all"),
		"empty sequence":  {0x30, 0x00},
		"truncated":       base().pkcs1(t)[:100],
		"integer missing": {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x03},
	} {
		if err := checkRSAKeySize(der); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestGenerateRSASigner_RejectsOverCap: the cap applies to generation too,
// and is decided before the (very long) search for primes of that size.
func TestGenerateRSASigner_RejectsOverCap(t *testing.T) {
	s, err := GenerateRSASigner(rsaMaxModulusBits+1, AllowHeapTransients())
	if err == nil {
		s.Destroy()
		t.Fatal("generated a key over the modulus cap")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("%v, want a refusal naming the size", err)
	}
}
