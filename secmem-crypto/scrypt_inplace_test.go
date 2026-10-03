package secmemcrypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	xscrypt "golang.org/x/crypto/scrypt"
)

// scryptKey runs scryptCompute over a region of exactly the size it asks
// for, and requires what it promises about that region: wiped on return.
func scryptKey(t testing.TB, password, salt []byte, n, r, p, keyLen int) []byte {
	t.Helper()
	region := make([]byte, scryptRegionSize(len(salt), n, r, p))
	dst := make([]byte, keyLen)
	scryptCompute(dst, region, password, salt, n, r, p)
	if !bytes.Equal(region, make([]byte, len(region))) {
		t.Fatalf("N=%d r=%d p=%d: scryptCompute left its region non-zero", n, r, p)
	}
	return dst
}

// TestScrypt_RFC7914 is RFC 7914 §12 through this module's own PBKDF2 — the
// vectors internal/scrypt runs with the standard library's around the same
// memory-hard step. The fourth vector (N = 1048576, 1 GiB) is not run: it
// is sixteen times MaxScryptMemory.
func TestScrypt_RFC7914(t *testing.T) {
	for _, v := range []struct {
		password, salt string
		n, r, p        int
		want           string
	}{
		{"", "", 16, 1, 1,
			`77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
			 f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
			 fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
			 e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06`},
		{"password", "NaCl", 1024, 8, 16,
			`fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
			 7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
			 2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
			 c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40`},
		{"pleaseletmein", "SodiumChloride", 16384, 8, 1,
			`70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
			 fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
			 d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
			 e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87`},
	} {
		t.Run(fmt.Sprintf("N=%d,r=%d,p=%d", v.n, v.r, v.p), func(t *testing.T) {
			want, err := hex.DecodeString(strings.Join(strings.Fields(v.want), ""))
			if err != nil {
				t.Fatal(err)
			}
			if got := scryptKey(t, []byte(v.password), []byte(v.salt), v.n, v.r, v.p, len(want)); !bytes.Equal(got, want) {
				t.Fatalf("scrypt:\n got %x\nwant %x", got, want)
			}
		})
	}
}

// TestScrypt_MatchesXCrypto is the differential against
// golang.org/x/crypto/scrypt: r of 1, 2 and 8, p of 1, 2 and 3, a spread of
// N, the three AES key lengths and lengths either side of one PBKDF2 block,
// a passphrase longer than HMAC-SHA256's block (which PBKDF2 hashes first),
// and salts from one byte to the parser's bound — the long ones are longer
// than B at small r·p, which is the case where the PBKDF2 region is sized
// by the salt rather than by B.
func TestScrypt_MatchesXCrypto(t *testing.T) {
	passwords := [][]byte{[]byte("p"), []byte(testPassphrase), randBytes(t, 64), randBytes(t, 65), randBytes(t, 200)}
	salts := [][]byte{{7}, randBytes(t, 16), randBytes(t, 131), randBytes(t, maxPBES2Salt)}
	i := 0
	for _, n := range []int{2, 16, 256, 1024} {
		for _, r := range []int{1, 2, 8} {
			for _, p := range []int{1, 2, 3} {
				for _, keyLen := range []int{16, 24, 31, 32, 33, 64} {
					password, salt := passwords[i%len(passwords)], salts[i%len(salts)]
					i++
					want, err := xscrypt.Key(password, salt, n, r, p, keyLen)
					if err != nil {
						t.Fatal(err)
					}
					if got := scryptKey(t, password, salt, n, r, p, keyLen); !bytes.Equal(got, want) {
						t.Fatalf("N=%d r=%d p=%d keyLen=%d, password of %d, salt of %d: differs from x/crypto/scrypt\n got %x\nwant %x",
							n, r, p, keyLen, len(password), len(salt), got, want)
					}
				}
			}
		}
	}
}

// TestScryptRegionSize_IsWhatTheCapCounts pins MaxScryptMemory's doc: what
// a parse locks for the derivation is the 128·r·(N + 2·p + 2) the cap is
// measured over plus a fixed part of under 2 KiB — the key and the cipher's
// scratch included — whatever the salt's length, so the constant is the
// budget a caller has to provide and not an approximation of it.
func TestScryptRegionSize_IsWhatTheCapCounts(t *testing.T) {
	for _, c := range []struct{ n, r, p int }{
		{2, 1, 1}, {16, 1, 1}, {16, 8, 1}, {1024, 8, 2}, {16384, 8, 1}, {32768, 1, 1}, {32768, 15, 1}, {16384, 8, 32}, {4, 3, 7},
		{scryptBothCapsN, scryptBothCapsR, scryptBothCapsP},
	} {
		for _, saltLen := range []int{1, 8, 16, 128, 129, maxPBES2Salt} {
			counted := 128 * c.r * (c.n + 2*c.p + 2)
			locked := scryptRegionSize(saltLen, c.n, c.r, c.p) + 32 + cipherScratch
			if fixed := locked - counted; fixed < 0 || fixed >= 2048 {
				t.Errorf("N=%d r=%d p=%d, salt of %d: the call locks %d bytes, the cap counts %d: a difference of %d, want [0, 2048)",
					c.n, c.r, c.p, saltLen, locked, counted, fixed)
			}
		}
	}
}

// BenchmarkScryptInPlace is the cost behind MaxScryptWork's doc comment:
// one derivation at openssl's default parameters (N·r·p = 131072), with the
// region allocated once, so ns/op ÷ 131072 is the cost of a unit of work.
// The wipe of the 16 MiB region is inside the measurement, as it is inside
// a parse.
func BenchmarkScryptInPlace(b *testing.B) {
	const n, r, p = 16384, 8, 1
	salt := make([]byte, 16)
	region := make([]byte, scryptRegionSize(len(salt), n, r, p))
	dst := make([]byte, 32)
	b.ResetTimer()
	for range b.N {
		scryptCompute(dst, region, []byte(testPassphrase), salt, n, r, p)
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(n*r*p), "ns/unit")
}

// The parameters MaxScryptWork's doc gives as the slowest the caps admit.
const scryptBothCapsN, scryptBothCapsR, scryptBothCapsP = 16, 1, 262135

// TestScryptBothCaps_AreAtBothCaps pins what MaxScryptWork's doc says of
// those parameters: their working set is exactly MaxScryptMemory, N·r·p is
// 144 under MaxScryptWork, the parser runs them, and it refuses one more p.
// A file the parser opens can exceed them by that 144 in N·r·p, or by 7 in
// r·p (N=2, r=1, p=262142), and no further. Nothing is derived: the files
// carry p as raw INTEGER content, which the encoder keys with zeros.
func TestScryptBothCaps_AreAtBothCaps(t *testing.T) {
	const n, r, p = scryptBothCapsN, scryptBothCapsR, scryptBothCapsP
	if mem := 128 * r * (n + 2*p + 2); mem != MaxScryptMemory {
		t.Errorf("the working set is %d bytes, want MaxScryptMemory = %d", mem, MaxScryptMemory)
	}
	if under := MaxScryptWork - n*r*p; under != 144 {
		t.Errorf("N·r·p is %d under MaxScryptWork, want 144", under)
	}
	p8, _ := testPKCS8Ed25519(t)
	file := func(p int) []byte {
		raw := []byte{byte(p >> 16), byte(p >> 8), byte(p)}
		return encryptPKCS8(t, p8, pbes2Spec{kdf: oidScrypt, n: n, r: r, pRaw: raw})
	}
	f, err := readPBES2(file(p))
	if err != nil || f.n != n || f.r != r || f.p != p {
		t.Fatalf("readPBES2 read N=%d r=%d p=%d, %v: the parser does not run the parameters", f.n, f.r, f.p, err)
	}
	if _, err := readPBES2(file(p + 1)); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("one more p: %v, want ErrUnsupportedKey", err)
	}
}

// BenchmarkScryptInPlace_BothCaps is the other figure in MaxScryptWork's
// doc comment: one derivation at the parameters that meet both caps at
// once, under the longest salt the parser reads. Most of it is not the
// memory-hard step but the first PBKDF2, filling 32 MiB of B with one HMAC
// for every 32 bytes.
func BenchmarkScryptInPlace_BothCaps(b *testing.B) {
	const n, r, p = scryptBothCapsN, scryptBothCapsR, scryptBothCapsP
	salt := make([]byte, maxPBES2Salt)
	region := make([]byte, scryptRegionSize(len(salt), n, r, p))
	dst := make([]byte, 32)
	b.ResetTimer()
	for range b.N {
		scryptCompute(dst, region, []byte(testPassphrase), salt, n, r, p)
	}
}
