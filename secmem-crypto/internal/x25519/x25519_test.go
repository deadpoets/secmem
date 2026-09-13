package x25519

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func unhex(t *testing.T, s string) *[32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad test vector %q", s)
	}
	return (*[32]byte)(b)
}

// RFC 7748 §5.2, the two single-shot vectors.
func TestScalarMult_RFC7748Vectors(t *testing.T) {
	for _, v := range []struct{ scalar, point, out string }{
		{"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
			"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
			"c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"},
		{"4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
			"e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
			"95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"},
	} {
		var dst [32]byte
		ScalarMult(&dst, unhex(t, v.scalar), unhex(t, v.point))
		if want := unhex(t, v.out); dst != *want {
			t.Errorf("ScalarMult(%s, %s) = %x, want %s", v.scalar, v.point, dst, v.out)
		}
	}
}

// RFC 7748 §5.2, the iterated vector: k, u = X25519(k, u), k each round,
// starting from k = u = 9. One million iterations only with -long.
func TestScalarMult_RFC7748Iterated(t *testing.T) {
	var k, u [32]byte
	k[0], u[0] = 9, 9
	check := map[int]string{
		1:    "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
		1000: "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
	}
	n := 1000
	if testing.Short() {
		n = 1
	}
	for i := 1; i <= n; i++ {
		var out [32]byte
		ScalarMult(&out, &k, &u)
		u, k = k, out
		if want, ok := check[i]; ok && k != *unhex(t, want) {
			t.Fatalf("after %d iterations k = %x, want %s", i, k, want)
		}
	}
}

// Differential against x/crypto/curve25519 (crypto/ecdh underneath) over
// random scalars and every class of point: random u (top bit set or not,
// possibly non-canonical), the canonical base point, and the low-order and
// non-canonical points RFC 7748 implementations are tested with, where the
// standard library reports an all-zero output as an error.
func TestScalarMult_MatchesStandardLibrary(t *testing.T) {
	special := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
		"4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
		"d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"0900000000000000000000000000000000000000000000000000000000000000",
	}
	var points []*[32]byte
	for _, s := range special {
		points = append(points, unhex(t, s))
	}
	for range 200 {
		p := new([32]byte)
		_, _ = rand.Read(p[:])
		points = append(points, p)
	}
	for _, p := range points {
		for range 5 {
			var scalar [32]byte
			_, _ = rand.Read(scalar[:])
			var got [32]byte
			ScalarMult(&got, &scalar, p)
			want, err := curve25519.X25519(scalar[:], p[:])
			if err != nil {
				if got != [32]byte{} {
					t.Fatalf("point %x: the standard library rejects it as low order, ScalarMult returned %x instead of zero", p, got)
				}
				continue
			}
			if !bytes.Equal(got[:], want) {
				t.Fatalf("ScalarMult(%x, %x) = %x, standard library %x", scalar, p, got, want)
			}
		}
	}
}

func FuzzScalarMult(f *testing.F) {
	f.Add(make([]byte, 32), make([]byte, 32))
	f.Fuzz(func(t *testing.T, scalar, point []byte) {
		if len(scalar) != 32 || len(point) != 32 {
			return
		}
		var got [32]byte
		ScalarMult(&got, (*[32]byte)(scalar), (*[32]byte)(point))
		want, err := curve25519.X25519(scalar, point)
		if err != nil {
			if got != [32]byte{} {
				t.Fatalf("low-order point %x gave %x, want zero", point, got)
			}
			return
		}
		if !bytes.Equal(got[:], want) {
			t.Fatalf("ScalarMult(%x, %x) = %x, standard library %x", scalar, point, got, want)
		}
	})
}
