package secmemcrypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/deadpoets/secmem"
)

// TestArgon2Into_RFC9106Vectors runs the three RFC 9106 §5 vectors through
// the public API. They need the secret key K and associated data X, which
// golang.org/x/crypto/argon2 cannot express; before the fork this package
// could only check x/crypto against itself.
func TestArgon2Into_RFC9106Vectors(t *testing.T) {
	password := bytes.Repeat([]byte{0x01}, 32)
	salt := bytes.Repeat([]byte{0x02}, 16)
	p := Argon2Params{
		Time: 3, Memory: 32, Threads: 4,
		Secret: bytes.Repeat([]byte{0x03}, 8),
		Data:   bytes.Repeat([]byte{0x04}, 12),
	}
	for _, tc := range []struct {
		name string
		mode Argon2Mode
		tag  string
	}{
		{"5.1 Argon2d", Argon2d, "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"},
		{"5.2 Argon2i", Argon2i, "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"},
		{"5.3 Argon2id", Argon2id, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := mustDecodeHex(t, tc.tag)
			out := newTestBuffer(t, 32)
			p.Mode = tc.mode
			if err := Argon2Into(password, salt, p, out); err != nil {
				t.Fatalf("Argon2Into: %v", err)
			}
			if got := readBuf(t, out); !bytes.Equal(got, want) {
				t.Fatalf("tag = %x, want %x", got, want)
			}
		})
	}
}

// TestArgon2Into_MatchesXCrypto pins that Argon2IDKeyInto and Argon2Into
// with Mode Argon2i are byte-identical to x/crypto's IDKey and Key, at a
// multi-lane, multi-pass profile and at an odd output length that takes the
// blake2b.New fallback in H'.
func TestArgon2Into_MatchesXCrypto(t *testing.T) {
	password, salt := []byte("password"), []byte("0123456789abcdef")
	for _, size := range []int{32, 40, 64, 100} {
		out := newTestBuffer(t, size)
		if err := Argon2IDKeyInto(password, salt, 2, 256, 3, out); err != nil {
			t.Fatalf("Argon2IDKeyInto: %v", err)
		}
		if got, want := readBuf(t, out), argon2.IDKey(password, salt, 2, 256, 3, uint32(size)); !bytes.Equal(got, want) {
			t.Errorf("size %d: Argon2IDKeyInto %x != IDKey %x", size, got, want)
		}
		if err := Argon2Into(password, salt, Argon2Params{Mode: Argon2i, Time: 2, Memory: 256, Threads: 3}, out); err != nil {
			t.Fatalf("Argon2Into: %v", err)
		}
		if got, want := readBuf(t, out), argon2.Key(password, salt, 2, 256, 3, uint32(size)); !bytes.Equal(got, want) {
			t.Errorf("size %d: Argon2Into(i) %x != Key %x", size, got, want)
		}
	}
}

// TestArgon2Into_Errors pins every validation path as an error, never a
// panic, including the ones the fork adds (mode, input lengths).
func TestArgon2Into_Errors(t *testing.T) {
	good := Argon2Params{Time: 1, Memory: 8, Threads: 1}
	out := newTestBuffer(t, 32)

	if err := Argon2Into([]byte("p"), []byte("s"), good, nil); err == nil {
		t.Error("nil out: no error")
	}
	for name, p := range map[string]Argon2Params{
		"time=0":    {Time: 0, Memory: 8, Threads: 1},
		"threads=0": {Time: 1, Memory: 8, Threads: 0},
		"bad mode":  {Mode: Argon2Mode(7), Time: 1, Memory: 8, Threads: 1},
	} {
		err := Argon2Into([]byte("p"), []byte("s"), p, out)
		if err == nil {
			t.Errorf("%s: no error", name)
		} else if !strings.Contains(err.Error(), "argon2") {
			t.Errorf("%s: error does not name argon2: %v", name, err)
		}
	}
	// memory=0 is not an error: it is raised to the minimum, as upstream does.
	if err := Argon2Into([]byte("p"), []byte("s"), Argon2Params{Time: 1, Memory: 0, Threads: 1}, out); err != nil {
		t.Errorf("memory=0: %v", err)
	}

	destroyed := newTestBuffer(t, 32)
	destroyed.Destroy()
	if err := Argon2Into([]byte("p"), []byte("s"), good, destroyed); !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("destroyed out: err = %v, want ErrDestroyed", err)
	}
}

// TestArgon2Into_SecretAndDataChangeOutput pins that K and X are actually
// hashed in: the same password/salt with and without them must differ.
func TestArgon2Into_SecretAndDataChangeOutput(t *testing.T) {
	base := Argon2Params{Time: 1, Memory: 8, Threads: 1}
	derive := func(p Argon2Params) []byte {
		out := newTestBuffer(t, 32)
		if err := Argon2Into([]byte("p"), []byte("0123456789abcdef"), p, out); err != nil {
			t.Fatal(err)
		}
		return readBuf(t, out)
	}
	plain := derive(base)
	withK := derive(Argon2Params{Time: 1, Memory: 8, Threads: 1, Secret: []byte("pepper")})
	withX := derive(Argon2Params{Time: 1, Memory: 8, Threads: 1, Data: []byte("context")})
	if bytes.Equal(plain, withK) || bytes.Equal(plain, withX) || bytes.Equal(withK, withX) {
		t.Fatal("secret/data did not change the derived key")
	}
	if !bytes.Equal(plain, argon2.IDKey([]byte("p"), []byte("0123456789abcdef"), 1, 8, 1, 32)) {
		t.Fatal("no-K/no-X profile diverged from x/crypto")
	}
}

// newTestBuffer allocates an output buffer, skipping (not failing) when
// the platform refuses to lock memory: an environment condition, per the
// project's testing conventions.
func newTestBuffer(t *testing.T, size int) *secmem.SecureBuffer {
	t.Helper()
	b, err := secmem.NewEmptyBuffer(size)
	if err != nil {
		t.Skipf("NewEmptyBuffer(%d): %v", size, err)
	}
	t.Cleanup(func() { b.Destroy() })
	return b
}
