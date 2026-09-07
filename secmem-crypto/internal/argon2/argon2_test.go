package argon2

import (
	"bytes"
	"encoding/hex"
	"testing"

	upstream "golang.org/x/crypto/argon2"
)

// RFC 9106 §5 test vectors. All three use t=3, m=32 KiB, p=4, tag length
// 32, a 32-byte password of 0x01, a 16-byte salt of 0x02, an 8-byte secret
// key K of 0x03 and 12 bytes of associated data X of 0x04. Upstream's public
// API cannot express K or X, which is why secmem-crypto's kdf_test.go could
// only ever check upstream against itself.
var rfc9106Vectors = []struct {
	name string
	mode Mode
	tag  string
}{
	{"5.1 Argon2d", ModeD, "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"},
	{"5.2 Argon2i", ModeI, "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"},
	{"5.3 Argon2id", ModeID, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"},
}

func TestRFC9106Vectors(t *testing.T) {
	password := bytes.Repeat([]byte{0x01}, 32)
	salt := bytes.Repeat([]byte{0x02}, 16)
	secret := bytes.Repeat([]byte{0x03}, 8)
	data := bytes.Repeat([]byte{0x04}, 12)
	for _, tc := range rfc9106Vectors {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.tag)
			if err != nil {
				t.Fatal(err)
			}
			ws := NewWorkspace(32, 4)
			defer ws.Wipe()
			got := make([]byte, 32)
			Derive(got, tc.mode, password, salt, secret, data, 3, ws)
			if !bytes.Equal(got, want) {
				t.Fatalf("tag = %x, want %x", got, want)
			}
		})
	}
}

// deriveUpstream is the upstream call for a mode this package's public
// wrapper can express (Argon2d is not exposed upstream).
func deriveUpstream(mode Mode, password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	switch mode {
	case ModeI:
		return upstream.Key(password, salt, time, memory, threads, keyLen)
	case ModeID:
		return upstream.IDKey(password, salt, time, memory, threads, keyLen)
	}
	return nil
}

// TestMatchesUpstream is the byte-identity check across the shapes that
// matter: both public modes, single and multi-lane, every output length
// that takes a different path through H' (at most 32, then 48, 64, the
// lengths in between, and above 64 with and without a 64-byte tail), and
// the memory rounding edges.
func TestMatchesUpstream(t *testing.T) {
	type tc struct {
		time, memory uint32
		threads      uint8
		keyLen       uint32
	}
	cases := []tc{
		{1, 8, 1, 32}, {1, 64, 1, 32}, {2, 64, 1, 32}, {1, 64, 4, 32}, {3, 64, 4, 32},
		{1, 64, 2, 1}, {1, 64, 2, 4}, {1, 64, 2, 16}, {1, 64, 2, 31}, {1, 64, 2, 33},
		{1, 64, 2, 48}, {1, 64, 2, 64}, {1, 64, 2, 65}, {1, 64, 2, 72}, {1, 64, 2, 80},
		{1, 64, 2, 96}, {1, 64, 2, 100}, {1, 64, 2, 128}, {1, 64, 2, 1024}, {1, 64, 2, 1027},
		{1, 37, 3, 32},   // memory not a multiple of 4*threads: rounded down
		{1, 1, 5, 32},    // memory below the minimum: raised to 8*threads
		{2, 256, 8, 64},  // many lanes
		{1, 1024, 1, 32}, // 1 MiB single lane
	}
	password := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")
	for _, c := range cases {
		for _, mode := range []Mode{ModeI, ModeID} {
			want := deriveUpstream(mode, password, salt, c.time, c.memory, c.threads, c.keyLen)
			ws := NewWorkspace(c.memory, c.threads)
			got := make([]byte, c.keyLen)
			Derive(got, mode, password, salt, nil, nil, c.time, ws)
			ws.Wipe()
			if !bytes.Equal(got, want) {
				t.Errorf("mode %d %+v: fork %x\n upstream %x", mode, c, got, want)
			}
		}
	}
}

// TestEmptyInputs pins that empty password and salt behave as upstream
// (upstream accepts both; the length prefixes still get hashed).
func TestEmptyInputs(t *testing.T) {
	ws := NewWorkspace(8, 1)
	defer ws.Wipe()
	got := make([]byte, 32)
	Derive(got, ModeID, nil, nil, nil, nil, 1, ws)
	if want := upstream.IDKey(nil, nil, 1, 8, 1, 32); !bytes.Equal(got, want) {
		t.Fatalf("fork %x, upstream %x", got, want)
	}
}

// TestWorkspaceReuse pins that a wiped Workspace derives correctly again:
// the zero-block invariant the SSE mix step relies on is restored by Wipe.
func TestWorkspaceReuse(t *testing.T) {
	ws := NewWorkspace(64, 2)
	defer ws.Wipe()
	want := upstream.IDKey([]byte("pw"), []byte("salt"), 2, 64, 2, 32)
	for i := 0; i < 3; i++ {
		got := make([]byte, 32)
		Derive(got, ModeID, []byte("pw"), []byte("salt"), nil, nil, 2, ws)
		ws.Wipe()
		if !bytes.Equal(got, want) {
			t.Fatalf("run %d: %x, want %x", i, got, want)
		}
	}
}

func TestAdjustedMemory(t *testing.T) {
	for _, c := range []struct{ mem, threads, want uint32 }{
		{64, 1, 64}, {65, 1, 64}, {7, 1, 8}, {0, 1, 8}, {37, 3, 36}, {1, 5, 40}, {1 << 16, 4, 1 << 16},
	} {
		if got := AdjustedMemory(c.mem, uint8(c.threads)); got != c.want {
			t.Errorf("AdjustedMemory(%d, %d) = %d, want %d", c.mem, c.threads, got, c.want)
		}
	}
}

func TestDerivePanicsLikeUpstream(t *testing.T) {
	mustPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: no panic", name)
			}
		}()
		f()
	}
	ws := NewWorkspace(8, 1)
	mustPanic("time=0", func() { Derive(make([]byte, 32), ModeID, nil, nil, nil, nil, 0, ws) })
	mustPanic("empty out", func() { Derive(nil, ModeID, nil, nil, nil, nil, 1, ws) })
	mustPanic("nil ws", func() { Derive(make([]byte, 32), ModeID, nil, nil, nil, nil, 1, nil) })
	mustPanic("threads=0", func() { NewWorkspace(8, 0) })
}

// FuzzMatchesUpstream is the differential fuzz target: random parameters
// and inputs, fork versus upstream, byte for byte.
func FuzzMatchesUpstream(f *testing.F) {
	f.Add(uint32(1), uint32(64), uint8(1), uint32(32), true, []byte("p"), []byte("s"))
	f.Add(uint32(2), uint32(8), uint8(3), uint32(70), false, []byte(""), []byte("salt"))
	f.Fuzz(func(t *testing.T, time, memory uint32, threads uint8, keyLen uint32, id bool, password, salt []byte) {
		time = 1 + time%3
		memory %= 512
		threads = 1 + threads%4
		keyLen = 1 + keyLen%200
		mode := ModeI
		if id {
			mode = ModeID
		}
		want := deriveUpstream(mode, password, salt, time, memory, threads, keyLen)
		ws := NewWorkspace(memory, threads)
		got := make([]byte, keyLen)
		Derive(got, mode, password, salt, nil, nil, time, ws)
		ws.Wipe()
		if !bytes.Equal(got, want) {
			t.Fatalf("fork %x\nupstream %x", got, want)
		}
	})
}
