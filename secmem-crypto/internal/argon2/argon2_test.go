package argon2

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"runtime"
	"testing"

	upstream "golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
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

// TestLongInputs pins that the length of the H0 input is not a special
// case: passwords that end the input one byte short of, exactly on and one
// byte past a BLAKE2b block boundary, and ones far longer than any block,
// still match upstream.
func TestLongInputs(t *testing.T) {
	salt := []byte("0123456789abcdef")
	// The H0 input is 40 bytes of parameters and length prefixes, then the
	// password and the 16-byte salt.
	const fixed = 40 + 16
	for _, total := range []int{fixed, 127, 128, 129, 255, 256, 257, 4095, 4096, 4097, 4196, 8192, 1<<16 + 3} {
		password := bytes.Repeat([]byte("p"), total-fixed)
		ws := NewWorkspace(8, 1)
		got := make([]byte, 32)
		Derive(got, ModeID, password, salt, nil, nil, 1, ws)
		ws.Wipe()
		if want := upstream.IDKey(password, salt, 1, 8, 1, 32); !bytes.Equal(got, want) {
			t.Errorf("H0 input of %d bytes: fork %x, upstream %x", total, got, want)
		}
	}
}

// h0Reference is H0 as RFC 9106 defines it, computed the plain way: the
// whole input assembled and hashed with x/crypto's BLAKE2b-512.
func h0Reference(password, salt, secret, data []byte, time, memory uint32, threads uint8, keyLen uint32, mode Mode) [blake2b.Size]byte {
	var in []byte
	for _, v := range []uint32{uint32(threads), keyLen, memory, time, Version, uint32(mode)} {
		in = binary.LittleEndian.AppendUint32(in, v)
	}
	for _, part := range [][]byte{password, salt, secret, data} {
		in = binary.LittleEndian.AppendUint32(in, uint32(len(part)))
		in = append(in, part...)
	}
	return blake2b.Sum512(in)
}

// TestH0MatchesBLAKE2b covers what the upstream differential cannot: the
// secret key and associated data, which x/crypto's API does not take. Derive
// leaves H0 in the workspace until Wipe, so it is compared directly with
// BLAKE2b-512 of the assembled input, for part lengths that put every
// boundary between parts on either side of a block boundary.
func TestH0MatchesBLAKE2b(t *testing.T) {
	fill := func(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }
	for _, c := range []struct{ pw, salt, secret, data int }{
		{0, 0, 0, 0},
		{32, 16, 8, 12},
		{88, 0, 0, 0},     // exactly one block
		{87, 0, 0, 1},     // one byte into the second
		{84, 4, 0, 0},     // a length prefix ends the block
		{85, 3, 0, 0},     // a length prefix straddles it
		{216, 0, 0, 0},    // exactly two blocks
		{100, 16, 128, 0}, // a part exactly one block long
		{1, 1, 1, 8192},
		{5000, 16, 32, 5000},
		{0, 16, 4096, 0},
	} {
		password, salt := fill(c.pw, 0x01), fill(c.salt, 0x02)
		secret, data := fill(c.secret, 0x03), fill(c.data, 0x04)
		for _, mode := range []Mode{ModeD, ModeI, ModeID} {
			ws := NewWorkspace(8, 1)
			Derive(make([]byte, 32), mode, password, salt, secret, data, 1, ws)
			want := h0Reference(password, salt, secret, data, 1, 8, 1, 32, mode)
			if !bytes.Equal(ws.h0[:blake2b.Size], want[:]) {
				t.Errorf("mode %d %+v: H0 %x, BLAKE2b-512 of the input %x", mode, c, ws.h0[:blake2b.Size], want)
			}
			ws.Wipe()
		}
	}
}

// TestLongInputsStayInWorkspace pins that no input, however long, is copied
// to the heap on its way into H0: a derivation over a megabyte of associated
// data must allocate no more than one over a few bytes does. (What both
// allocate is the worker goroutines' bookkeeping; their stacks are not heap
// and are not counted.)
func TestLongInputsStayInWorkspace(t *testing.T) {
	password := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")
	secret := []byte("pepper")
	ws := NewWorkspace(8, 1)
	out := make([]byte, 32)
	allocated := func(data []byte) uint64 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		Derive(out, ModeID, password, salt, secret, data, 1, ws)
		runtime.ReadMemStats(&after)
		ws.Wipe()
		return after.TotalAlloc - before.TotalAlloc
	}
	long := bytes.Repeat([]byte{0x04}, 1<<20)
	allocated(nil) // warm up: the first goroutine start allocates more than later ones
	short := allocated([]byte("x"))
	if got := allocated(long); got > short+4096 {
		t.Fatalf("a derivation over %d bytes of associated data allocated %d bytes of heap, against %d for a short one: the input was copied out of the workspace", len(long), got, short)
	}
}

// TestWorkspaceReuse pins that a wiped Workspace derives correctly again.
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

func TestAdjustMemory(t *testing.T) {
	for _, c := range []struct{ mem, threads, want uint32 }{
		{64, 1, 64}, {65, 1, 64}, {7, 1, 8}, {0, 1, 8}, {37, 3, 36}, {1, 5, 40}, {1 << 16, 4, 1 << 16},
	} {
		if got := adjustMemory(c.mem, uint8(c.threads)); got != c.want {
			t.Errorf("adjustMemory(%d, %d) = %d, want %d", c.mem, c.threads, got, c.want)
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
	mustPanic("mode=3", func() { Derive(make([]byte, 32), Mode(3), nil, nil, nil, nil, 1, ws) })
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
