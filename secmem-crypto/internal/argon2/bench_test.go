package argon2

import (
	"fmt"
	"testing"

	upstream "golang.org/x/crypto/argon2"
)

// Acceptance criterion 5: the wipe's cost relative to Argon2's own. The
// pairs below run the fork (allocate, derive, wipe: what the public wrapper
// does per call) against upstream at the RFC 9106 second recommended
// profile secmem-crypto defaults to, at the second consumer's deployment
// parameters (t=2), and at a small profile where fixed costs would show if
// there were any.
//
// Measured 2026-09-07 on an Intel Core Ultra 7 265KF, Go 1.26.5, windows/
// amd64, -benchtime=5x -count=3: t3/64 MiB/p4 fork 33.8-35.9 ms vs upstream
// 28.6-28.8 ms; t2 fork 25.0-25.6 ms vs 20.3-20.9 ms; 8 MiB/p1 fork
// 3.7-4.1 ms vs 3.1-3.2 ms; BenchmarkWipeOnly 5.5 ms for 64 MiB (12 GB/s,
// cache-flushing). The difference is the wipe pass, to within a
// millisecond; the fork allocates slightly less than upstream.
func BenchmarkForkVsUpstream(b *testing.B) {
	password := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")
	for _, p := range []struct {
		name         string
		time, memory uint32
		threads      uint8
	}{
		{"t3_m64MiB_p4", 3, 64 * 1024, 4},
		{"t2_m64MiB_p4", 2, 64 * 1024, 4},
		{"t1_m8MiB_p1", 1, 8 * 1024, 1},
	} {
		b.Run(fmt.Sprintf("fork/%s", p.name), func(b *testing.B) {
			out := make([]byte, 32)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ws := NewWorkspace(p.memory, p.threads)
				Derive(out, ModeID, password, salt, nil, nil, p.time, ws)
				ws.Wipe()
			}
		})
		b.Run(fmt.Sprintf("upstream/%s", p.name), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = upstream.IDKey(password, salt, p.time, p.memory, p.threads, 32)
			}
		})
	}
}

// BenchmarkWipeOnly isolates the wipe itself at the 64 MiB profile.
func BenchmarkWipeOnly(b *testing.B) {
	ws := NewWorkspace(64*1024, 4)
	b.SetBytes(int64(ws.Memory()) * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ws.Wipe()
	}
}
