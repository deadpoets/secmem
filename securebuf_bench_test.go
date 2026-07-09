package secmem

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"runtime"
	"testing"
)

// ---------------------------------------------------------------------------
// SecureBuffer — Lifecycle benchmarks
// ---------------------------------------------------------------------------

// BenchmarkNewBuffer measures allocation + mlock + copy cost.
// Each iteration allocates and immediately destroys to stay within mlock limits.
func BenchmarkNewBuffer(b *testing.B) {
	sizes := []int{32, 256, 4096, 65536}
	for _, sz := range sizes {
		raw := make([]byte, sz)
		if _, err := rand.Read(raw); err != nil {
			b.Fatalf("rand.Read: %v", err)
		}
		b.Run(sizeName(sz), func(b *testing.B) {
			b.SetBytes(int64(sz))
			for b.Loop() {
				// NewBuffer wipes the input; provide a fresh copy each iteration.
				tmp := make([]byte, sz)
				copy(tmp, raw)
				buf, err := NewBuffer(tmp)
				if err != nil {
					b.Fatalf("NewBuffer: %v", err)
				}
				_ = buf.Destroy()
			}
		})
	}
}

// BenchmarkNewEmptyBuffer measures zero-filled allocation cost (no copy).
func BenchmarkNewEmptyBuffer(b *testing.B) {
	sizes := []int{32, 256, 4096, 65536}
	for _, sz := range sizes {
		b.Run(sizeName(sz), func(b *testing.B) {
			b.SetBytes(int64(sz))
			for b.Loop() {
				buf, err := NewEmptyBuffer(sz)
				if err != nil {
					b.Fatalf("NewEmptyBuffer: %v", err)
				}
				_ = buf.Destroy()
			}
		})
	}
}

// BenchmarkDestroy measures the wipe+munmap+cleanup cost in isolation.
// Allocates and destroys serially to avoid exhausting mlock limits.
func BenchmarkDestroy(b *testing.B) {
	sizes := []int{32, 4096, 65536}
	for _, sz := range sizes {
		b.Run(sizeName(sz), func(b *testing.B) {
			b.SetBytes(int64(sz))
			for b.Loop() {
				buf, err := NewEmptyBuffer(sz)
				if err != nil {
					b.Fatalf("NewEmptyBuffer: %v", err)
				}
				_ = buf.Destroy()
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SecureBuffer — Access benchmarks (hot path)
// ---------------------------------------------------------------------------

// BenchmarkWithBytes measures the callback-based read access pattern.
func BenchmarkWithBytes(b *testing.B) {
	buf := mustBuffer(b, 64)
	defer destroyBuffer(b, buf)

	var sink byte
	b.ResetTimer()
	for b.Loop() {
		_ = buf.WithBytes(func(data []byte) {
			sink = data[0]
		})
	}
	runtime.KeepAlive(sink)
	b.ReportAllocs()
}

// BenchmarkWithBytesErr_Sized measures the error-returning callback with
// realistic payload sizes. Complements the noop baseline in securebuf_test.go.
func BenchmarkWithBytesErr_Sized(b *testing.B) {
	buf := mustBuffer(b, 64)
	defer destroyBuffer(b, buf)

	var sink byte
	b.ResetTimer()
	for b.Loop() {
		_ = buf.WithBytesErr(func(data []byte) error {
			sink = data[0]
			return nil
		})
	}
	runtime.KeepAlive(sink)
	b.ReportAllocs()
}

// BenchmarkRead measures bulk read with copy.
func BenchmarkRead(b *testing.B) {
	sizes := []int{32, 256, 4096}
	for _, sz := range sizes {
		b.Run(sizeName(sz), func(b *testing.B) {
			buf := mustBuffer(b, sz)
			defer destroyBuffer(b, buf)
			dst := make([]byte, sz)
			b.SetBytes(int64(sz))
			b.ResetTimer()
			for b.Loop() {
				_, _ = buf.Read(dst, 0)
			}
		})
	}
}

// BenchmarkWrite measures bulk write with copy.
func BenchmarkWrite(b *testing.B) {
	sizes := []int{32, 256, 4096}
	for _, sz := range sizes {
		b.Run(sizeName(sz), func(b *testing.B) {
			buf := mustBuffer(b, sz)
			defer destroyBuffer(b, buf)
			src := make([]byte, sz)
			b.SetBytes(int64(sz))
			b.ResetTimer()
			for b.Loop() {
				_, _ = buf.Write(src, 0)
			}
		})
	}
}

// BenchmarkByteAt measures single-byte indexed read.
func BenchmarkByteAt(b *testing.B) {
	buf := mustBuffer(b, 64)
	defer destroyBuffer(b, buf)

	var sink byte
	b.ResetTimer()
	for b.Loop() {
		sink, _ = buf.ByteAt(0)
	}
	runtime.KeepAlive(sink)
	b.ReportAllocs()
}

// BenchmarkSetByteAt measures single-byte indexed write.
func BenchmarkSetByteAt(b *testing.B) {
	buf := mustBuffer(b, 64)
	defer destroyBuffer(b, buf)

	b.ResetTimer()
	for b.Loop() {
		_ = buf.SetByteAt(0, 0x42)
	}
	b.ReportAllocs()
}

// BenchmarkConstantEqual measures constant-time comparison.
func BenchmarkConstantEqual(b *testing.B) {
	sizes := []int{32, 256, 4096}
	for _, sz := range sizes {
		b.Run(sizeName(sz), func(b *testing.B) {
			buf := mustBuffer(b, sz)
			defer destroyBuffer(b, buf)
			other := make([]byte, sz)
			b.SetBytes(int64(sz))
			b.ResetTimer()
			for b.Loop() {
				_, _ = buf.ConstantEqual(other)
			}
		})
	}
}

// BenchmarkWriteTo measures io.WriterTo performance.
func BenchmarkWriteTo(b *testing.B) {
	buf := mustBuffer(b, 4096)
	defer destroyBuffer(b, buf)

	b.SetBytes(4096)
	b.ResetTimer()
	for b.Loop() {
		_, _ = buf.WriteTo(io.Discard)
	}
}

// BenchmarkReadFrom measures io.ReaderFrom performance.
func BenchmarkReadFrom(b *testing.B) {
	buf := mustBuffer(b, 4096)
	defer destroyBuffer(b, buf)

	payload := make([]byte, 4096)
	b.SetBytes(4096)
	b.ResetTimer()
	for b.Loop() {
		_, _ = buf.ReadFrom(bytes.NewReader(payload))
	}
}

// ---------------------------------------------------------------------------
// SecureBuffer — Len / IsDestroyed (metadata hot path)
// ---------------------------------------------------------------------------

// BenchmarkLen measures the Len() read-lock overhead.
func BenchmarkLen(b *testing.B) {
	buf := mustBuffer(b, 64)
	defer destroyBuffer(b, buf)

	var sink int
	b.ResetTimer()
	for b.Loop() {
		sink = buf.Len()
	}
	runtime.KeepAlive(sink)
	b.ReportAllocs()
}

// BenchmarkIsDestroyed measures the destroyed-check read-lock overhead.
func BenchmarkIsDestroyed(b *testing.B) {
	buf := mustBuffer(b, 64)
	defer destroyBuffer(b, buf)

	var sink bool
	b.ResetTimer()
	for b.Loop() {
		sink = buf.IsDestroyed()
	}
	runtime.KeepAlive(sink)
	b.ReportAllocs()
}

// ---------------------------------------------------------------------------
// SecureBuffer — Scope benchmarks
// ---------------------------------------------------------------------------

// BenchmarkScope measures the full Scope lifecycle (alloc + callback + destroy).
func BenchmarkScope(b *testing.B) {
	sizes := []int{32, 256, 4096}
	for _, sz := range sizes {
		b.Run(sizeName(sz), func(b *testing.B) {
			b.SetBytes(int64(sz))
			for b.Loop() {
				_ = Scope(sz, func(buf *SecureBuffer) error {
					return buf.WithBytesErr(func(data []byte) error {
						data[0] = 0x42
						return nil
					})
				})
			}
		})
	}
}

// BenchmarkScopeWith measures ScopeWith with a NewBuffer constructor.
func BenchmarkScopeWith(b *testing.B) {
	raw := make([]byte, 64)
	b.ResetTimer()
	for b.Loop() {
		tmp := make([]byte, len(raw))
		copy(tmp, raw)
		_ = ScopeWith(
			func() (*SecureBuffer, error) { return NewBuffer(tmp) },
			func(buf *SecureBuffer) error {
				return buf.WithBytesErr(func(data []byte) error {
					data[0] = 0x42
					return nil
				})
			},
		)
	}
	b.ReportAllocs()
}

// ---------------------------------------------------------------------------
// SecureBuffer — mprotect benchmarks
// ---------------------------------------------------------------------------

// BenchmarkReadOnlyReadWrite measures the cost of toggling memory protection.
func BenchmarkReadOnlyReadWrite(b *testing.B) {
	buf := mustBuffer(b, 4096)
	defer destroyBuffer(b, buf)

	b.ResetTimer()
	for b.Loop() {
		_ = buf.ReadOnly()
		_ = buf.ReadWrite()
	}
	b.ReportAllocs()
}

// ---------------------------------------------------------------------------
// SecureBuffer — Concurrent access benchmarks
// ---------------------------------------------------------------------------

// BenchmarkWithBytesErr_Parallel_Sized measures contended read-lock throughput
// with a real payload read. Complements the noop baseline in securebuf_test.go.
func BenchmarkWithBytesErr_Parallel_Sized(b *testing.B) {
	buf := mustBuffer(b, 64)
	defer destroyBuffer(b, buf)

	var sink byte
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = buf.WithBytesErr(func(data []byte) error {
				sink = data[0]
				return nil
			})
		}
	})
	runtime.KeepAlive(sink)
}

// BenchmarkRead_Parallel measures contended bulk read throughput.
func BenchmarkRead_Parallel(b *testing.B) {
	buf := mustBuffer(b, 4096)
	defer destroyBuffer(b, buf)

	b.SetBytes(4096)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		dst := make([]byte, 4096)
		for pb.Next() {
			_, _ = buf.Read(dst, 0)
		}
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mustBuffer creates a SecureBuffer for benchmarks, calling b.Fatal on error.
// Forces a GC before allocation to release any mlock'd pages from prior benchmarks.
func mustBuffer(b *testing.B, size int) *SecureBuffer {
	b.Helper()
	runtime.GC()
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		b.Fatalf("rand.Read: %v", err)
	}
	buf, err := NewBuffer(raw)
	if err != nil {
		b.Fatalf("NewBuffer(%d): %v", size, err)
	}
	return buf
}

// destroyBuffer destroys a SecureBuffer and reports an error on failure.
func destroyBuffer(b *testing.B, buf *SecureBuffer) {
	b.Helper()
	if err := buf.Destroy(); err != nil {
		b.Errorf("Destroy: %v", err)
	}
}

// sizeName returns a human-readable size label for sub-benchmarks.
func sizeName(n int) string {
	switch {
	case n >= 1024*1024:
		return fmt.Sprintf("%dMiB", n/(1024*1024))
	case n >= 1024:
		return fmt.Sprintf("%dKiB", n/1024)
	default:
		return fmt.Sprintf("%dB", n)
	}
}
