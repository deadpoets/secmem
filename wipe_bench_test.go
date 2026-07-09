package secmem

import (
	"testing"
	"unsafe"
)

// ---------------------------------------------------------------------------
// secureWipeSlice benchmarks — measures the wipe primitive at various sizes
// ---------------------------------------------------------------------------

// BenchmarkSecureWipeSlice measures the low-level zeroing + cache-flush cost.
// On amd64 this exercises the REP STOSB + CLFLUSH/CLFLUSHOPT assembly path.
// On other architectures it exercises the constant-time portable fallback.
func BenchmarkSecureWipeSlice(b *testing.B) {
	sizes := []int{32, 256, 4096, 65536}
	for _, sz := range sizes {
		buf := make([]byte, sz)
		b.Run(sizeName(sz), func(b *testing.B) {
			b.SetBytes(int64(sz))
			for b.Loop() {
				// Refill with non-zero to prevent the compiler from optimizing
				// away the wipe as a no-op on already-zero memory.
				buf[0] = 0xFF
				buf[sz-1] = 0xFF
				secureWipeSlice(buf)
			}
		})
	}
}

// BenchmarkSecureWipe_RawPointer measures the unsafe.Pointer entry point directly.
func BenchmarkSecureWipe_RawPointer(b *testing.B) {
	buf := make([]byte, 4096)
	ptr := unsafe.Pointer(&buf[0])
	b.SetBytes(4096)
	b.ResetTimer()
	for b.Loop() {
		buf[0] = 0xFF
		secureWipe(ptr, 4096)
	}
}
