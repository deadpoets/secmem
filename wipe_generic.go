//go:build !amd64 && !arm64

// Portable fallback for non-amd64 platforms. On amd64 the real implementations
// live in wipe_amd64.s / wipe_amd64.go / wipe_init_amd64.go.
package secmem

import (
	"crypto/subtle"
	"unsafe"
)

// secureWipe zeroes length bytes at ptr using constant-time selection.
// subtle.ConstantTimeSelect prevents the compiler from eliminating the zeroing
// loop as a dead store — it always performs the full memory write.
func secureWipe(ptr unsafe.Pointer, length uintptr) {
	if length == 0 || ptr == nil {
		return
	}
	b := unsafe.Slice((*byte)(ptr), length)
	for i := range b {
		b[i] = byte(subtle.ConstantTimeSelect(1, 0, int(b[i])))
	}
}

// secureWipeSlice zeroes all bytes in b.
func secureWipeSlice(b []byte) {
	if len(b) == 0 {
		return
	}
	secureWipe(unsafe.Pointer(&b[0]), uintptr(len(b)))
}

// HasCLFLUSHOPT always returns false on non-amd64 platforms.
func HasCLFLUSHOPT() bool { return false }

// cpuid is not available on non-amd64; returns zero values.
func cpuid(_, _ uint32) (uint32, uint32, uint32, uint32) { return 0, 0, 0, 0 }

// setCLFLUSHOPTFlag is a no-op on non-amd64.
func setCLFLUSHOPTFlag(_ byte) {}
