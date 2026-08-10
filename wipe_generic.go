//go:build !amd64 && !arm64

// Portable fallback for non-amd64 platforms. On amd64 the real implementations
// live in wipe_amd64.s / wipe_amd64.go / wipe_init_amd64.go.
package secmem

import (
	"sync/atomic"
	"unsafe"
)

// wipeZero is the opaque source of the zero byte, and wipeSink the opaque
// destination of the verification pass. Both are package-level atomics and
// neither is ever written with anything but zero — the point is not their
// value, it is that the compiler cannot PROVE their value and so cannot fold
// the wipe away. See secureWipe.
var (
	wipeZero atomic.Uint32 //nolint:gochecknoglobals // compiler barrier — see secureWipe.
	wipeSink atomic.Uint32 //nolint:gochecknoglobals // compiler barrier — see secureWipe.
)

// secureWipe zeroes length bytes at ptr on architectures with no assembly
// implementation (everything except amd64 and arm64).
//
// # Why it is written this way
//
// A plain `for i := range b { b[i] = 0 }` over memory nothing reads again is
// textbook dead-store elimination. Go's compiler does not currently remove it,
// but "does not currently" is not a guarantee, and this package's whole promise
// rests on the zeros actually reaching memory. The construction below does not
// depend on compiler goodwill:
//
//  1. The zero written is loaded from a package-level atomic, so the value
//     stored is not a compile-time constant and the stores cannot be folded
//     into a known-value memclr the optimizer may then reason about.
//  2. Every byte is read BACK and OR-accumulated, so the stores are observed —
//     a dead-store pass would have to prove the read pass dead first.
//  3. The accumulator is published to a second package-level atomic. An atomic
//     store is globally visible and may not be elided or reordered across, so
//     the read pass is provably live, which keeps the write pass live.
//
// The accumulator is always zero (that is the postcondition); it is the data
// dependency that matters, not the value. //go:noinline keeps a caller from
// inlining the body and re-deriving what it cannot derive here.
//
// The read-back pass costs a second traversal — accepted on this path, which
// is the fallback for architectures secmem does not ship assembly for. It is
// NOT a cache-line flush: archWipeFlushed is false here and Capabilities says
// so.
//
// This replaces an earlier subtle.ConstantTimeSelect(1, 0, b[i]) formulation,
// which read as a barrier but was not one: with a constant selector the whole
// expression folds to a constant 0 at compile time, leaving exactly the plain
// zeroing loop it was meant to protect.
//
//go:noinline
func secureWipe(ptr unsafe.Pointer, length uintptr) {
	if length == 0 || ptr == nil {
		return
	}
	b := unsafe.Slice((*byte)(ptr), length)

	z := byte(wipeZero.Load()) // opaque zero — not a compile-time constant
	for i := range b {
		b[i] = z
	}

	var acc byte
	for _, v := range b {
		acc |= v
	}
	wipeSink.Store(uint32(acc)) // observes the stores above; cannot be elided
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

// archWipeFlushed: the portable wipe is a store loop behind a compiler barrier
// with no cache-line flush — the zeros are written but lines may linger in
// cache.
const archWipeFlushed = false
