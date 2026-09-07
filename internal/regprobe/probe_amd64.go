// Package regprobe is a test-only helper: it copies the vector register file
// to memory, and memory into the vector register file, so a test can plant a
// known pattern in the registers and see what a scrub left behind.
//
// It is its own package, rather than a _test.s file next to the code under
// test, because go/build treats every .s file in a package as production
// source — a *_test.s is assembled into the non-test package too — and a
// register-dump routine must not be one stray reference away from shipping
// inside a package that clears registers for secrecy. It is internal, so only
// this module can import it, and only test files do, so it is never linked
// into a consumer.
//
// Every routine is NOSPLIT with an empty frame so that nothing between the
// caller's fill and its dump touches the registers being observed.
package regprobe

// DumpXMM copies X0–X15 into buf, 16 bytes each in register order.
//
//go:noescape
func DumpXMM(buf *[256]byte)

// FillXMM loads X0–X14 from buf, 16 bytes each in register order. X15 is left
// alone: the Go internal ABI fixes it at zero, and the ABI wrapper around any
// assembly call re-zeroes it on return anyway, so a value planted there could
// never be observed. A dump after a fill therefore shows buf[0:240] followed by
// sixteen zero bytes.
//
//go:noescape
func FillXMM(buf *[256]byte)

// DumpZMMHi copies Z16–Z31 into buf, 64 bytes each in register order. It
// executes AVX-512 instructions unconditionally: call it only when
// cpu.X86.HasAVX512F reports the registers exist.
//
//go:noescape
func DumpZMMHi(buf *[1024]byte)

// FillZMMHi loads Z16–Z31 from buf, 64 bytes each in register order. Same
// AVX-512 requirement as DumpZMMHi.
//
//go:noescape
func FillZMMHi(buf *[1024]byte)
