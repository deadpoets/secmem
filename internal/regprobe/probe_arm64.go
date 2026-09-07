// Package regprobe is a test-only helper: it copies the vector register file
// to memory, and memory into the vector register file, so a test can plant a
// known pattern in the registers and see what a scrub left behind. See
// probe_amd64.go for why it is a package of its own.
package regprobe

// DumpV copies V0–V31 into buf, 16 bytes each in register order.
//
//go:noescape
func DumpV(buf *[512]byte)

// FillV loads V0–V31 from buf, 16 bytes each in register order. Every vector
// register is caller-saved scratch under the Go arm64 ABI and none holds a
// fixed value, so all thirty-two are loaded and a dump after a fill shows the
// whole of buf back.
//
//go:noescape
func FillV(buf *[512]byte)
