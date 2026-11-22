package regprobe

import "unsafe"

// StackMark returns an address inside the calling goroutine's stack. Two
// calls from the same function return the same value unless the runtime
// copied the stack in between, which it does to grow it and, during a
// collection, to shrink it.
//
// The register proofs need to know, because the copy is a memmove through
// the vector registers: when it lands between a clear and the dump that
// checks it, the dump shows the goroutine's own stack words (frame pointers,
// return addresses) in registers the clear had zeroed. Measured on
// linux/amd64 with a collection forced every few milliseconds: about one
// dump in a million, none with GODEBUG=gcshrinkstackoff=1, none with the
// collector off, and no planted byte in any of them.
//
//go:noinline
func StackMark() uintptr {
	var x byte
	return uintptr(unsafe.Pointer(&x))
}
