//go:build amd64 && gc && !purego

// Package regprobe is a test-only helper: it copies the vector register
// file to memory so a test can see what an assembly routine left behind.
// It is its own package, rather than a _test.s file next to the code
// under test, because go/build treats every .s file in a package as
// production source — a *_test.s is assembled into the non-test package
// too — and a register-dump routine must not be one stray reference away
// from shipping inside a package that handles secrets. It is internal to
// this module and only test files import it, so it is never linked into a
// consumer. (The core module's internal/regprobe is the same idea with
// fill routines as well; this one only observes, which is all the tests
// here need.)
package regprobe

// DumpXMM copies X0–X15 into buf, 16 bytes each in register order.
//
//go:noescape
func DumpXMM(buf *[256]byte)
