// Vector-register clear for the AMD64 Scrub window. The implementation lives
// in vecclear_amd64.s; the _amd64.go filename suffix constrains this file to
// amd64 builds.
package secmem

import "golang.org/x/sys/cpu"

// clearVectorRegs zeroes the vector register file on the calling thread:
// X0–X15, with the YMM and ZMM widths of those registers where the CPU has
// them, and Z16–Z31 where AVX-512 is present.
//
// # Why
//
// Vectorised crypto keeps its working state in these registers: an AES round
// key in XMM, a BLAKE2b or ChaCha state in YMM, an Argon2 block row in X0–X7.
// Neither the Go ABI nor the scheduler ever clears them, so after fn returns
// the last values it computed sit in the register file of whichever thread ran
// it, readable by the next code that thread runs and copied wholesale by the
// next asynchronous preemption or synchronous fault. The frame wipe cannot
// reach them, because they are not on the stack.
//
// # Why it is safe
//
// The Go internal ABI treats every vector register as caller-saved scratch —
// no value the caller relies on is ever live in one across a call — and pins
// X15 as a fixed zero, which this makes zero again. Nothing live is destroyed.
//
// # Why it is on this thread and after fn
//
// The residue is a property of the thread that ran fn, so the window pins the
// goroutine to its OS thread (suppressAsyncPreempt) before fn starts and the
// clear runs as the first deferred call after fn returns, on the same thread,
// before the frame wipe and before the pin is released.
//
// # Why it is trusted
//
// The project rule for any register scrub: it ships only with an empirical
// test showing the registers hold residue without it and are zero with it.
// scrub_vecclear_test.go loads a pattern into the registers inside a Scrub
// window and reads the register file back after the window closes, with a
// control that repeats the window's exit sequence without the clear and
// requires the pattern to survive — the ABI does not reload vector registers
// around a call, so a clear here really does reach what fn left. A control
// that reads zero is a test failure, not a skip.
//
// # What it does not do
//
// General-purpose registers are not cleared: the ABI keeps live values in
// them across the call that would clear them, so a Go-level clear cannot be
// shown to do anything. Only runtime/secret, with the runtime's cooperation,
// covers those.
func clearVectorRegs() {
	if cpu.X86.HasAVX {
		clearVectorRegsAVX()
		if cpu.X86.HasAVX512F {
			// VZEROALL reaches ZMM0–ZMM15 in full but is defined only over
			// the AVX register set; Z16–Z31 exist solely under AVX-512 and
			// need their own instructions.
			clearVectorRegsAVX512Hi()
		}
		return
	}
	// No AVX means the registers are 128 bits wide and X0–X15 is the whole
	// file, so sixteen PXORs are a complete clear.
	clearVectorRegsSSE()
}

//go:noescape
func clearVectorRegsAVX()

//go:noescape
func clearVectorRegsAVX512Hi()

//go:noescape
func clearVectorRegsSSE()
