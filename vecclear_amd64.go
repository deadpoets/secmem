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
// General-purpose registers are cleared separately, by clearGPRegs; Scrub
// calls both through clearRegisters.
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

// clearGPRegs zeroes the general-purpose registers a callee may clobber: AX,
// BX, CX, DX, SI, DI, R8–R13 and R15 — every one but SP, BP and R14 (g).
//
// # Why
//
// Scalar code keeps secrets in these: memmove moves a short copy through two
// of them, and hash and bignum assembly holds its state words there. Nothing
// clears them, so after fn returns they wait for the next asynchronous
// preemption on the thread to be saved onto some goroutine's stack — outside
// the window, where Scrub no longer blocks the signal and the frame wipe no
// longer reaches. The residue test in secmem-crypto measured exactly that on
// linux/arm64, where memmove moves a 17–32 byte copy through R6/R7 and
// R12/R13 and asyncPreempt saves those pairs side by side.
//
// # Why it is safe
//
// The Go ABI has no callee-saved general-purpose registers: a call site
// never keeps a live value in one across the call, so at the moment
// clearGPRegs is called nothing in these registers belongs to anyone. The
// registers with fixed meanings — the stack pointer, the frame pointer and g
// — are not touched.
//
// # Why it is trusted
//
// scrub_gpclear_test.go plants a pattern in every register this clears
// inside a window, and requires it to survive the window's exit sequence
// without the clear (the control) and to be gone after Scrub and ScrubErr.
//
//go:noescape
func clearGPRegs()
