//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && amd64

// Legacy wipe assembly for AMD64.
//
// Provides two functions:
//
//   wipeScratchFrameFull()  — zeros a 32 KiB local frame using REP STOSB + SFENCE.
//     Allocates a fixed-size local stack frame and zeros it. Because it is
//     //go:noinline, the frame is separate from the caller's; zeroing it covers
//     register spills and local variable storage for the current execution
//     context. Safe because it only writes within its own allocated frame —
//     never past it.
//
//   wipeBytes(b []byte) — zeros the bytes in b using REP STOSB + SFENCE.
//     Intentionally omits CLFLUSH/CLFLUSHOPT: those are for evicting mmap'd
//     secret pages from L1/L2/L3 cache. For Go slice memory (stack or heap)
//     that does not outlive the process, REP STOSB + SFENCE is correct.
//
// Intel SDM references:
//   REP STOSB — Vol. 2B §4-527  Hardware-accelerated fill (ERMSB on recent CPUs).
//   SFENCE    — Vol. 2B §4-617  Serializes store operations.

#include "textflag.h"

// func wipeScratchFrameFull()
//
// Allocates 32768 bytes of local frame, zeros it with REP STOSB + SFENCE.
// Deferred by Scrub/ScrubErr on the legacy path for a wide-coverage scrub
// after a secret-touching call tree returns.
TEXT ·wipeScratchFrameFull(SB), $32768-0
	MOVQ	$32768, CX
	MOVQ	SP, DI
	XORQ	AX, AX
	REP
	STOSB
	SFENCE
	RET

// func wipeBytes(b []byte)
//
// Stack layout (Go slice header, 3 words):
//   b_base+0(FP)  = data pointer (*byte) — 8 bytes
//   b_len+8(FP)   = length (int)         — 8 bytes
//   b_cap+16(FP)  = capacity (int)       — 8 bytes (unused)
// Total argument frame: 24 bytes. Local frame: 0.
TEXT ·wipeBytes(SB), NOSPLIT, $0-24
	MOVQ	b_base+0(FP), DI
	MOVQ	b_len+8(FP), CX
	TESTQ	CX, CX
	JZ	wipe_done
	XORQ	AX, AX
	REP
	STOSB
	SFENCE
wipe_done:
	RET
