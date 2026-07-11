//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && amd64

// Legacy wipe assembly for AMD64.
//
//   wipeScratchFrameFull()  — zeros a 32 KiB local frame using REP STOSB + SFENCE.
//     Allocates a fixed-size local stack frame and zeros it. Because it is
//     //go:noinline, the frame is separate from the caller's; zeroing it covers
//     register spills and local variable storage for the current execution
//     context. Safe because it only writes within its own allocated frame —
//     never past it.
//
// Intentionally omits CLFLUSH/CLFLUSHOPT: those are for evicting mmap'd
// secret pages from L1/L2/L3 cache (see secureWipe in wipe_amd64.s). For Go
// stack memory that does not outlive the process, REP STOSB + SFENCE is correct.
//
// Intel SDM references:
//   REP STOSB — Vol. 2B §4-527  Hardware-accelerated fill (ERMSB on recent CPUs).
//   SFENCE    — Vol. 2B §4-617  Serializes store operations.

#include "textflag.h"

// func wipeScratchFrameFull()
//
// Allocates 32768 bytes of local frame, zeros it with REP STOSB + SFENCE.
// Called on entry and deferred by Scrub/ScrubErr on the legacy path for a
// wide-coverage scrub around a secret-touching call tree.
TEXT ·wipeScratchFrameFull(SB), $32768-0
	MOVQ	$32768, CX
	MOVQ	SP, DI
	XORQ	AX, AX
	REP
	STOSB
	SFENCE
	RET
