//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && amd64

// Legacy hardening assembly for AMD64.
//
// DO NOT REMOVE — required for Windows/Darwin. See hardened_legacy.go header.
//
// Provides three functions for the legacy-path SecureContext:
//
//   wipeScratchFrame()      — zeros a 2 KiB local frame using REP STOSB + SFENCE.
//   wipeScratchFrameFull()  — zeros a 32 KiB local frame using REP STOSB + SFENCE.
//
//     These functions allocate a fixed-size local stack frame and zero it using
//     REP STOSB. Because they are //go:noinline, the local frame is separate
//     from the caller's frame. Zeroing it covers register spills and local
//     variable storage for the current execution context. This is safe because
//     we only write within our own allocated frame — never past it.
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

// func wipeScratchFrame()
//
// Allocates 2048 bytes of local frame, zeros it with REP STOSB + SFENCE.
// Local frame is stacked contiguously with the caller's frame in the goroutine
// stack — zeroing it covers recent register spills and stack-allocated secrets.
//
// Not NOSPLIT: Go may grow the goroutine stack if needed (safe).
// Must be //go:noinline at the Go level to guarantee a separate frame.
TEXT ·wipeScratchFrame(SB), $2048-0
	// DI = top of our 2048-byte local frame.
	// After function prologue, SP points to the bottom of our local frame.
	// The local area is [SP, SP+2048). Zero it from SP.
	MOVQ	$2048, CX
	MOVQ	SP, DI
	XORQ	AX, AX
	REP
	STOSB
	SFENCE
	RET

// func wipeScratchFrameFull()
//
// Allocates 32768 bytes of local frame, zeros it with REP STOSB + SFENCE.
// Used by SecureContext.Close() for a wider coverage scrub on scope exit.
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
