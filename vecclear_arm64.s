// vecclear_arm64.s — vector-register clear for the ARM64 Scrub window.
// Prototype and reasoning in vecclear_arm64.go.
//
// NOSPLIT with an empty frame: no stack is touched, so the clear leaves no
// spill of its own and no stack-growth check can move the goroutine between
// fn's return and the clear.
//
// ARM Architecture Reference Manual (ARMv8-A) reference:
//   EOR (vector) — a register with itself is the zeroing idiom; the whole
//                  128-bit register is written, so no stale lane survives.

#include "textflag.h"

// func clearVectorRegs()
TEXT ·clearVectorRegs(SB), NOSPLIT, $0-0
	VEOR V0.B16, V0.B16, V0.B16
	VEOR V1.B16, V1.B16, V1.B16
	VEOR V2.B16, V2.B16, V2.B16
	VEOR V3.B16, V3.B16, V3.B16
	VEOR V4.B16, V4.B16, V4.B16
	VEOR V5.B16, V5.B16, V5.B16
	VEOR V6.B16, V6.B16, V6.B16
	VEOR V7.B16, V7.B16, V7.B16
	VEOR V8.B16, V8.B16, V8.B16
	VEOR V9.B16, V9.B16, V9.B16
	VEOR V10.B16, V10.B16, V10.B16
	VEOR V11.B16, V11.B16, V11.B16
	VEOR V12.B16, V12.B16, V12.B16
	VEOR V13.B16, V13.B16, V13.B16
	VEOR V14.B16, V14.B16, V14.B16
	VEOR V15.B16, V15.B16, V15.B16
	VEOR V16.B16, V16.B16, V16.B16
	VEOR V17.B16, V17.B16, V17.B16
	VEOR V18.B16, V18.B16, V18.B16
	VEOR V19.B16, V19.B16, V19.B16
	VEOR V20.B16, V20.B16, V20.B16
	VEOR V21.B16, V21.B16, V21.B16
	VEOR V22.B16, V22.B16, V22.B16
	VEOR V23.B16, V23.B16, V23.B16
	VEOR V24.B16, V24.B16, V24.B16
	VEOR V25.B16, V25.B16, V25.B16
	VEOR V26.B16, V26.B16, V26.B16
	VEOR V27.B16, V27.B16, V27.B16
	VEOR V28.B16, V28.B16, V28.B16
	VEOR V29.B16, V29.B16, V29.B16
	VEOR V30.B16, V30.B16, V30.B16
	VEOR V31.B16, V31.B16, V31.B16
	RET

// func clearGPRegs()
// Zeroes every general-purpose register a callee may clobber under the Go
// ABI: R0–R17 and R19–R27. Left alone: R18 (the platform register), R28 (g),
// R29 (the frame pointer), R30 (the link register) and RSP.
TEXT ·clearGPRegs(SB), NOSPLIT, $0-0
	MOVD ZR, R0
	MOVD ZR, R1
	MOVD ZR, R2
	MOVD ZR, R3
	MOVD ZR, R4
	MOVD ZR, R5
	MOVD ZR, R6
	MOVD ZR, R7
	MOVD ZR, R8
	MOVD ZR, R9
	MOVD ZR, R10
	MOVD ZR, R11
	MOVD ZR, R12
	MOVD ZR, R13
	MOVD ZR, R14
	MOVD ZR, R15
	MOVD ZR, R16
	MOVD ZR, R17
	MOVD ZR, R19
	MOVD ZR, R20
	MOVD ZR, R21
	MOVD ZR, R22
	MOVD ZR, R23
	MOVD ZR, R24
	MOVD ZR, R25
	MOVD ZR, R26
	MOVD ZR, R27
	RET
