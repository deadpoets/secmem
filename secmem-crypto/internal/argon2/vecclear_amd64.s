//go:build amd64 && gc && !purego

#include "textflag.h"

// func clearVectorRegsAVX()
// Requires: AVX. VZEROALL zeroes YMM0–YMM15 in full (the whole ZMM0–15
// width on AVX-512 parts); ZMM16–31 are not touched by any code in this
// package or in x/crypto/blake2b.
TEXT ·clearVectorRegsAVX(SB), NOSPLIT, $0-0
	VZEROALL
	RET

// func clearVectorRegsSSE()
// Requires: SSE2.
TEXT ·clearVectorRegsSSE(SB), NOSPLIT, $0-0
	PXOR X0, X0
	PXOR X1, X1
	PXOR X2, X2
	PXOR X3, X3
	PXOR X4, X4
	PXOR X5, X5
	PXOR X6, X6
	PXOR X7, X7
	PXOR X8, X8
	PXOR X9, X9
	PXOR X10, X10
	PXOR X11, X11
	PXOR X12, X12
	PXOR X13, X13
	PXOR X14, X14
	PXOR X15, X15
	RET
