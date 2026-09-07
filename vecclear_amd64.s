// vecclear_amd64.s — vector-register clear for the AMD64 Scrub window.
// Prototypes and the reasoning live in vecclear_amd64.go.
//
// Every routine is NOSPLIT with an empty frame: no stack is touched, so the
// clear cannot itself leave a spill behind, and no stack-growth check can move
// the goroutine between fn's return and the clear.
//
// Intel SDM references:
//   VZEROALL — Vol. 2C §5-568  Zeroes YMM0–YMM15; in 64-bit mode on an
//              AVX-512 part the full ZMM0–ZMM15 width. Requires AVX.
//   VPXORQ   — Vol. 2C §5-449  EVEX-encoded XOR; a register with itself is
//              the canonical zeroing idiom and touches nothing else.
//              Requires AVX-512F.
//   PXOR     — Vol. 2B §4-403  SSE2 XOR; the amd64 baseline.

#include "textflag.h"

// func clearVectorRegsAVX()
// Requires: AVX.
TEXT ·clearVectorRegsAVX(SB), NOSPLIT, $0-0
	VZEROALL
	RET

// func clearVectorRegsAVX512Hi()
// Requires: AVX-512F. Clears Z16–Z31, which VZEROALL does not reach.
TEXT ·clearVectorRegsAVX512Hi(SB), NOSPLIT, $0-0
	VPXORQ Z16, Z16, Z16
	VPXORQ Z17, Z17, Z17
	VPXORQ Z18, Z18, Z18
	VPXORQ Z19, Z19, Z19
	VPXORQ Z20, Z20, Z20
	VPXORQ Z21, Z21, Z21
	VPXORQ Z22, Z22, Z22
	VPXORQ Z23, Z23, Z23
	VPXORQ Z24, Z24, Z24
	VPXORQ Z25, Z25, Z25
	VPXORQ Z26, Z26, Z26
	VPXORQ Z27, Z27, Z27
	VPXORQ Z28, Z28, Z28
	VPXORQ Z29, Z29, Z29
	VPXORQ Z30, Z30, Z30
	VPXORQ Z31, Z31, Z31
	RET

// func clearVectorRegsSSE()
// Requires: SSE2. Used only where AVX is absent, so the 128-bit XMM width is
// the whole register (a legacy-encoded PXOR leaves YMM upper halves alone,
// which is exactly why this path is not taken on an AVX part).
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
