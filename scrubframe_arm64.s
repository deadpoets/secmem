// scrubframe_arm64.s — ARM64 stack-frame scrub for the legacy Scrub path.
//
// The amd64 counterpart (scrubframe_amd64.s) has existed since the first
// release; arm64 fell through to the no-op stub in scrubframe_generic.go, so on
// every arm64 build WITHOUT GOEXPERIMENT=runtimesecret — which is every arm64
// build today, since the experiment is linux-only and not yet default — Scrub
// reserved no stack headroom and burned no residue. It was a documented no-op
// pretending to be a scrub. This is that gap closed.
//
// ARM Architecture Reference Manual (ARMv8-A) references:
//   STP  — Store Pair of registers; 16 bytes per instruction.
//   DMB ISHST — Data Memory Barrier, Inner Shareable, Stores. Same barrier the
//               wipe uses (wipe_arm64.s) to order the zeroing stores.
//
// Deliberately NO cache maintenance. DC CIVAC in the wipe evicts secret pages
// that outlive the process's use of them; this frame is goroutine stack that
// the runtime will reuse in-process, so ordering the stores is sufficient and
// eviction would only cost cycles. Same reasoning the amd64 file records for
// omitting CLFLUSH.

#include "textflag.h"

// func wipeScratchFrameFull()
//
// Allocates 32768 bytes of local frame and zeros it, matching the amd64 frame
// size exactly so the two platforms reserve and burn the same band.
//
// Two jobs, both load-bearing, and the order they happen in is the whole point
// (see the "why the wipe runs twice" note in scrub_legacy.go):
//
//   1. Called on ENTRY, the large frame forces any stack growth to happen
//      BEFORE fn writes a secret. A goroutine starts on 8 KiB, so a 32 KiB
//      frame triggers morestack; getting that copy out of the way early means
//      the abandoned segment holds nothing sensitive.
//   2. Called on EXIT (deferred), it zeroes the band fn's call tree used. Step
//      1 guarantees no growth happened in between, so this runs on the SAME
//      stack the residue is on rather than on a fresh copy.
//
// NOT NOSPLIT, deliberately: the stack-growth check at entry is the mechanism
// for job 1, and marking this NOSPLIT would both defeat that and blow the
// linker's nosplit budget at this frame size.
//
// R0 = write pointer, R1 = remaining bytes. Both are scratch under the Go ABI.
//
// The frame base is taken via the assembler's PSEUDO-SP (`frame-32768(SP)`),
// never via the hardware RSP. That is load-bearing, not style: Go's arm64
// prologue is
//
//	SUB  $32784, RSP, R20
//	STP  (R29, R30), -8(R20)   // saved FP at RSP-8, saved LR at RSP+0
//	MOVD R20, RSP
//
// so the saved LINK REGISTER sits at RSP+0 and the locals only begin at RSP+8.
// Zeroing from the hardware RSP would overwrite the return address and jump to
// 0 on RET. Letting the assembler resolve the local area keeps this correct if
// the prologue ever changes (frame-pointer settings, a future toolchain).
TEXT ·wipeScratchFrameFull(SB), $32768-0
	MOVD	$·zeroFrameSize(SB), R1
	MOVD	(R1), R1		// R1 = 32768, opaque to the optimizer
	MOVD	$frame-32768(SP), R0	// R0 = base of the LOCAL area (not RSP)

loop:
	// 16 bytes per iteration via the zero register pair. The frame size is a
	// multiple of 16, so no tail is possible.
	STP	(ZR, ZR), (R0)
	ADD	$16, R0
	SUB	$16, R1
	CBNZ	R1, loop

	// Order the zeroing stores before anything the caller does next. Matches
	// the SFENCE the amd64 path issues for the same reason.
	WORD	$0xD5033ABF		// DMB ISHST
	RET
