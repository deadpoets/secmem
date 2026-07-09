// security/wipe_arm64.s — ARM64 assembly for hardened cryptographic memory wipe.
//
// ARM Architecture Reference Manual (ARMv8-A) references:
//   DMB ISHST  — Data Memory Barrier, Inner Shareable, Stores only
//   DMB ISH    — Data Memory Barrier, Inner Shareable, Loads and Stores
//   DC CIVAC   — Data Cache Clean and Invalidate by Virtual Address to PoC
//                SYS #3, C7, C14, #1 — available to EL0 (unprivileged)
//   DSB ISH    — Data Synchronization Barrier, Inner Shareable
//   ISB SY     — Instruction Synchronization Barrier, full system
//
// Barrier encodings (AArch64 system instruction form):
//   DMB ISHST  = 0xD5033ABF  (CRm=0b1010, opc=0b101)
//   DMB ISH    = 0xD5033BBF  (CRm=0b1011, opc=0b101)
//   DSB ISH    = 0xD5033B9F  (CRm=0b1011, opc=0b100)
//   ISB SY     = 0xD5033FDF  (CRm=0b1111, opc=0b110)
//
// DC CIVAC encoding (SYS #3, C7, C14, #1, Xt):
//   Base: 0xD50B7E20 | Rt  — e.g. DC CIVAC, R2 = 0xD50B7E22
//
// Cache line size: 64 bytes (standard ARMv8-A minimum and Hetzner Ampere value).

#include "textflag.h"

// ─────────────────────────────────────────────────────────────────────────────
// func secureWipe(ptr unsafe.Pointer, length uintptr)
//
// Hardened, architecturally-complete wipe of the memory region at ptr for
// length bytes. The 5-step sequence:
//
//   Step 1 — DMB ISHST:  Serialize stores — prevent write reordering before zeroing.
//   Step 2 — zero loop:  MOVD ZR (8-byte) chunks + byte tail — zero the region.
//   Step 3 — DMB ISH:    Serialize stores before cache eviction.
//   Step 4 — DC CIVAC:   Evict every 64-byte cache line (L1/L2/L3) holding data.
//   Step 5 — DSB ISH + ISB SY: Completion barriers after eviction.
//
// Register allocation:
//   R0 = ptr (original base address — preserved through flush phase)
//   R1 = length (preserved through zero phase; becomes end address at flush)
//   R2 = moving write pointer (zero phase) / moving flush pointer (flush phase)
//   R3 = remaining byte count (zero phase)
//   R4 = alignment scratch (flush phase)
//
// NOSPLIT: no stack frame — prevents any secret data from being copied to the stack.
// ─────────────────────────────────────────────────────────────────────────────
TEXT ·secureWipe(SB), NOSPLIT, $0-16
	MOVD	ptr+0(FP), R0		// R0 = base address
	MOVD	length+8(FP), R1	// R1 = byte count
	CBZ	R0, done
	CBZ	R1, done

	// ── Step 1: DMB ISHST ──────────────────────────────────────────────────
	// Ensure all prior stores are visible before we begin zeroing.
	WORD	$0xD5033ABF		// DMB ISHST

	// ── Step 2: Zero the region ────────────────────────────────────────────
	// Main loop: 8 bytes per iteration using the architectural zero register.
	MOVD	R0, R2			// R2 = write pointer
	MOVD	R1, R3			// R3 = remaining bytes

zero_8_loop:
	CMP	$8, R3
	BLT	zero_byte_loop
	MOVD	ZR, (R2)		// store 8 zero bytes
	ADD	$8, R2
	SUB	$8, R3
	B	zero_8_loop

	// Tail: byte-by-byte for any remaining < 8 bytes.
zero_byte_loop:
	CBZ	R3, flush_start
	MOVB	ZR, (R2)		// store 1 zero byte
	ADD	$1, R2
	SUB	$1, R3
	B	zero_byte_loop

flush_start:
	// ── Step 3: DMB ISH ───────────────────────────────────────────────────
	// Serialize all stores before issuing cache eviction instructions.
	WORD	$0xD5033BBF		// DMB ISH

	// ── Step 4: DC CIVAC loop ─────────────────────────────────────────────
	// Evict every 64-byte cache line that overlaps [ptr, ptr+length).
	// Align the flush pointer down to the 64-byte cache-line boundary so the
	// first (potentially partial) cache line is not missed.
	//
	// Alignment: R4 = R0 & 63 (offset within cache line)
	//            R2 = R0 - R4  (64-byte aligned start)
	//            R1 = R0 + R1  (end address, computed in-place)
	AND	$63, R0, R4		// R4 = ptr mod 64
	SUB	R4, R0, R2		// R2 = aligned flush start
	ADD	R0, R1, R1		// R1 = end address (ptr + length)

flush_loop:
	WORD	$0xD50B7E22		// DC CIVAC, R2  (Clean+Invalidate by VA to PoC)
	ADD	$64, R2
	CMP	R1, R2			// sets flags: R2 - R1
	BLO	flush_loop		// branch if R2 < R1 (unsigned — more lines remain)

	// ── Step 5: DSB ISH + ISB SY ──────────────────────────────────────────
	// DSB ISH: wait for all cache operations to complete (Inner Shareable).
	// ISB SY:  flush the instruction pipeline — ensures subsequent reads see
	//          the evicted (zero) values rather than stale prefetched data.
	WORD	$0xD5033B9F		// DSB ISH
	WORD	$0xD5033FDF		// ISB SY

done:
	RET
