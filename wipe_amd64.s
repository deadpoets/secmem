// security/wipe_amd64.s — AMD64 assembly for hardened cryptographic memory management.
//
// Intel SDM references:
//   CLFLUSH    — Vol. 2A §3-139  Opcode: NP 0F AE /7
//   CLFLUSHOPT — Vol. 2A §3-141  Opcode: 66 0F AE /7  CPUID.(EAX=7,ECX=0):EBX[bit 23]
//   LFENCE     — Vol. 2A §3-549  Serializes load operations.
//   SFENCE     — Vol. 2B §4-617  Serializes store operations.
//   REP STOSB  — Vol. 2B §4-527  Hardware-accelerated fill (ERMSB).
//   CPUID      — Vol. 2A §3-191  Processor identification.

#include "textflag.h"

// ─────────────────────────────────────────────────────────────────────────────
// Assembly-visible global: hasCLFLUSHOPT
// Written once during init(); read on every secureWipe call.
// Declared NOPTR (no GC pointers), size 1 byte.
// ─────────────────────────────────────────────────────────────────────────────
GLOBL ·hasCLFLUSHOPT(SB), NOPTR, $1

// ─────────────────────────────────────────────────────────────────────────────
// func setCLFLUSHOPTFlag(v byte)
//
// Writes a single byte (0 or 1) into hasCLFLUSHOPT.
// Called once from Go init() to bridge CPUID detection into the wipe loop.
//
// Stack layout: v+0(FP) = byte argument (1 byte)
// ─────────────────────────────────────────────────────────────────────────────
TEXT ·setCLFLUSHOPTFlag(SB), NOSPLIT, $0-1
    MOVB    v+0(FP), AL
    MOVB    AL, ·hasCLFLUSHOPT(SB)
    RET

// ─────────────────────────────────────────────────────────────────────────────
// func cpuid(eax, ecx uint32) (a, b, c, d uint32)
//
// Thin wrapper around the x86 CPUID instruction for runtime feature detection.
// Called once during package init(). Cost is acceptable.
//
// Stack layout:
//   eax+0(FP)  = input EAX  (4 bytes)
//   ecx+4(FP)  = input ECX  (4 bytes)
//   a+8(FP)    = output EAX (4 bytes)
//   b+12(FP)   = output EBX (4 bytes)
//   c+16(FP)   = output ECX (4 bytes)
//   d+20(FP)   = output EDX (4 bytes)
// Total frame: 24 bytes of arguments (0 local).
// ─────────────────────────────────────────────────────────────────────────────
TEXT ·cpuid(SB), NOSPLIT, $0-24
    MOVL    eax+0(FP), AX
    MOVL    ecx+4(FP), CX
    CPUID
    MOVL    AX, a+8(FP)
    MOVL    BX, b+12(FP)
    MOVL    CX, c+16(FP)
    MOVL    DX, d+20(FP)
    RET

// ─────────────────────────────────────────────────────────────────────────────
// func secureWipe(ptr unsafe.Pointer, length uintptr)
//
// Hardened, architecturally-complete wipe of the memory region at ptr for
// length bytes. The 5-step sequence:
//
//   Step 1 — LFENCE:         Serialize loads, prevent speculative pre-read.
//   Step 2 — REP STOSB:      Zero the region (ERMSB-accelerated where available).
//   Step 3 — SFENCE:         Serialize stores before cache eviction.
//   Step 4 — CLFLUSH[OPT]:   Evict every cache line (L1/L2/L3) holding secret data.
//   Step 5 — SFENCE+LFENCE:  Final barriers after eviction.
//
// FLUSH LOOP CORRECTNESS: The flush pointer R8 starts at the cache line
// containing ptr (ptr rounded DOWN to 64 via AND $-64) and advances by 64
// until it reaches the end address R9 = ptr+length (CMPQ/JB = unsigned below).
// Aligning the start down is required: an unaligned [ptr, ptr+length) region
// spans ceil(length/64)+1 cache lines, so a count-based loop that started at
// the unaligned ptr would miss the final partial line (this is what the arm64
// path already does, and what the prior amd64 count-based loop got wrong for
// non-page-aligned slices). Rounding ptr down stays within ptr's page (page
// size >= 64), so the flushed base address is always mapped. CLFLUSH/CLFLUSHOPT
// operate on the full 64-byte aligned line containing the addressed byte
// (Intel SDM Vol. 2A §3-139).
//
// CLFLUSHOPT encoding for [R8]: 0x66 0x41 0x0F 0xAE 0x38
//   0x66 = mandatory prefix (distinguishes from CLFLUSH)
//   0x41 = REX.B (extends rm to R8)
//   0x0F = two-byte opcode escape
//   0xAE = opcode byte
//   0x38 = ModR/M: mod=00 reg=111(/7) rm=000 → [R8]
//
// Stack layout:
//   ptr+0(FP)    = base pointer  (8 bytes)
//   length+8(FP) = byte count    (8 bytes)
// Total frame: 16 bytes of arguments (0 local).
// ─────────────────────────────────────────────────────────────────────────────
TEXT ·secureWipe(SB), NOSPLIT, $0-16
    MOVQ    ptr+0(FP), DI
    MOVQ    length+8(FP), CX

    TESTQ   CX, CX
    JZ      done

    // Step 1: Serialize loads — prevent speculative pre-read of secret data.
    LFENCE

    // Precompute the flush bounds BEFORE REP STOSB consumes DI and CX:
    //   R9 = ptr + length             (end address, exclusive)
    //   R8 = ptr rounded down to 64   (aligned flush start; covers a partial
    //                                  leading cache line on unaligned slices)
    MOVQ    DI, R9
    ADDQ    CX, R9              // R9 = end address (ptr + length)
    MOVQ    DI, R8
    ANDQ    $-64, R8           // R8 = ptr & ~63 — aligned-down flush pointer
    XORQ    AX, AX              // AL = 0x00

    // Step 2: Hardware-accelerated zeroing.
    // REP STOSB stores AL into [RDI], incrementing RDI, decrementing RCX.
    REP
    STOSB

    // Step 3: Store barrier — commit zeros before cache eviction.
    SFENCE

    // Step 4: Cache line eviction. Flush each line in [R8, R9) — i.e. every
    // 64-byte line that overlaps the wiped region, including the leading and
    // trailing partial lines.
    CMPB    ·hasCLFLUSHOPT(SB), $1
    JE      flush_opt_loop

flush_legacy_loop:
    // CLFLUSH [R8]: strictly-ordered eviction.
    CLFLUSH (R8)
    ADDQ    $64, R8
    CMPQ    R8, R9
    JB      flush_legacy_loop
    JMP     flush_done

flush_opt_loop:
    // CLFLUSHOPT [R8]: pipelined eviction (Skylake+, Zen+).
    // Encoding: 0x66 0x41 0x0F 0xAE 0x38
    BYTE $0x66; BYTE $0x41; BYTE $0x0F; BYTE $0xAE; BYTE $0x38
    ADDQ    $64, R8
    CMPQ    R8, R9
    JB      flush_opt_loop

flush_done:
    // Step 5: Final barriers — ensure all flushes retire before continuing.
    SFENCE
    LFENCE

done:
    RET
