//go:build linux || darwin || windows

// Proof tests for the guard pages and the overflow canary. These do not test
// bookkeeping — they prove the protections behave as claimed:
//
//   - reading one byte past either end of the secret area FAULTS (the guard
//     pages are real PROT_NONE / uncommitted memory, not an accounting fiction);
//   - an overflow that stays inside the mapping is DETECTED by the canary on
//     Destroy / Release, and a clean lifecycle reports nothing.
//
// Probing dead addresses requires unsafe pointer reads with
// debug.SetPanicOnFault — there is no safe-Go way to observe a fault.

package secmem

import (
	"bytes"
	"errors"
	"runtime/debug"
	"testing"
	"unsafe"
)

// probeRead reads one byte at addr. noinline keeps the fault attributable to
// this exact load; nocheckptr because probing addresses outside any Go object
// is the entire point.
//
//go:noinline
//go:nocheckptr
func probeRead(addr uintptr) byte {
	return *(*byte)(unsafe.Pointer(addr)) //nolint:govet // unsafeptr: intentional guard-page probe
}

// probeWrite writes one byte at addr (used to corrupt canary slack, which IS
// mapped RW — this only faults if aimed at a guard).
//
//go:noinline
//go:nocheckptr
func probeWrite(addr uintptr, v byte) {
	*(*byte)(unsafe.Pointer(addr)) = v //nolint:govet // unsafeptr: intentional canary corruption
}

// corruptCanary flips the byte at addr so it can no longer match the canary
// pattern, whatever that random process-global byte happens to be. Writing a
// fixed value (e.g. 0x00) would silently no-op on the ~1/256 of runs where the
// pattern byte already equals it — a rare flake these overflow proofs must not
// have.
func corruptCanary(addr uintptr) {
	probeWrite(addr, probeRead(addr)^0xFF)
}

// faults reports whether fn causes a hardware memory fault. SetPanicOnFault
// converts the fault into a recoverable runtime panic for this goroutine.
func faults(fn func()) (faulted bool) {
	old := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(old)
	defer func() {
		if recover() != nil {
			faulted = true
		}
	}()
	fn()
	return false
}

// TestGuardPages_FaultOnBothEdges proves the guards are real: one byte below
// the secret area and one byte past it must both fault, while the first and
// last bytes of the area itself must not.
func TestGuardPages_FaultOnBothEdges(t *testing.T) {
	buf, err := NewEmptyBuffer(100)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if !buf.Capabilities().GuardPages {
		t.Fatal("Capabilities().GuardPages = false on a supported platform")
	}

	inner := buf.region.inner
	base := uintptr(unsafe.Pointer(&inner[0]))
	end := base + uintptr(len(inner))

	if faults(func() { probeRead(base) }) {
		t.Error("first byte of the secret area faulted — mapping is broken")
	}
	if faults(func() { probeRead(end - 1) }) {
		t.Error("last byte of the secret area faulted — mapping is broken")
	}
	if !faults(func() { probeRead(base - 1) }) {
		t.Error("read one byte BELOW the secret area did not fault — leading guard page is not in force")
	}
	if !faults(func() { probeRead(end) }) {
		t.Error("read one byte PAST the secret area did not fault — trailing guard page is not in force")
	}
}

// TestGuardPages_SyscallSafePath proves the no-memfd allocMapAnon path
// produces guarded memory too.
func TestGuardPages_SyscallSafePath(t *testing.T) {
	buf, err := NewSyscallSafeBuffer([]byte("guarded-ingest"))
	if err != nil {
		t.Fatalf("NewSyscallSafeBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	inner := buf.region.inner
	end := uintptr(unsafe.Pointer(&inner[0])) + uintptr(len(inner))
	if !faults(func() { probeRead(end) }) {
		t.Error("allocMapAnon path: trailing guard page is not in force")
	}
}

// TestCanary_CleanLifecycleReportsNothing pins the no-false-positive side:
// a normal create → use → Destroy cycle must not report a violation.
func TestCanary_CleanLifecycleReportsNothing(t *testing.T) {
	t.Parallel()
	buf, err := NewBuffer([]byte("well-behaved-secret"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	if _, err := buf.CopyIn([]byte("still-well-behaved!"), 0); err != nil {
		t.Fatalf("CopyIn: %v", err)
	}
	if err := buf.Destroy(); err != nil {
		t.Fatalf("clean Destroy reported: %v", err)
	}
}

// TestCanary_DetectsOverflowOnDestroy corrupts the slack behind the buffer —
// an overflow that stays inside the mapping, too short to reach the guard —
// and requires Destroy to report ErrCanaryViolation while still destroying.
func TestCanary_DetectsOverflowOnDestroy(t *testing.T) {
	buf, err := NewEmptyBuffer(100) // 100 < page size → slack exists
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}

	// The overflow: one byte immediately past the buffer's usable bytes.
	// cap(data) is the slack boundary; the write lands in canary territory.
	base := uintptr(unsafe.Pointer(&buf.region.inner[0]))
	corruptCanary(base + uintptr(cap(buf.data)))

	err = buf.Destroy()
	if !errors.Is(err, ErrCanaryViolation) {
		t.Fatalf("Destroy after overflow = %v, want ErrCanaryViolation", err)
	}
	if !buf.IsDestroyed() {
		t.Fatal("violation report must not prevent destruction")
	}
	// Idempotent second Destroy stays clean.
	if err := buf.Destroy(); err != nil {
		t.Errorf("second Destroy = %v, want nil", err)
	}
}

// TestCanary_TruncateDoesNotDisturb verifies Truncate's tail wipe (inside the
// data region) never touches the canary slack behind cap(data).
func TestCanary_TruncateDoesNotDisturb(t *testing.T) {
	t.Parallel()
	buf, err := NewBuffer([]byte("truncate-me-down-to-something-small"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	if err := buf.Truncate(4); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy after Truncate reported: %v", err)
	}
}

// TestArena_ReleaseDetectsSlotOverflow overflows one slot into its trailing
// canary strip and requires Release to report it, re-arm the strip, and still
// return the slot to the pool.
func TestArena_ReleaseDetectsSlotOverflow(t *testing.T) {
	a, err := NewArena(32, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	slot, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	// Overflow: write one byte past the slot's usable bytes, into its strip.
	var slotBase uintptr
	if err := slot.WithBytes(func(b []byte) {
		slotBase = uintptr(unsafe.Pointer(&b[0]))
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	corruptCanary(slotBase + 32)

	if err := slot.Release(); !errors.Is(err, ErrCanaryViolation) {
		t.Fatalf("Release after slot overflow = %v, want ErrCanaryViolation", err)
	}

	// The strip was re-armed and the slot returned to the pool: a fresh
	// acquire/release cycle on the same arena must be clean again.
	slot2, err := a.Acquire()
	if err != nil {
		t.Fatalf("re-Acquire: %v", err)
	}
	if err := slot2.Release(); err != nil {
		t.Errorf("clean Release after re-arm = %v, want nil", err)
	}
}

// TestArena_OverflowStaysOutOfNextSlot proves the strip does its actual job:
// a small overflow out of slot 0 corrupts the canary, NOT slot 1's secret.
func TestArena_OverflowStaysOutOfNextSlot(t *testing.T) {
	a, err := NewArena(32, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	s0, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire s0: %v", err)
	}
	s1, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire s1: %v", err)
	}

	want := bytes.Repeat([]byte{0xAB}, 32)
	if err := s1.WithBytes(func(b []byte) { copy(b, want) }); err != nil {
		t.Fatalf("fill s1: %v", err)
	}

	// Overflow slot 0 by 4 bytes — well past its end, well short of slot 1.
	var s0base uintptr
	_ = s0.WithBytes(func(b []byte) { s0base = uintptr(unsafe.Pointer(&b[0])) })
	for i := 0; i < 4; i++ {
		corruptCanary(s0base + 32 + uintptr(i))
	}

	// Slot 1's secret is untouched: the strip absorbed the overflow.
	if err := s1.WithBytes(func(b []byte) {
		if !bytes.Equal(b, want) {
			t.Error("overflow out of slot 0 corrupted slot 1's data — strip layout broken")
		}
	}); err != nil {
		t.Fatalf("read s1: %v", err)
	}

	if err := s0.Release(); !errors.Is(err, ErrCanaryViolation) {
		t.Errorf("Release s0 = %v, want ErrCanaryViolation", err)
	}
	if err := s1.Release(); err != nil {
		t.Errorf("Release s1 = %v, want nil (its strip is intact)", err)
	}
}

// TestArena_DestroyDetectsTailViolation corrupts the slab's page-rounding
// tail and requires Destroy to report it.
func TestArena_DestroyDetectsTailViolation(t *testing.T) {
	a, err := NewArena(32, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}

	// Corrupt the first byte of the tail zone (after the last strip).
	tailOff := a.count * a.stride
	if tailOff >= len(a.region.inner) {
		t.Skip("no tail slack on this configuration")
	}
	base := uintptr(unsafe.Pointer(&a.region.inner[0]))
	corruptCanary(base + uintptr(tailOff))

	if err := a.Destroy(); !errors.Is(err, ErrCanaryViolation) {
		t.Fatalf("Destroy after tail corruption = %v, want ErrCanaryViolation", err)
	}
	if !a.IsDestroyed() {
		t.Fatal("violation report must not prevent destruction")
	}
}

// TestArena_SlotCapClamped verifies the slice handed to WithBytes cannot be
// re-sliced into the canary strip: its capacity equals the slot size.
func TestArena_SlotCapClamped(t *testing.T) {
	t.Parallel()
	a, err := NewArena(32, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	slot, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = slot.Release() }()

	if err := slot.WithBytes(func(b []byte) {
		if cap(b) != 32 {
			t.Errorf("slot slice cap = %d, want 32 (must not reach the canary strip)", cap(b))
		}
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
}

// TestBuffer_DataCapClamped verifies the same for SecureBuffer.
func TestBuffer_DataCapClamped(t *testing.T) {
	t.Parallel()
	buf, err := NewEmptyBuffer(100)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.WithBytes(func(b []byte) {
		if cap(b) != 100 {
			t.Errorf("data cap = %d, want 100 (must not reach the canary slack)", cap(b))
		}
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
}
