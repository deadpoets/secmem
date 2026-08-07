package secmem

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// TestWipeAllSecrets_UnborrowedBuffersWipeWhileOneIsBorrowed covers the
// two-pass emergency wipe. A buffer parked inside a borrowing callback cannot
// be wiped until the callback returns — but it must not hold every OTHER
// secret in the process hostage while it sits there. The unborrowed buffer has
// to be zeroed before the borrow releases, which a single blocking pass over
// the registry could not guarantee (it depends on map iteration order).
func TestWipeAllSecrets_UnborrowedBuffersWipeWhileOneIsBorrowed(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	secret := bytes.Repeat([]byte{0x5A}, 40)

	borrowed, err := NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		t.Fatalf("NewBuffer(borrowed): %v", err)
	}
	defer func() { _ = borrowed.Destroy() }()

	idle, err := NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		t.Fatalf("NewBuffer(idle): %v", err)
	}
	defer func() { _ = idle.Destroy() }()

	inCallback := make(chan struct{})
	releaseCallback := make(chan struct{})
	borrowDone := make(chan struct{})
	go func() {
		defer close(borrowDone)
		_ = borrowed.WithBytes(func([]byte) {
			close(inCallback)
			<-releaseCallback
		})
	}()
	<-inCallback

	wipeDone := make(chan error, 1)
	go func() { wipeDone <- WipeAllSecrets() }()

	// The idle buffer must go to zero while the borrow is still held. Poll:
	// the wipe is concurrent, so this is "eventually", bounded by a deadline
	// that a regression (one blocking pass, borrow-first) would blow through
	// because the borrow only releases after this loop succeeds.
	deadline := time.Now().Add(5 * time.Second)
	for {
		zeroed := true
		if err := idle.WithBytes(func(b []byte) {
			for _, x := range b {
				if x != 0 {
					zeroed = false
				}
			}
		}); err != nil {
			t.Fatalf("idle.WithBytes: %v", err)
		}
		if zeroed {
			break
		}
		if time.Now().After(deadline) {
			close(releaseCallback)
			<-borrowDone
			t.Fatal("idle buffer still holds its secret while another buffer is borrowed — " +
				"the emergency wipe is blocked behind an unrelated borrow")
		}
		time.Sleep(time.Millisecond)
	}

	// Now let the borrow go; the blocking second pass must finish it off.
	close(releaseCallback)
	<-borrowDone
	if err := <-wipeDone; err != nil {
		t.Fatalf("WipeAllSecrets: %v", err)
	}
	if err := borrowed.WithBytes(func(b []byte) {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Error("previously-borrowed buffer survived the emergency wipe")
		}
	}); err != nil {
		t.Fatalf("borrowed.WithBytes after wipe: %v", err)
	}
}

// TestWipeAllSecrets_DestroyReclaimsMapping covers the deferred unmap. The
// emergency wipe deliberately leaves regions mapped so a late access reads
// zeros instead of faulting — but once the owner calls Destroy it has stated
// nothing is using the buffer, so the address space must be reclaimed rather
// than leaked until process exit.
func TestWipeAllSecrets_DestroyReclaimsMapping(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	buf, err := NewBuffer(bytes.Repeat([]byte{0x5A}, 40))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	key := buf.janitorKey

	if err := WipeAllSecrets(); err != nil {
		t.Fatalf("WipeAllSecrets: %v", err)
	}

	// Still mapped, and retained for reclamation.
	emergencyJanitor.mu.Lock()
	_, retained := emergencyJanitor.wiped[key]
	emergencyJanitor.mu.Unlock()
	if !retained {
		t.Fatal("wiped-in-place region was not retained for later reclamation")
	}
	if err := buf.WithBytes(func([]byte) {}); err != nil {
		t.Fatalf("access after emergency wipe = %v, want nil (region must stay mapped)", err)
	}

	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy after emergency wipe: %v", err)
	}
	emergencyJanitor.mu.Lock()
	_, stillRetained := emergencyJanitor.wiped[key]
	emergencyJanitor.mu.Unlock()
	if stillRetained {
		t.Error("Destroy did not reclaim the wiped-but-mapped region — the mapping leaks until exit")
	}
	if !buf.IsDestroyed() {
		t.Error("IsDestroyed() = false after Destroy")
	}
	if err := buf.Destroy(); err != nil {
		t.Errorf("second Destroy = %v, want nil (idempotent)", err)
	}
}

// TestTryLock_FailsWhileHeld pins the non-blocking acquire the two-pass wipe
// depends on: it must refuse while a reader holds the lock, refuse while a
// writer holds it, and succeed on a free lock.
func TestTryLock_FailsWhileHeld(t *testing.T) {
	l := newBufferRWLock()

	if !l.tryLock() {
		t.Fatal("tryLock on a free lock = false, want true")
	}
	if l.tryLock() {
		t.Error("tryLock while a writer holds the lock = true, want false")
	}
	l.unlock()

	l.rLock()
	if l.tryLock() {
		t.Error("tryLock while a reader holds the lock = true, want false")
	}
	l.rUnlock()

	if !l.tryLock() {
		t.Error("tryLock after all holders released = false, want true")
	}
	l.unlock()
}

// TestWipeAllSecrets_ConcurrentDestroyStillReclaimsMapping pins the ordering
// inside the blocking wipe pass. That pass must not remove a region from the
// registry before it holds the region's lock: a Destroy already queued on that
// same lock would reach janitor.release with the key in NEITHER map, report
// success, and never unmap — and the retainWiped landing afterwards would
// strand the mapping in the wiped set, which nothing collects. The result is a
// permanently leaked (and still mlock'd) mapping, from the very API pair
// WipeAllSecrets documents as safe to use concurrently.
//
// The interleaving is forced rather than raced: a parked reader keeps both
// operations queued on the lock, and Destroy is queued FIRST so it wins the
// wakeup and reaches release() while the wipe pass is mid-flight.
func TestWipeAllSecrets_ConcurrentDestroyStillReclaimsMapping(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	buf, err := NewBuffer(bytes.Repeat([]byte{0x5A}, 4096))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	key := buf.janitorKey

	// Park a reader so the non-blocking first pass cannot take this region and
	// has to defer it to the blocking pass.
	inCallback := make(chan struct{})
	releaseCallback := make(chan struct{})
	borrowDone := make(chan struct{})
	go func() {
		defer close(borrowDone)
		_ = buf.WithBytes(func([]byte) {
			close(inCallback)
			<-releaseCallback
		})
	}()
	<-inCallback

	// Queue Destroy on the exclusive lock first, so it is ahead of the wipe.
	destroyDone := make(chan error, 1)
	go func() { destroyDone <- buf.Destroy() }()
	waitForWritersWaiting(t, buf.mu, 1)

	// Now the emergency wipe: its blocking pass queues behind Destroy.
	wipeDone := make(chan error, 1)
	go func() { wipeDone <- WipeAllSecrets() }()
	waitForWritersWaiting(t, buf.mu, 2)

	close(releaseCallback)
	<-borrowDone
	if err := <-destroyDone; err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if err := <-wipeDone; err != nil {
		t.Fatalf("WipeAllSecrets: %v", err)
	}

	if !buf.IsDestroyed() {
		t.Fatal("IsDestroyed() = false after Destroy")
	}
	emergencyJanitor.mu.Lock()
	_, stranded := emergencyJanitor.wiped[key]
	_, stillLive := emergencyJanitor.regions[key]
	emergencyJanitor.mu.Unlock()
	if stranded {
		t.Errorf("region %#x left in janitor.wiped after an explicit Destroy — "+
			"the mapping is never unmapped and the janitor holds it until process exit", key)
	}
	if stillLive {
		t.Errorf("region %#x left in janitor.regions after an explicit Destroy", key)
	}
}

// waitForWritersWaiting blocks until at least want writers are queued on l,
// so a test can pin the ORDER two operations enter the lock rather than race
// them and hope.
func waitForWritersWaiting(t *testing.T, l *bufferRWLock, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		l.mu.Lock()
		n := l.writersWaiting
		l.mu.Unlock()
		if n >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d queued writers (got %d)", want, n)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestWipeAllSecrets_MarksOwnerDead pins the deadness contract. The emergency
// path wipes in place and deliberately leaves the region MAPPED so a late read
// gets zeros instead of a fault — but that same decision used to leave the
// buffer fully writable, so a process still running (a panic-recovery handler
// is a documented call site) could put a FRESH secret into a region the wipe
// had already reported as handled. Reads must keep working; every mutation must
// now refuse.
func TestWipeAllSecrets_MarksOwnerDead(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	buf, err := NewBuffer(bytes.Repeat([]byte{0x5A}, 40))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := WipeAllSecrets(); err != nil {
		t.Fatalf("WipeAllSecrets: %v", err)
	}

	// Reads still work and see zeros — the documented no-fault guarantee.
	if err := buf.WithBytes(func(b []byte) {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("read after emergency wipe returned non-zero bytes: %x", b)
		}
	}); err != nil {
		t.Errorf("WithBytes after emergency wipe = %v, want nil (reads must not fault or fail)", err)
	}

	// Every mutation refuses, and does so as both ErrWiped and ErrDestroyed so
	// existing errors.Is(err, ErrDestroyed) callers keep working.
	mutations := map[string]error{
		"CopyIn":    errOf(func() error { _, e := buf.CopyIn([]byte{1}, 0); return e }),
		"SetByteAt": buf.SetByteAt(0, 1),
		"Truncate":  buf.Truncate(1),
		"ReadFrom":  errOf(func() error { _, e := buf.ReadFrom(bytes.NewReader([]byte{1})); return e }),
		"Seal":      buf.Seal(),
		"Unseal":    buf.Unseal(),
		"ReadOnly":  buf.ReadOnly(),
		"ReadWrite": buf.ReadWrite(),
	}
	for name, err := range mutations {
		if !errors.Is(err, ErrWiped) {
			t.Errorf("%s after emergency wipe = %v, want ErrWiped", name, err)
		}
		if !errors.Is(err, ErrDestroyed) {
			t.Errorf("%s error does not satisfy errors.Is(err, ErrDestroyed): %v", name, err)
		}
	}
}

// TestWipeAllSecrets_ArenaRefusesAcquire is the arena half: Acquire would hand
// out a slot to write a new secret into, so it refuses once the slab is wiped.
func TestWipeAllSecrets_ArenaRefusesAcquire(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	a, err := NewArena(32, 4)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	if err := WipeAllSecrets(); err != nil {
		t.Fatalf("WipeAllSecrets: %v", err)
	}
	if _, err := a.Acquire(); !errors.Is(err, ErrWiped) {
		t.Errorf("Acquire after emergency wipe = %v, want ErrWiped", err)
	}
}

// TestWipeAllSecrets_RewipesSlotWrittenThroughLiveHandle covers the one path
// deadness does NOT close, which is why the emergency sweep still visits the
// already-wiped set.
//
// ArenaSlot.WithBytes hands out a single slice used for both reading and
// writing; there is no way to permit the read and refuse the write, and reads
// must keep working. So a caller holding a slot acquired BEFORE the wipe can
// still write through it afterwards. Acquire refuses, which stops new slots,
// but this handle is already out. The second wipe has to catch it — and it only
// can because wipeAllInPlace sweeps janitor.wiped as well as janitor.regions.
func TestWipeAllSecrets_RewipesSlotWrittenThroughLiveHandle(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	a, err := NewArena(32, 4)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	slot, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := WipeAllSecrets(); err != nil {
		t.Fatalf("first WipeAllSecrets: %v", err)
	}

	// The handle predates the wipe, so it still writes.
	if err := slot.WithBytes(func(b []byte) { copy(b, bytes.Repeat([]byte{0xC3}, len(b))) }); err != nil {
		t.Fatalf("WithBytes through a pre-wipe handle: %v", err)
	}
	if err := WipeAllSecrets(); err != nil {
		t.Fatalf("second WipeAllSecrets: %v", err)
	}
	if err := slot.WithBytes(func(b []byte) {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("bytes written through a live handle after the first wipe survived the second: %x", b)
		}
	}); err != nil {
		t.Fatalf("WithBytes after the second wipe: %v", err)
	}
}

// TestWipeAllSecrets_ClearsSealCipherFlag pins the seal-cipher bookkeeping. The
// flag is shared with the owning SecureBuffer and means "these bytes are
// CryptProtectMemory ciphertext". The wipe replaces them with zeros, so leaving
// it set would make Destroy's pre-decrypt step run CryptUnprotectMemory over
// wiped memory. (Unseal is now refused outright, but Destroy still consults the
// flag, so clearing it remains load-bearing.)
//
// The flag is only ever set on Windows — sealEncrypt is a no-op elsewhere — but
// the postcondition holds on every platform.
func TestWipeAllSecrets_ClearsSealCipherFlag(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	buf, err := NewBuffer(bytes.Repeat([]byte{0x5A}, 40))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	if err := buf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := WipeAllSecrets(); err != nil {
		t.Fatalf("WipeAllSecrets: %v", err)
	}
	if buf.sealCipher.Load() {
		t.Error("sealCipher still set after the wipe replaced the ciphertext with zeros")
	}
	if err := buf.Destroy(); err != nil {
		t.Errorf("Destroy after an emergency-wiped seal cycle: %v", err)
	}
}

// errOf adapts a (T, error) call to the error alone, so the mutation table above
// reads uniformly.
func errOf(fn func() error) error { return fn() }
