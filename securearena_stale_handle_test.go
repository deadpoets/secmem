package secmem

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// TestArenaSlot_StaleHandleRefusedUnderLock pins where the borrow path checks
// a handle's generation: under the region lock, immediately before the slice
// is produced — not before the lock is taken.
//
// The check used to run first, lock-free, and the lock was taken afterwards.
// A borrower that passed the check and then waited for the lock (a queued
// writer — ReadOnly, ReadWrite, the emergency wipe — parks every new reader)
// resumed with a slice into a slot that, meanwhile, had been Released, wiped,
// re-Acquired and written by a new owner. It read, or overwrote, the next
// tenant's secret, and reported no error.
//
// The interleaving is forced with rLockSlowTestHook, which holds the borrower
// still at the one point that matters: enrolled as a reader, not yet past the
// liveness check. While it is parked there the slot is released and handed to
// a new owner, who writes a distinguishable secret. The stale borrower must
// then be refused with ErrSlotReleased and its callback must never run.
func TestArenaSlot_StaleHandleRefusedUnderLock(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	arena, err := NewArena(32, 2)
	if err != nil {
		t.Skipf("NewArena: %v", err)
	}
	defer func() { _ = arena.Destroy() }()

	parked, err := arena.Acquire() // slot 0: keeps a reader on the lock
	if err != nil {
		t.Fatalf("Acquire(parked): %v", err)
	}
	defer func() { _ = parked.Release() }()
	subject, err := arena.Acquire() // slot 1: the handle that goes stale
	if err != nil {
		t.Fatalf("Acquire(subject): %v", err)
	}
	first := bytes.Repeat([]byte{0x11}, 32)
	if err := subject.WithBytes(func(b []byte) { copy(b, first) }); err != nil {
		t.Fatalf("subject.WithBytes: %v", err)
	}

	// 1. A reader parked in a callback holds the region lock shared.
	inCallback := make(chan struct{})
	releaseCallback := make(chan struct{})
	callbackDone := make(chan struct{})
	go func() {
		defer close(callbackDone)
		_ = parked.WithBytes(func([]byte) {
			close(inCallback)
			<-releaseCallback
		})
	}()
	<-inCallback

	// 2. A writer queues behind it, so the next reader takes the slow path.
	writerDone := make(chan error, 1)
	go func() { writerDone <- arena.ReadWrite() }()
	waitForWritersWaiting(t, arena.mu, 1)

	// 3. The borrower: it will pass whatever check precedes the lock, enter
	//    the slow path, and — once the writer has come and gone — enroll and
	//    park in the hook with the lock held.
	borrowerEnrolled := make(chan struct{})
	resumeBorrower := make(chan struct{})
	var hooked bool
	rLockSlowTestHook = func() {
		if hooked {
			return
		}
		hooked = true
		close(borrowerEnrolled)
		<-resumeBorrower
	}
	defer func() { rLockSlowTestHook = nil }()

	borrowErr := make(chan error, 1)
	ran := make(chan []byte, 1)
	go func() {
		borrowErr <- subject.WithBytesErr(func(b []byte) error {
			ran <- append([]byte(nil), b...) //nolint:secmem-lint // test copies its own fixture out to assert on it after the borrow
			return nil
		})
	}()

	// Only once the borrower is parked in the slow path: released earlier,
	// the writer could come and go first and the borrower would take the
	// fast path, never reaching the hook.
	waitForReadersWaiting(t, arena.mu, 1)

	// Let the writer through; the borrower then enrolls and parks.
	close(releaseCallback)
	<-callbackDone
	if err := <-writerDone; err != nil {
		t.Fatalf("ReadWrite: %v", err)
	}
	<-borrowerEnrolled

	// 4. With the borrower holding the lock but not yet past its check, the
	//    slot is released and handed to a new owner, who writes a new secret.
	if err := subject.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	next, err := arena.Acquire()
	if err != nil {
		t.Fatalf("Acquire(next): %v", err)
	}
	defer func() { _ = next.Release() }()
	if next.Index() != subject.Index() {
		t.Fatalf("free list handed out slot %d, want the just-released %d", next.Index(), subject.Index())
	}
	second := bytes.Repeat([]byte{0x22}, 32)
	if err := next.WithBytes(func(b []byte) { copy(b, second) }); err != nil {
		t.Fatalf("next.WithBytes: %v", err)
	}

	// 5. Resume the stale borrower. It must be refused.
	close(resumeBorrower)
	err = <-borrowErr
	select {
	case got := <-ran:
		t.Fatalf("stale handle's callback ran and saw %x — a borrow that waited for the lock "+
			"was handed the next tenant's slot (WithBytesErr returned %v)", got[:4], err)
	default:
	}
	if !errors.Is(err, ErrSlotReleased) {
		t.Fatalf("stale borrow returned %v, want ErrSlotReleased", err)
	}

	// The new owner's secret is intact.
	if err := next.WithBytes(func(b []byte) {
		if !bytes.Equal(b, second) {
			t.Errorf("next tenant's slot = %x…, want %x…", b[:4], second[:4])
		}
	}); err != nil {
		t.Fatalf("next.WithBytes: %v", err)
	}
}

// waitForReadersWaiting blocks until at least want readers are parked in l's
// slow path, or fails the test after five seconds.
func waitForReadersWaiting(t *testing.T, l *bufferRWLock, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		l.mu.Lock()
		n := l.readersWaiting
		l.mu.Unlock()
		if n >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d parked readers (got %d)", want, n)
		}
		time.Sleep(time.Millisecond)
	}
}
