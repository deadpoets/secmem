package secmem

import (
	"bytes"
	"testing"
)

// TestArenaSlot_StaleReleaseDoesNotWipeNextTenant: two Releases of one handle
// used to both pass the lock-free liveness check, and the loser, parked on
// the region lock behind a queued writer, wiped the slot when it resumed —
// by then re-acquired and holding the next owner's secret. Release's wipe is
// now preceded by a claim on the handle, taken under the region lock.
//
// The interleaving is forced, not raced for: a parked borrow plus a queued
// writer push the first Release onto the reader slow path, where
// rLockSlowTestHook holds it (lock already granted) while a second Release
// completes and the slot is handed to a new owner.
func TestArenaSlot_StaleReleaseDoesNotWipeNextTenant(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	arena, err := NewArena(32, 2)
	if err != nil {
		t.Skipf("NewArena: %v", err)
	}
	defer func() { _ = arena.Destroy() }()
	parked, err := arena.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	subject, err := arena.Acquire()
	if err != nil {
		t.Fatal(err)
	}

	inCb, relCb, cbDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(cbDone)
		_ = parked.WithBytes(func([]byte) { close(inCb); <-relCb })
	}()
	<-inCb
	writerDone := make(chan error, 1)
	go func() { writerDone <- arena.ReadWrite() }()
	waitForWritersWaiting(t, arena.mu, 1)

	enrolled, resume := make(chan struct{}), make(chan struct{})
	hooked := false
	rLockSlowTestHook = func() {
		if hooked {
			return
		}
		hooked = true
		close(enrolled)
		<-resume
	}
	defer func() { rLockSlowTestHook = nil }()

	first := make(chan error, 1)
	go func() { first <- subject.Release() }()
	waitForReadersWaiting(t, arena.mu, 1)
	close(relCb)
	<-cbDone
	if err := <-writerDone; err != nil {
		t.Fatalf("ReadWrite: %v", err)
	}
	<-enrolled // the first Release holds the region lock and has not yet claimed

	if err := subject.Release(); err != nil {
		t.Fatalf("second Release: %v", err)
	}
	next, err := arena.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if next.Index() != subject.Index() {
		t.Fatalf("the free list did not hand back slot %d (got %d); the test no longer forces the reuse", subject.Index(), next.Index())
	}
	want := bytes.Repeat([]byte{0x22}, 32)
	if err := next.WithBytes(func(b []byte) { copy(b, want) }); err != nil {
		t.Fatal(err)
	}

	close(resume)
	if err := <-first; err != nil {
		t.Fatalf("stale Release: %v", err)
	}
	if err := next.WithBytes(func(b []byte) {
		if !bytes.Equal(b, want) {
			t.Errorf("a stale Release wiped the next owner's slot: % x", b[:8]) //nolint:secmem-lint // diagnostic on failure only; the contents are a test fixture, not a secret
		}
	}); err != nil {
		t.Fatal(err)
	}
	if !next.IsLive() || arena.LiveCount() != 2 {
		t.Errorf("after the stale Release: next.IsLive=%v LiveCount=%d, want true and 2", next.IsLive(), arena.LiveCount())
	}
}
