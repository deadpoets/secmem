package secmem

import "testing"

// TestArena_IsDestroyedWaitsForTheWipe pins what IsDestroyed answers while
// Destroy is still waiting on a borrow. Destroy raises its fail-fast flag
// before it takes the lock, so that new borrows stop queueing; IsDestroyed
// used to return that flag, and so said "destroyed" while a callback was still
// reading plaintext from a slab that had not been wiped. SecureBuffer's
// IsDestroyed never did.
func TestArena_IsDestroyedWaitsForTheWipe(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	a, err := NewArena(32, 2)
	if err != nil {
		t.Skipf("NewArena: %v", err)
	}
	slot, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	entered, release, borrowDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(borrowDone)
		_ = slot.WithBytes(func([]byte) { close(entered); <-release })
	}()
	<-entered

	destroyDone := make(chan error, 1)
	go func() { destroyDone <- a.Destroy() }()
	waitForWritersWaiting(t, a.mu, 1) // Destroy has announced itself and is queued

	if a.IsDestroyed() {
		t.Error("IsDestroyed() = true while a borrow still holds the unwiped slab")
	}
	// The fail-fast half is unchanged: nothing new gets in.
	if _, err := a.Acquire(); err == nil {
		t.Error("Acquire succeeded on an arena whose Destroy is in progress")
	}

	close(release)
	<-borrowDone
	if err := <-destroyDone; err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if !a.IsDestroyed() {
		t.Error("IsDestroyed() = false after Destroy returned")
	}
}
