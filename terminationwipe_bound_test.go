package secmem

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// TestWipeAllSecretsBounded_GivesUpOnAStuckBorrow is the portable half of the
// handler's bound: the wait ends at the timeout while a callback is parked,
// the unborrowed buffer is already wiped by then, and the abandoned wipe still
// takes the borrowed one once its callback returns.
func TestWipeAllSecretsBounded_GivesUpOnAStuckBorrow(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	secret := bytes.Repeat([]byte{0x5A}, 32)
	stuck, err := NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		t.Skipf("NewBuffer(stuck): %v", err)
	}
	defer func() { _ = stuck.Destroy() }()
	idle, err := NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		t.Skipf("NewBuffer(idle): %v", err)
	}
	defer func() { _ = idle.Destroy() }()

	entered := make(chan struct{})
	release := make(chan struct{})
	borrowDone := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }); <-borrowDone }
	defer free()
	go func() {
		defer close(borrowDone)
		_ = stuck.WithBytes(func([]byte) {
			close(entered)
			<-release
		})
	}()
	<-entered

	returned := make(chan bool, 1)
	go func() { returned <- wipeAllSecretsBounded(200 * time.Millisecond) }()
	select {
	case completed := <-returned:
		if completed {
			t.Fatal("reported a complete wipe while a buffer was still borrowed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the bounded wipe is still waiting on a borrowed buffer long after its timeout")
	}

	requireWiped(t, "idle.WithBytes", idle.WithBytes(func([]byte) {}))

	free()
	if wiped, err := waitWiped(stuck, 3*time.Second); err != nil {
		t.Fatalf("stuck buffer: %v", err)
	} else if !wiped {
		t.Error("the borrowed buffer was never wiped after its callback returned")
	}

	// With nothing borrowed the wipe completes inside the bound.
	if !wipeAllSecretsBounded(5 * time.Second) {
		t.Error("an unobstructed wipe did not complete inside its bound")
	}
}
