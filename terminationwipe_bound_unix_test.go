//go:build unix

package secmem

import (
	"bytes"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestInstallTerminationWipe_StuckBorrowDoesNotHoldTheHandler drives the
// handler with a real signal while one buffer sits inside a borrowing callback
// that does not return.
//
// The handler used to call WipeAllSecrets synchronously, and that call waits
// for every borrow. One parked callback therefore kept the handler from ever
// reaching the re-raise, while its Notify registration went on suppressing the
// default disposition: every other secret was zeroed, the process ran on, and
// each later signal was swallowed. The wait is now bounded, so the re-raise
// has to arrive while the borrow is still held.
//
// SIGUSR1 for the reason the rearm test gives: with no channel registered the
// runtime ignores it, so nothing here can take the test binary down.
func TestInstallTerminationWipe_StuckBorrowDoesNotHoldTheHandler(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	old := terminationWipeTimeout
	terminationWipeTimeout = 200 * time.Millisecond
	defer func() { terminationWipeTimeout = old }()

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

	// Park a borrow. Released on every exit path, and before the deferred
	// Destroy calls above, which would otherwise wait on it forever.
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

	reraised := make(chan os.Signal, 1)
	uninstall := installTerminationWipeHooks(true,
		func(sig os.Signal) error { reraised <- sig; return nil },
		func(int) { t.Error("exit called although the re-raise succeeded") },
		nil,
		syscall.SIGUSR1)
	defer uninstall()

	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("raise SIGUSR1: %v", err)
	}

	select {
	case <-reraised:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler is still waiting on a borrowed buffer: it never re-raised, " +
			"so the process would neither terminate nor see a later signal")
	}

	// The bound gives up on the borrowed buffer only. Everything else was
	// wiped before the handler started waiting.
	if wiped, err := waitWiped(idle, 3*time.Second); err != nil {
		t.Fatalf("idle buffer: %v", err)
	} else if !wiped {
		t.Error("the unborrowed buffer was not wiped before the handler moved on")
	}

	// The abandoned wipe is still queued on the borrowed buffer and takes it
	// the moment the callback returns.
	free()
	if wiped, err := waitWiped(stuck, 3*time.Second); err != nil {
		t.Fatalf("stuck buffer: %v", err)
	} else if !wiped {
		t.Error("the borrowed buffer was never wiped after its callback returned")
	}
}
