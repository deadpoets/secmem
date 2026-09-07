//go:build unix

package secmem

import (
	"bytes"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

// TestInstallTerminationWipe_RearmsWhenReraiseImpossible drives the survive
// path with real signal delivery: SIGUSR1 raised at this process, with the
// re-raise stubbed to fail the way os.Process.Signal fails on Windows, so the
// NoExit installer wipes, cannot re-raise, and leaves the process running.
//
// The handler used to be one-shot: after that first signal its goroutine had
// returned and its channel was gone, although uninstall was never called, so a
// second signal wiped nothing and a secret created after the first wipe was
// left intact. The rearmed hook is what makes sending the second signal
// deterministic — between the handler's Stop and its Notify the default
// disposition is live, and a signal landing there is a different event.
//
// SIGUSR1 is used because the runtime ignores it when no channel wants it, so a
// second signal can never take the test binary down, fixed or not: on the old
// code it simply does nothing, which is exactly the defect.
func TestInstallTerminationWipe_RearmsWhenReraiseImpossible(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}

	rearmed := make(chan struct{}, 4)
	cannotReraise := errors.New("re-raise refused (as on Windows)")
	uninstall := installTerminationWipeHooks(false,
		func(os.Signal) error { return cannotReraise },
		func(int) { t.Error("exit called under NoExit") },
		func() { rearmed <- struct{}{} },
		syscall.SIGUSR1)
	defer uninstall()

	secret := bytes.Repeat([]byte{0x5A}, 32)
	first, err := NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = first.Destroy() }()

	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("raise SIGUSR1: %v", err)
	}
	if wiped, err := waitWiped(first, 3*time.Second); err != nil {
		t.Fatalf("access during wipe returned %v", err)
	} else if !wiped {
		t.Fatal("first signal did not wipe")
	}

	// Created AFTER the first wipe: the only thing a second wipe can catch.
	second, err := NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = second.Destroy() }()

	select {
	case <-rearmed:
	case <-time.After(3 * time.Second):
		// Not fatal: send the second signal anyway so the failure shows the
		// consequence, not just the mechanism.
		t.Error("handler did not register again after the first signal")
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("raise SIGUSR1: %v", err)
	}
	if wiped, err := waitWiped(second, 3*time.Second); err != nil {
		t.Fatalf("access during wipe returned %v", err)
	} else if !wiped {
		t.Fatal("secret created after the first wipe survived the second signal")
	}
}
