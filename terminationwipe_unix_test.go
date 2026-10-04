//go:build unix

package secmem

import (
	"bytes"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// TestInstallTerminationWipe_Cooperative proves the installer does NOT clobber a
// coexisting handler and does NOT force the process to exit. It uses SIGUSR1
// (whose default disposition is terminate) with the test's own handler also
// registered: on the signal the installer must wipe, the test's handler must
// still receive it (additive Notify — no clobber), and the process must survive
// (the test keeps running) because the test's own registration keeps the signal
// caught rather than falling through to the default terminate.
func TestInstallTerminationWipe_Cooperative(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}

	// The test's own handler for SIGUSR1 — must keep receiving after install.
	mine := make(chan os.Signal, 2)
	signal.Notify(mine, syscall.SIGUSR1)
	defer signal.Stop(mine)

	secret := bytes.Repeat([]byte{0x5A}, 32)
	buf, err := NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	uninstall := InstallTerminationWipe(syscall.SIGUSR1)
	defer uninstall()

	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("raise SIGUSR1: %v", err)
	}

	// The coexisting handler must receive it — proves additive delivery.
	select {
	case <-mine:
	case <-time.After(3 * time.Second):
		t.Fatal("coexisting SIGUSR1 handler did not fire — the installer clobbered it")
	}

	// The installer wipes on its own goroutine; poll for the wipe.
	wiped, err := waitWiped(buf, 3*time.Second)
	if err != nil {
		t.Fatalf("access during wipe returned %v", err)
	}
	if !wiped {
		t.Fatal("secret was not wiped by the termination handler")
	}
	if !bufRegionIsZero(t, buf) {
		t.Fatal("buffer reports ErrWiped but its region is not zero")
	}
	// Reaching here means the process did NOT terminate: cooperative success.
}
