package secmem

import (
	"bytes"
	"syscall"
	"testing"
)

// TestWipeAllSecrets wipes every registered secret in place: the contents are
// gone, the region stays mapped and holds zeros, and a subsequent borrow is
// refused with ErrWiped rather than handed those zeros.
func TestWipeAllSecrets(t *testing.T) {
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	secret := bytes.Repeat([]byte{0x5A}, 40)
	buf, err := NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := WipeAllSecrets(); err != nil {
		t.Fatalf("WipeAllSecrets: %v", err)
	}

	if !bufRegionIsZero(t, buf) {
		t.Fatal("secret survived WipeAllSecrets")
	}
	requireWiped(t, "WithBytes", buf.WithBytes(func([]byte) {}))
}

// TestInstallTerminationWipe_UninstallClean verifies install then uninstall is
// a clean no-op path (no signal delivered), and that uninstall is idempotent.
func TestInstallTerminationWipe_UninstallClean(t *testing.T) {
	uninstall := InstallTerminationWipe()
	uninstall()
	uninstall() // idempotent — must not panic
}

// oddSignal is an os.Signal that is not a syscall.Signal and whose dynamic
// type is not comparable. os/signal.Notify skips such a value silently; the
// installer's inherited-ignore record must skip it too rather than panic on
// the map insert.
type oddSignal struct{ tags []string }

func (oddSignal) String() string { return "odd" }
func (oddSignal) Signal()        {}

// TestInstallTerminationWipe_ToleratesNonSyscallSignal pins that a caller's
// own os.Signal implementation is accepted, as it was before the
// inherited-ignore record existed.
func TestInstallTerminationWipe_ToleratesNonSyscallSignal(t *testing.T) {
	uninstall := InstallTerminationWipeNoExit(oddSignal{tags: []string{"x"}}, syscall.SIGTERM)
	uninstall()
}
