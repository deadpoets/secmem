package secmem

import (
	"bytes"
	"testing"
)

// TestWipeAllSecrets wipes every registered secret in place: the contents are
// gone, a subsequent access does not fault (the region stays mapped) and reads
// back as zeros.
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

	sawNonZero := false
	if err := buf.WithBytes(func(b []byte) {
		for _, x := range b {
			if x != 0 {
				sawNonZero = true
			}
		}
	}); err != nil {
		t.Fatalf("access after WipeAllSecrets returned %v (must read the wiped-but-mapped region)", err)
	}
	if sawNonZero {
		t.Fatal("secret survived WipeAllSecrets")
	}
}

// TestInstallTerminationWipe_UninstallClean verifies install then uninstall is
// a clean no-op path (no signal delivered), and that uninstall is idempotent.
func TestInstallTerminationWipe_UninstallClean(t *testing.T) {
	uninstall := InstallTerminationWipe()
	uninstall()
	uninstall() // idempotent — must not panic
}
