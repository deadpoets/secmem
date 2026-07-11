//go:build windows

package secmem

import (
	"os"
	"os/exec"
	"testing"
)

// TestWERExclusion_Reported verifies the WER dump exclusion is registered on
// a real allocation and surfaces through Capabilities.NoDump. This is the
// fix for the previously-false claim that Windows offers no dump exclusion.
func TestWERExclusion_Reported(t *testing.T) {
	t.Parallel()
	buf, err := NewEmptyBuffer(64)
	if err != nil {
		t.Fatalf("NewEmptyBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if !buf.Capabilities().NoDump {
		t.Error("Capabilities().NoDump = false on Windows — WerRegisterExcludedMemoryBlock did not take effect")
	}
}

// TestHardenProcess_Windows runs HardenProcess in a re-exec'd child: it
// applies Arbitrary Code Guard, which is IRREVERSIBLE for the process
// lifetime and must not be imposed on the rest of the suite.
func TestHardenProcess_Windows(t *testing.T) {
	if os.Getenv("SECMEM_HARDEN_CHILD") == "1" {
		return // child work happens in init()
	}
	cmd := exec.Command(os.Args[0], "-test.run", "TestHardenProcess_Windows", "-test.v")
	cmd.Env = append(os.Environ(), "SECMEM_HARDEN_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("HardenProcess child failed: %v\n%s", err, out)
	}
}

//nolint:gochecknoinits // deterministic child dispatch for the irreversible ACG test.
func init() {
	if os.Getenv("SECMEM_HARDEN_CHILD") != "1" {
		return
	}
	level, err := hardenProcess()
	if err != nil {
		os.Stderr.WriteString("hardenProcess: " + err.Error() + "\n")
		os.Exit(1)
	}
	if level&HardenStrictHandles == 0 || level&HardenNoDynamicCode == 0 {
		os.Stderr.WriteString("expected StrictHandles|NoDynamicCode bits\n")
		os.Exit(1)
	}
	os.Exit(0)
}
