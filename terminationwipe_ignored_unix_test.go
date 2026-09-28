//go:build unix

package secmem

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// inheritedIgnoreChildEnv marks the re-executed test binary as the child of
// TestInstallTerminationWipe_InheritedIgnoredSignalStillExits.
const inheritedIgnoreChildEnv = "SECMEM_TEST_INHERITED_IGNORE_CHILD"

// TestInstallTerminationWipe_InheritedIgnoredSignalStillExits is the live
// proof for the inherited-ignore case, with a real signal against a real
// process. The child is this test binary, re-executed through `sh -c 'trap ""
// INT; exec ...'` so that it INHERITS SIGINT as ignored — the disposition every
// `cmd &` in a non-interactive shell script gives its child. It creates a
// buffer, installs the default termination wipe, and waits.
//
// Measured before the fix: the child reported SIGINT ignored at start, the
// wipe ran on the signal (the buffer read as zeros), the re-raise "succeeded"
// — kill(2) accepts a signal the kernel then discards — and the child ran on
// for as long as it liked, reads returning zeros and mutations ErrWiped,
// exiting normally with status 0. That is the state WipeAllSecrets does not
// support and that the installer's documentation said only Windows could
// reach.
//
// With the fix the installer records the inherited ignore before Notify and
// exits the process itself, with the same status it uses on Windows for the
// same reason. The child's own output carries the two facts the assertion
// rests on: that SIGINT really was inherited as ignored (or the test would be
// proving nothing), and that the handler was installed before the parent
// signalled (or the signal would be discarded before Notify ever saw it).
func TestInstallTerminationWipe_InheritedIgnoredSignalStillExits(t *testing.T) {
	if os.Getenv(inheritedIgnoreChildEnv) == "1" {
		inheritedIgnoreChild()
		return
	}
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("no sh to set the inherited disposition with: %v", err)
	}

	// exec "$0" keeps the child's argv[0] and pid identity simple; the trap
	// with an empty action sets SIGINT to SIG_IGN, which exec preserves.
	cmd := exec.Command(sh, "-c",
		`trap "" INT; exec "$0" -test.run='^TestInstallTerminationWipe_InheritedIgnoredSignalStillExits$' -test.count=1 -test.v`,
		os.Args[0])
	cmd.Env = append(os.Environ(), inheritedIgnoreChildEnv+"=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}

	// Read the child's lines until it says the handler is installed, keeping
	// everything for the report.
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	var seen []string
	installed, ignored := false, false
	deadline := time.After(20 * time.Second)
wait:
	for !installed {
		select {
		case l, ok := <-lines:
			if !ok {
				break wait
			}
			seen = append(seen, l)
			switch {
			case strings.HasPrefix(l, "child: ready ignored="):
				ignored = strings.HasSuffix(l, "true")
			case l == "child: installed":
				installed = true
			}
		case <-deadline:
			_ = cmd.Process.Kill()
			t.Fatalf("child never reported the handler installed; output so far:\n%s", strings.Join(seen, "\n"))
		}
	}
	if !installed {
		_ = cmd.Wait()
		t.Fatalf("child exited before installing the handler; output:\n%s", strings.Join(seen, "\n"))
	}
	if !ignored {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("test setup: the child did not inherit SIGINT as ignored, so the case under test was not produced; output:\n%s", strings.Join(seen, "\n"))
	}

	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("signal child: %v", err)
	}

	// Drain the rest of the output and wait for the exit, bounded: a child
	// that survives (the defect) prints SURVIVED after four seconds and exits
	// 0, which is a distinct failure from a hang.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("child neither exited nor reported survival; output:\n%s", strings.Join(seen, "\n"))
	}
	for l := range lines {
		seen = append(seen, l)
	}
	out := strings.Join(seen, "\n")

	for _, l := range seen {
		if l == "child: SURVIVED" {
			t.Fatalf("child survived its own termination signal with every secret wiped (exit %v); output:\n%s", waitErr, out)
		}
	}
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		t.Fatalf("child exited 0 after a termination signal (wait error %v); output:\n%s", waitErr, out)
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		// Killed by the signal itself would mean the ignore was not inherited
		// after all (the default disposition terminated it) — the setup check
		// above should have caught that.
		t.Fatalf("child was killed by signal %v rather than exiting on its own; output:\n%s", ws.Signal(), out)
	}
	if got := exitErr.ExitCode(); got != forcedExitStatus {
		t.Fatalf("child exit status = %d, want %d (forcedExitStatus); output:\n%s", got, forcedExitStatus, out)
	}
}

// inheritedIgnoreChild is the child's body. It exits through the installer on
// the signal; reaching the end means the installer failed to terminate it.
func inheritedIgnoreChild() {
	buf, err := NewBuffer([]byte("live-secret-material"))
	if err != nil {
		fmt.Println("child: NewBuffer:", err)
		os.Exit(3)
	}
	// Before InstallTerminationWipe: Notify overrides the inherited ignore,
	// and signal.Ignored stops reporting it from then on.
	fmt.Printf("child: ready ignored=%v\n", signal.Ignored(syscall.SIGINT))
	uninstall := InstallTerminationWipe()
	defer uninstall()
	fmt.Println("child: installed")
	_ = os.Stdout.Sync()

	time.Sleep(4 * time.Second)
	wiped := true
	_ = buf.WithBytes(func(b []byte) {
		for _, x := range b {
			if x != 0 {
				wiped = false
			}
		}
	})
	fmt.Printf("child: still running after the signal window, secret wiped=%v\n", wiped)
	fmt.Println("child: SURVIVED")
	os.Exit(0)
}
