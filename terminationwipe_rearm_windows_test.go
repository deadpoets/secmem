//go:build windows

package secmem

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestInstallTerminationWipeNoExit_RearmsAfterCtrlBreak delivers two genuine
// console events to a child in its own process group. Windows is where the
// NoExit installer has an effect at all — the re-raise is impossible, so the
// process survives its signal — and so where the handler used to be one-shot:
// the second event landed on the default disposition and terminated the child
// with STATUS_CONTROL_C_EXIT, the secret created after the first wipe intact.
//
// Ctrl-Break rather than Ctrl-C: CREATE_NEW_PROCESS_GROUP disables Ctrl-C for
// the new group, and GenerateConsoleCtrlEvent cannot target a group with it
// anyway. The runtime maps both to os.Interrupt, so the handler cannot tell.
// The event goes to every process in the group that shares this console, which
// is the child alone.
//
// The child is this binary re-exec'd. Unlike the sibling harnesses it does its
// work from the test function, NOT from init: the console delivers a control
// event by injecting a thread, and the runtime parks a callback arriving on a
// thread it did not create until package initialization has finished
// (cgocallbackg1 waits on main_init_done). A child that never leaves init is
// deaf to every console event — measured, not inferred.
//
// The child observes the handler's re-arm through the hook and prints a line
// the parent waits for before sending the second event; without that the
// second event could land in the handler's own Stop-to-Notify window, which is
// a different case.
func TestInstallTerminationWipeNoExit_RearmsAfterCtrlBreak(t *testing.T) {
	if os.Getenv("SECMEM_TERMWIPE_CHILD") == "1" {
		os.Exit(terminationWipeRearmChild())
	}
	if !platformHasSecureMemory {
		t.Skip("no secure memory on this platform")
	}

	cmd := exec.Command(os.Args[0], "-test.run", "^TestInstallTerminationWipeNoExit_RearmsAfterCtrlBreak$")
	cmd.Env = append(os.Environ(), "SECMEM_TERMWIPE_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}

	lines := make(chan string, 16)
	var transcript bytes.Buffer
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			transcript.WriteString(sc.Text() + "\n")
			lines <- sc.Text()
		}
	}()
	// Reads from the pipe must finish before Wait; drain then wait, and take
	// the child down first if it is stuck.
	finish := func() error {
		timer := time.NewTimer(15 * time.Second)
		defer timer.Stop()
		for {
			select {
			case _, ok := <-lines:
				if !ok {
					return cmd.Wait()
				}
			case <-timer.C:
				_ = cmd.Process.Kill()
				for range lines {
				}
				return cmd.Wait()
			}
		}
	}
	fail := func(format string, args ...any) {
		t.Helper()
		err := finish()
		t.Fatalf(format+"\nchild: %v\nstdout:\n%sstderr:\n%s", append(args, err, transcript.String(), stderr.String())...)
	}
	nextLine := func() (string, bool) {
		select {
		case l, ok := <-lines:
			return l, ok
		case <-time.After(15 * time.Second):
			return "", false
		}
	}

	if l, ok := nextLine(); !ok || l != "READY" {
		fail("child did not report READY (got %q)", l)
	}
	ctrlBreak := func() error {
		return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(cmd.Process.Pid))
	}
	if err := ctrlBreak(); err != nil {
		// No console attached to this test process (a service, a detached
		// runner): the event cannot be generated at all. Environment, not a
		// failure.
		_ = cmd.Process.Kill()
		_ = finish()
		t.Skipf("GenerateConsoleCtrlEvent: %v (no console attached)", err)
	}

	switch l, ok := nextLine(); {
	case !ok:
		fail("child did not report the first wipe")
	case l == "NOREARM":
		// Keep going: the second event shows the consequence.
		t.Error("handler did not register again after the first Ctrl-Break")
	case l != "REARMED":
		fail("unexpected line %q after the first Ctrl-Break", l)
	}
	if err := ctrlBreak(); err != nil {
		fail("second GenerateConsoleCtrlEvent: %v", err)
	}
	if err := finish(); err != nil {
		var ee *exec.ExitError
		status := ""
		if errors.As(err, &ee) && uint32(ee.ExitCode()) == 0xC000013A {
			status = " (STATUS_CONTROL_C_EXIT: the second Ctrl-Break terminated it on the default disposition, no wipe)"
		}
		t.Fatalf("child: %v%s\nstdout:\n%sstderr:\n%s", err, status, transcript.String(), stderr.String())
	}
}

// terminationWipeRearmChild is the child side: install NoExit with the default
// signals, hold a secret, and report on stdout as each event lands. Exit codes
// are distinct so a failure names its step even if the output is lost.
func terminationWipeRearmChild() int {
	fail := func(code int, msg string) int {
		os.Stderr.WriteString("child: " + msg + "\n")
		return code
	}
	say := func(line string) { os.Stdout.WriteString(line + "\n") }

	rearmed := make(chan struct{}, 4)
	uninstall := installTerminationWipeHooks(false, reraiseSignal, os.Exit, func() { rearmed <- struct{}{} })
	defer uninstall()

	secret := bytes.Repeat([]byte{0x5A}, 32)
	first, err := NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		return fail(2, "NewBuffer: "+err.Error())
	}
	defer func() { _ = first.Destroy() }()
	say("READY")

	if wiped, err := waitWiped(first, 10*time.Second); err != nil {
		return fail(3, "access during wipe: "+err.Error())
	} else if !wiped {
		return fail(4, "first Ctrl-Break did not wipe within 10s")
	}

	// Created AFTER the first wipe: the only thing a second wipe can catch.
	second, err := NewBuffer(append([]byte(nil), secret...))
	if err != nil {
		return fail(2, "NewBuffer: "+err.Error())
	}
	defer func() { _ = second.Destroy() }()

	select {
	case <-rearmed:
		say("REARMED")
	case <-time.After(3 * time.Second):
		say("NOREARM")
	}

	if wiped, err := waitWiped(second, 10*time.Second); err != nil {
		return fail(3, "access during wipe: "+err.Error())
	} else if !wiped {
		return fail(6, "secret created after the first wipe survived the second Ctrl-Break")
	}
	say("WIPED2")
	return 0
}
