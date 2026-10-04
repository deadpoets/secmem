//go:build linux

package secmem

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// no_new_privs is an attribute of a thread, inherited by the threads and
// processes that thread creates. A Go program is many threads before main
// runs, and a child process is forked from whichever one the calling
// goroutine happens to be on, so setting the attribute on one thread leaves
// os/exec able to start a setuid binary from another. These tests read the
// attribute of EVERY thread, which is the only form in which the claim
// "the process cannot gain privileges" can be checked.

const hardenThreadsChildEnv = "SECMEM_TEST_HARDEN_THREADS_CHILD"

// allThreadsSyscallAvailable reports whether the runtime can run a system call
// on every thread. It cannot in a binary that links cgo (which a -race build
// does), and there HardenProcess must not claim HardenNoNewPriv.
func allThreadsSyscallAvailable() bool {
	_, _, errno := syscall.AllThreadsSyscall(syscall.SYS_GETPID, 0, 0, 0)
	return errno != syscall.ENOTSUP
}

// threadsWithoutNoNewPrivs returns the ids of this process's threads whose
// NoNewPrivs attribute is not 1, and how many threads it looked at.
func threadsWithoutNoNewPrivs() (missing []string, total int, err error) {
	tasks, err := filepath.Glob("/proc/self/task/*/status")
	if err != nil {
		return nil, 0, err
	}
	for _, p := range tasks {
		status, err := os.ReadFile(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
				continue // the thread exited between the listing and the read
			}
			return nil, 0, err
		}
		total++
		if !bytes.Contains(status, []byte("\nNoNewPrivs:\t1\n")) {
			missing = append(missing, filepath.Base(filepath.Dir(p)))
		}
	}
	return missing, total, nil
}

// TestHardenProcess_NoNewPrivsOnEveryThread runs HardenProcess in a child
// that has first been made to hold several OS threads, then checks each one,
// along with the level it returns and the dumpable flag. A child, because the
// call is irreversible: see harden_test.go.
func TestHardenProcess_NoNewPrivsOnEveryThread(t *testing.T) {
	if os.Getenv(hardenThreadsChildEnv) == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHardenProcess_NoNewPrivsOnEveryThread$", "-test.v")
		cmd.Env = append(os.Environ(), hardenThreadsChildEnv+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
		t.Logf("child:\n%s", out)
		return
	}

	// Hold extra threads for the whole test: each goroutine is wired to its
	// own thread and parks there, so the threads exist before the prctl and
	// cannot be the one that issues it.
	const extra = 4
	started := make(chan struct{}, extra)
	release := make(chan struct{})
	defer close(release)
	for i := 0; i < extra; i++ {
		go func() {
			runtime.LockOSThread()
			started <- struct{}{}
			<-release
		}()
	}
	for i := 0; i < extra; i++ {
		<-started
	}

	level, err := HardenProcess(context.Background())
	if err != nil {
		t.Fatalf("HardenProcess: %v", err)
	}
	if level&HardenNoDump == 0 {
		t.Error("HardenNoDump not reported")
	}
	if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || d != 0 {
		t.Errorf("PR_GET_DUMPABLE = %d, %v; want 0 (not dumpable)", d, err)
	}
	missing, total, err := threadsWithoutNoNewPrivs()
	if err != nil {
		t.Fatalf("reading /proc/self/task: %v", err)
	}
	if total <= extra {
		t.Fatalf("saw %d threads, expected more than the %d held open", total, extra)
	}

	if !allThreadsSyscallAvailable() {
		// A cgo binary. The attribute cannot be set process-wide, so the
		// level must not say it was.
		if level&HardenNoNewPriv != 0 {
			t.Errorf("HardenNoNewPriv reported in a cgo binary, where %d of %d threads do not have it", len(missing), total)
		}
		fmt.Printf("cgo binary: no_new_privs is per-thread here and HardenNoNewPriv is not reported (%d of %d threads lack it)\n", len(missing), total)
		return
	}
	if level&HardenNoNewPriv == 0 {
		t.Error("HardenNoNewPriv not reported although every thread can be reached")
	}
	if len(missing) > 0 {
		t.Errorf("HardenProcess reported HardenNoNewPriv, but %d of %d threads do not have no_new_privs: %v", len(missing), total, missing)
	}
}
