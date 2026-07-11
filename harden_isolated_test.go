//go:build linux

// Out-of-process tests for the IRREVERSIBLE process-hardening helpers.
// DisableCoreDumps zeroes RLIMIT_CORE's hard limit and HardenProcess sets
// PR_SET_DUMPABLE=0 — both would poison the rest of the parallel suite if run
// in-process. Each runs in a re-exec'd child that asserts and exits.

package secmem

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// TestHelpersIsolated re-execs this test binary once per isolated case. The
// child runs the case body (selected by an env var) and exits 0 on success.
func TestHelpersIsolated(t *testing.T) {
	cases := []string{"disable_core_dumps", "harden_dumpable"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if os.Getenv("SECMEM_ISOLATED_CASE") == name {
				return // handled by TestMain-style dispatch below
			}
			cmd := exec.Command(os.Args[0], "-test.run", "TestHelpersIsolated/"+name, "-test.v")
			cmd.Env = append(os.Environ(), "SECMEM_ISOLATED_CASE="+name)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("isolated child %q failed: %v\n%s", name, err, out)
			}
		})
	}
}

// The child dispatch runs before the normal test machinery via an init-time
// check: if the env var is set, execute exactly that case and exit.
//
//nolint:gochecknoinits // deterministic single-case child dispatch for isolation.
func init() {
	switch os.Getenv("SECMEM_ISOLATED_CASE") {
	case "disable_core_dumps":
		if err := DisableCoreDumps(); err != nil {
			os.Stderr.WriteString("DisableCoreDumps: " + err.Error() + "\n")
			os.Exit(1)
		}
		var rl unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil {
			os.Exit(1)
		}
		if rl.Cur != 0 || rl.Max != 0 {
			os.Stderr.WriteString("RLIMIT_CORE not zeroed\n")
			os.Exit(1)
		}
		os.Exit(0)
	case "harden_dumpable":
		if _, err := hardenProcess(); err != nil {
			os.Stderr.WriteString("hardenProcess: " + err.Error() + "\n")
			os.Exit(1)
		}
		d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil || d != 0 {
			os.Stderr.WriteString("PR_GET_DUMPABLE not 0\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
}
