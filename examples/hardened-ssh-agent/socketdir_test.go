//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The default socket directory must not be a name anyone can predict or
// that a previous run can have left behind: a directory named after the pid
// made the agent fail to start when it came up under the same pid twice (a
// container's pid 1, say), and let another user of a shared temp dir create
// the next pids' names first.
func TestNewSocketDir_PrivateAndNeverTheSameNameTwice(t *testing.T) {
	base := t.TempDir()

	first, err := newSocketDir(base)
	if err != nil {
		t.Fatalf("newSocketDir: %v", err)
	}
	// The same process asking again is what a restart under the same pid
	// looks like when the first directory is still there.
	second, err := newSocketDir(base)
	if err != nil {
		t.Fatalf("second newSocketDir under the same pid: %v", err)
	}
	if first == second {
		t.Fatalf("both calls returned %s", first)
	}
	for _, dir := range []string{first, second} {
		if filepath.Dir(dir) != base {
			t.Errorf("%s is not directly under %s", dir, base)
		}
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Errorf("%s has mode %v, want a 0700 directory", dir, info.Mode())
		}
	}
}
