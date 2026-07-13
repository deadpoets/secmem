//go:build !linux && !darwin && !windows

// rlimit helper stubs for platforms on the insecure heap fallback: there is
// no locked memory to budget and no rlimit interface worth pretending to.

package secmem

import (
	"errors"
	"fmt"
)

func disableCoreDumps() error {
	return fmt.Errorf("secmem.DisableCoreDumps: not available on this platform: %w", errors.ErrUnsupported)
}

func ensureMemlockLimit(_ uint64) (uint64, error) {
	return 0, fmt.Errorf("secmem.EnsureMemlockLimit: no locked memory on this platform (heap fallback): %w", errors.ErrUnsupported)
}
