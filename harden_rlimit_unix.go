//go:build linux || darwin

// rlimit-based process hardening helpers for Linux and Darwin.

package secmem

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// disableCoreDumps zeroes RLIMIT_CORE, soft and hard. Zeroing the hard limit
// is deliberate: it cannot be raised again without privilege, so a
// compromised process cannot quietly re-enable core dumps.
func disableCoreDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("secmem.DisableCoreDumps: setrlimit(RLIMIT_CORE, 0): %w", err)
	}
	return nil
}

// setMemlockLimit raises RLIMIT_MEMLOCK's soft limit to bytes, raising the
// hard limit too when privilege allows. Returns the soft limit actually in
// force; err is non-nil whenever that is below the request.
func setMemlockLimit(bytes uint64) (uint64, error) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		return 0, fmt.Errorf("secmem.SetMemlockLimit: getrlimit: %w", err)
	}

	// Already sufficient — never LOWER an existing budget.
	if rl.Cur >= bytes {
		return rl.Cur, nil
	}

	// Within the hard limit: raising the soft limit needs no privilege.
	if bytes <= rl.Max {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: bytes, Max: rl.Max}); err != nil {
			return rl.Cur, fmt.Errorf("secmem.SetMemlockLimit: setrlimit(soft=%d): %w", bytes, err)
		}
		return bytes, nil
	}

	// Beyond the hard limit: try raising both (needs CAP_SYS_RESOURCE/root).
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: bytes, Max: bytes}); err == nil {
		return bytes, nil
	}

	// Unprivileged: deliver as much as the hard limit allows and say so.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: rl.Max, Max: rl.Max}); err != nil {
		return rl.Cur, fmt.Errorf("secmem.SetMemlockLimit: setrlimit(soft=hard=%d): %w", rl.Max, err)
	}
	return rl.Max, fmt.Errorf(
		"secmem.SetMemlockLimit: requested %d bytes but the hard limit is %d and raising it needs CAP_SYS_RESOURCE; achieved %d",
		bytes, rl.Max, rl.Max)
}
