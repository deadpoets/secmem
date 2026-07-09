package secmem

import "context"

// HardenLevel is a bitmask describing which hardening mitigations were applied.
type HardenLevel int

const (
	// HardenNone means no hardening was applied (non-Linux or unavailable).
	HardenNone HardenLevel = 0

	// HardenNoDump indicates PR_SET_DUMPABLE=0 was set — core dumps disabled.
	HardenNoDump HardenLevel = 1 << iota

	// HardenNoNewPriv indicates PR_SET_NO_NEW_PRIVS=1 was set — no privilege escalation.
	HardenNoNewPriv

	// HardenSeccomp indicates a seccomp BPF filter was loaded (reserved for post-MVP).
	HardenSeccomp
)

// HardenProcess applies process-level hardening mitigations.
// Returns the bitmask of mitigations that were successfully applied.
//
// Call this early in main() before any secret loading or privilege acquisition.
// On non-Linux platforms this is a no-op returning (HardenNone, nil).
//
// ctx is reserved for future cancellation; currently unused but required by convention.
func HardenProcess(_ context.Context) (HardenLevel, error) {
	return hardenProcess()
}
