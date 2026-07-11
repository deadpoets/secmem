package secmem

import "context"

// HardenLevel is a bitmask describing which hardening mitigations were applied.
type HardenLevel int

const (
	// HardenNone means no hardening was applied (unsupported platform or unavailable).
	HardenNone HardenLevel = 0

	// HardenNoDump indicates PR_SET_DUMPABLE=0 was set — core dumps disabled.
	HardenNoDump HardenLevel = 1 << iota

	// HardenNoNewPriv indicates PR_SET_NO_NEW_PRIVS=1 was set — no privilege escalation.
	HardenNoNewPriv

	// HardenSeccomp indicates a seccomp BPF filter was loaded (reserved for post-MVP).
	HardenSeccomp

	// HardenStrictHandles indicates Windows strict handle checking is in
	// force: use of a stale or invalid handle raises an exception instead of
	// silently succeeding against whatever object now owns the handle value.
	HardenStrictHandles

	// HardenNoDynamicCode indicates Windows Arbitrary Code Guard is in force:
	// the process can no longer create executable memory or make writable
	// memory executable. Pure-Go binaries never need either; JIT-based cgo
	// dependencies would break, which is why HardenProcess is opt-in.
	HardenNoDynamicCode
)

// HardenProcess applies process-level hardening mitigations.
// Returns the bitmask of mitigations that were successfully applied.
//
// Call this early in main() before any secret loading or privilege
// acquisition. Applied per platform:
//
//   - Linux: PR_SET_DUMPABLE=0 (no core dumps, no ptrace attach by
//     non-privileged peers) and PR_SET_NO_NEW_PRIVS=1.
//   - Windows: strict handle checks and Arbitrary Code Guard via
//     SetProcessMitigationPolicy. Both are IRREVERSIBLE for the process
//     lifetime — that is their value. ACG is incompatible with anything that
//     generates code at runtime (pure Go never does; a JIT inside a cgo
//     dependency would).
//   - Elsewhere: no-op returning (HardenNone, nil).
//
// ctx is reserved for future cancellation; currently unused but required by convention.
func HardenProcess(_ context.Context) (HardenLevel, error) {
	return hardenProcess()
}

// DisableCoreDumps sets the process core-dump size limit to zero
// (setrlimit(RLIMIT_CORE, 0), soft AND hard) on Linux and Darwin.
//
// It is the blunt backstop to the surgical per-mapping protections
// (MADV_DONTDUMP, memfd_secret): those cover only secmem's own mappings and
// can silently not apply; RLIMIT_CORE=0 stops the entire process from
// dumping. Setting the hard limit is deliberate and IRREVERSIBLE without
// privilege — a compromised process cannot quietly re-enable dumps.
//
// Never called implicitly: changing a process rlimit is the application's
// decision, not the library's. On Windows there is no core-dump rlimit and
// this returns errors.ErrUnsupported — the per-allocation WER dump exclusion
// is applied automatically by the allocator instead.
func DisableCoreDumps() error {
	return disableCoreDumps()
}

// SetMemlockLimit raises the locked-memory budget to at least bytes,
// returning the value actually achieved.
//
// Each SecureBuffer locks a page-rounded minimum (typically 4 KiB), and the
// default RLIMIT_MEMLOCK on Linux is 64 KiB — roughly a dozen buffers before
// NewBuffer starts returning mlock errors. A server holding one buffer per
// live secret WILL hit this; call SetMemlockLimit once at startup, before the
// first allocation.
//
// Honesty notes: raising the soft limit up to the hard limit needs no
// privilege; raising the hard limit needs CAP_SYS_RESOURCE (or root). When
// the request cannot be met the function raises the soft limit as far as the
// hard limit allows and returns that value together with a non-nil error —
// it never silently under-delivers. On Windows the equivalent budget is the
// process minimum working-set size, adjusted via SetProcessWorkingSetSizeEx.
func SetMemlockLimit(bytes uint64) (achieved uint64, err error) {
	return setMemlockLimit(bytes)
}
