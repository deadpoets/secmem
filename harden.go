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

	// HardenSeccomp indicates a seccomp BPF filter was loaded (reserved; not yet implemented).
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

// EnsureMemlockLimit raises the locked-memory budget to at least bytes,
// returning the value actually achieved.
//
// Each SecureBuffer locks a page-rounded minimum (typically 4 KiB), so the
// ceiling is RLIMIT_MEMLOCK/pagesize buffers exactly. Current systemd-based
// distributions default that limit to 8 MiB — 2048 buffers with 4 KiB pages,
// measured on both Ubuntu 26.04/amd64 and Armbian/arm64 — while the older raw
// kernel default of 64 KiB allowed only about a dozen. Do not design against
// either number: read the runtime limit. A server holding one buffer per live
// secret can hit whichever ceiling applies; call EnsureMemlockLimit once at
// startup, before the first allocation.
//
// # It disarms an implicit guard
//
// A bounded RLIMIT_MEMLOCK is also, incidentally, the thing that stops an
// oversized [NewArena] from killing the process. NewArena requests its locked
// slab before its Go-heap slot index precisely because the slab fails by
// returning an error while a refused heap allocation is runtime.throw — so a
// small locked budget turns an implausible count into a clean error. Raising
// the budget raises that ceiling with it, and raising it to unlimited removes
// it. If you call this and then size arenas (or buffers) from something outside
// your control — a config file, a peer's request — bound the count yourself.
//
// Honesty notes: raising the soft limit up to the hard limit needs no
// privilege; raising the hard limit needs CAP_SYS_RESOURCE (or root). When
// the request cannot be met the function raises the soft limit as far as the
// hard limit allows and returns that value together with a non-nil error —
// it never silently under-delivers. On Windows the equivalent budget is the
// process minimum working-set size, adjusted via SetProcessWorkingSetSizeEx.
func EnsureMemlockLimit(bytes uint64) (achieved uint64, err error) {
	return ensureMemlockLimit(bytes)
}
