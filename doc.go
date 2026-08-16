// Package secmem hardens secrets in memory.
//
// secmem keeps sensitive bytes — private keys, tokens, passwords — off the Go
// garbage-collected heap, in OS-locked pages that are excluded from swap and,
// where the platform allows, from core dumps and from other processes. The
// bytes are wiped on release by an architecture-specific routine and are reached
// only through a borrowing closure, so the plaintext never outlives its use.
//
// The core module is pure Go — CGO is not required — and depends only on
// golang.org/x/sys.
//
// # Honesty first
//
// Every guarantee secmem makes is stated per platform, together with what it
// does not protect against. A security library that overstates its guarantees
// is worse than none. A protection that cannot be provided on a given platform
// is reported through Capabilities rather than silently skipped, and a platform
// with no lockable off-heap memory fails loudly rather than degrading to
// unprotected heap storage.
//
// secmem has NOT had an independent third-party security audit. Every guarantee
// documented here is self-verified by the test suite that runs in CI, and
// self-verification is not an audit — TESTING.md records what is measured and,
// separately, the properties that are deliberately not proven. See SECURITY.md.
//
// Use Probe at startup to see exactly which
// protections are in force for your build, and inspect a buffer's own
// Capabilities to see how that allocation was actually backed.
//
// # Protection model
//
// The mechanisms below are best-effort and vary by platform. What each one
// achieves on a given OS and architecture — and what it does not — is set out
// in the per-platform capability matrix; the summary here is the intent.
//
//   - Off the Go heap. Secret bytes live in mmap'd pages (VirtualAlloc on
//     Windows), outside the region the garbage collector scans, moves, or copies.
//
//   - No swap. Pages are locked with mlock (VirtualLock on Windows) so they are
//     not written to the swap device.
//
//   - Kernel isolation. On 64-bit Linux (amd64/arm64, kernel 5.14+ with
//     CONFIG_SECRETMEM) pages are backed by memfd_secret, which hides them from
//     /proc/<pid>/mem, ptrace, and other readers of process memory. Elsewhere
//     this is unavailable and the mapping falls through to locked anonymous
//     memory.
//
//   - Excluded from core dumps. Where the OS allows it (MADV_DONTDUMP, and an
//     opt-in process-wide dumpable=0), the pages are kept out of core dumps.
//     This is best-effort and its failure is reported, not fatal.
//
//   - Guaranteed wipe. On destroy the pages are overwritten by an
//     architecture-specific assembly routine that the compiler cannot elide.
//
//   - Scrub windows. A SecureBuffer governs where a secret lives, not the copies
//     a computation makes of it on the stack. Scrub burns the stack band its
//     callback's call tree used, via architecture assembly (amd64, arm64), and
//     on Linux additionally blocks Go's preemption signal for the duration so
//     runtime.asyncPreempt cannot spill the entire register file onto that stack
//     partway through. Under GOEXPERIMENT=runtimesecret on linux/amd64 and
//     linux/arm64, runtime/secret supersedes the frame wipe and erases the
//     registers, stack, and heap of the whole call tree. The residue no tier
//     reaches — and which parts of it are constraints of the Go runtime or the
//     OS rather than gaps — is enumerated in THREAT-MODEL.md.
//
//   - Overflow trap. Each mapping is bracketed by inaccessible guard pages and
//     its slack is canary-filled, so an adjacent over- or under-flow traps or is
//     caught on destroy. This is a memory-safety bug-catcher, not a
//     confidentiality control: it does nothing against a privileged reader of
//     process memory.
//
//   - Emergency wipe (opt-in). Live buffers are registered so a single
//     WipeAllSecrets call zeroes every one at once. secmem installs no signal
//     handler itself: call WipeAllSecrets from your own shutdown or panic
//     handler, or opt into InstallTerminationWipe to wipe on termination
//     signals. Wiping a buffer waits for any in-flight borrowing callback to
//     return — zeroing memory a callback is reading would be a data race — so
//     a callback that never returns blocks the call. Buffers that are NOT
//     being borrowed are all wiped before that wait begins; see WipeAllSecrets.
//
// # Lifecycle
//
// Create a buffer, defer its destruction immediately, and touch the plaintext
// only inside a borrowing closure:
//
//	buf, err := secmem.NewBuffer(rawBytes)
//	if err != nil {
//	    return fmt.Errorf("create secure buffer: %w", err)
//	}
//	defer buf.Destroy() // always defer immediately after creation
//
//	err = buf.WithBytesErr(func(borrowed []byte) error {
//	    // borrowed is valid ONLY inside this closure; never store it,
//	    // send it to a goroutine, or copy it into an escaping slice.
//	    return doSomethingWith(borrowed)
//	})
//
// Scope and ScopeWith bind a buffer's lifetime to a function, wiping it on
// return:
//
//	err = secmem.Scope(len(rawBytes), func(buf *secmem.SecureBuffer) error {
//	    if _, err := buf.CopyIn(rawBytes, 0); err != nil {
//	        return fmt.Errorf("write: %w", err)
//	    }
//	    return doSomethingWith(buf)
//	})
//
// # RLIMIT_MEMLOCK budget
//
// Each SecureBuffer locks at least one page, so the number of concurrent
// buffers a process can hold is RLIMIT_MEMLOCK divided by the page size — no
// other term. Read the limit rather than assuming one: `ulimit -l` reports it
// in KiB, and it varies by two orders of magnitude across ordinary systems.
// Measured on three Linux boxes, all with 4 KiB pages: two stock installs
// (Ubuntu 26.04/amd64 and Armbian/arm64) had the systemd default of 8 MiB,
// giving exactly 2048 buffers; a Jetson with a raised limit of 943 MiB gave
// proportionally more. The historical 64 KiB kernel default, which allowed only
// about a dozen buffers, is not what current systemd-based distributions set.
//
// A process that holds one buffer per live secret should raise the limit once,
// before its first allocation — either through the OS:
//
//	# /etc/security/limits.d/secmem.conf
//	someuser soft memlock 262144
//	someuser hard memlock 262144
//
// or programmatically with EnsureMemlockLimit at startup. Raising the soft limit up
// to the hard limit needs no privilege; raising the hard limit needs
// CAP_SYS_RESOURCE. Over-budget allocations return an error — they never panic.
//
// # Reachability
//
// Secret bytes are outside the Go heap, so the garbage collector never scans,
// moves, or copies them. As a last resort, a buffer whose Destroy was forgotten
// is wiped when it becomes unreachable, and a warning is logged to flag the
// oversight; correct code always defers Destroy rather than relying on this.
package secmem
