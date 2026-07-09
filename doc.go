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
// unprotected heap storage. Use Probe at startup to see exactly which
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
//   - Kernel isolation. On Linux amd64 (kernel 5.14+) pages are backed by
//     memfd_secret, which hides them from /proc/<pid>/mem, ptrace, and other
//     readers of process memory. Elsewhere this is unavailable and the mapping
//     falls through to locked anonymous memory.
//
//   - Excluded from core dumps. Where the OS allows it (MADV_DONTDUMP, and an
//     opt-in process-wide dumpable=0), the pages are kept out of core dumps.
//     This is best-effort and its failure is reported, not fatal.
//
//   - Guaranteed wipe. On destroy the pages are overwritten by an
//     architecture-specific assembly routine that the compiler cannot elide.
//
//   - Overflow trap. Each mapping is bracketed by inaccessible guard pages and
//     its slack is canary-filled, so an adjacent over- or under-flow traps or is
//     caught on destroy. This is a memory-safety bug-catcher, not a
//     confidentiality control: it does nothing against a privileged reader of
//     process memory.
//
//   - Emergency wipe. Live buffers are registered so that a fatal signal wipes
//     them before the process exits.
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
//	    if _, err := buf.Write(rawBytes, 0); err != nil {
//	        return fmt.Errorf("write: %w", err)
//	    }
//	    return doSomethingWith(buf)
//	})
//
// # RLIMIT_MEMLOCK budget
//
// Each SecureBuffer locks at least one page (4 KiB on amd64). The default
// RLIMIT_MEMLOCK on many Linux systems is 64 KiB, which allows only about six to
// ten concurrent buffers before allocation fails. A process that holds one
// buffer per live secret should raise the limit once, before its first
// allocation — either through the OS:
//
//	# /etc/security/limits.d/secmem.conf
//	someuser soft memlock 262144
//	someuser hard memlock 262144
//
// or programmatically with SetMemlockLimit at startup. Raising the soft limit up
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
