//go:build !linux

// Async-preemption suppression is Linux-only. This file is the honest stub for
// everywhere else.
//
// Windows cannot support it at all: its preemption does not deliver a signal, it
// calls SuspendThread and rewrites the thread context with SetThreadContext
// (runtime/os_windows.go preemptM). There is no userspace mask for that.
//
// Darwin could in principle — it has pthread_sigmask — but golang.org/x/sys/unix
// exposes no binding for it, and reaching past that to a raw syscall on a
// platform with no coverage in this project's verification matrix would be
// asserting a security property nobody has executed. It stays unsupported, and
// Capabilities says so, which is the whole point of Capabilities.

package secmem

// preemptWindow is empty here; it exists so the callers in scrub_legacy.go and
// scrub_runtimesecret.go compile unchanged across platforms. The Linux version
// carries a saved signal mask — see scrub_window_unix.go for why that state is
// a value the caller stacks rather than a closure it heap-allocates.
type preemptWindow struct{}

// suppressAsyncPreempt is a no-op reporting false: Scrub still runs, still
// pre-grows the stack, and still burns its frame — it just cannot also close
// the asynchronous register-dump window.
func suppressAsyncPreempt(*preemptWindow) bool { return false }

// restore is a no-op: nothing was suppressed.
func (*preemptWindow) restore() {}

// asyncPreemptSuppressionSupported reports that this platform cannot suppress
// the register-dumping preemption signal.
const asyncPreemptSuppressionSupported = false
