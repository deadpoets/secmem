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

// suppressAsyncPreempt is a no-op reporting ok=false: Scrub still runs, still
// pre-grows the stack, and still burns its frame — it just cannot also close
// the asynchronous register-dump window.
func suppressAsyncPreempt() (restore func(), ok bool) {
	return func() {}, false
}

// asyncPreemptSuppressionSupported reports that this platform cannot suppress
// the register-dumping preemption signal.
const asyncPreemptSuppressionSupported = false
