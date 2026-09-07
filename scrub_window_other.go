//go:build !linux

// Async-preemption suppression is Linux-only. This file is the honest stub for
// everywhere else — honest, and no longer empty: the window still pins the
// goroutine to its OS thread, because the vector-register clear that ends every
// window (vecclear_amd64.go, vecclear_arm64.go) must run on the thread that
// holds the residue, and an unpinned goroutine can be rescheduled onto another
// thread between fn's return and the clear.
//
// Windows cannot support the suppression at all: its preemption does not
// deliver a signal, it calls SuspendThread and rewrites the thread context with
// SetThreadContext (runtime/os_windows.go preemptM). There is no userspace mask
// for that. So on Windows a preemption landing inside the window still copies
// the register file into runtime buffers before the clear runs; the clear
// removes what is in the registers themselves, not that copy.
//
// Darwin could in principle — it has pthread_sigmask — but golang.org/x/sys/unix
// exposes no binding for it, and reaching past that to a raw syscall on a
// platform with no coverage in this project's verification matrix would be
// asserting a security property nobody has executed. It stays unsupported, and
// Capabilities says so, which is the whole point of Capabilities.

package secmem

import "runtime"

// preemptWindow records whether the window pinned the goroutine, so restore
// unpins exactly once and a restore on a never-opened window is a no-op rather
// than an unbalanced UnlockOSThread. The Linux version additionally carries a
// saved signal mask — see scrub_window_unix.go for why that state is a value
// the caller stacks rather than a closure it heap-allocates; the same holds
// here.
type preemptWindow struct {
	locked bool
}

// suppressAsyncPreempt pins the goroutine to its OS thread and reports false:
// nothing is suppressed on this platform. Scrub still runs, still pre-grows the
// stack, still burns its frame, and still clears the vector registers — on the
// thread fn ran on, which is what the pin is for.
//
// The pin makes the documented contract real here too: a fn that unbalances
// runtime.LockOSThread unpins the goroutine mid-window, and the clear may then
// run on a thread that never held the residue. Nothing leaks permanently on
// this platform (there is no per-thread mask to strand) and no check trips,
// but code that honours the contract on Windows keeps working when it is built
// for Linux, where the same misuse is a process-lifetime leak.
func suppressAsyncPreempt(w *preemptWindow) bool {
	runtime.LockOSThread()
	w.locked = true
	return false
}

// restore unpins the goroutine. Idempotent, and a no-op on a window that was
// never opened.
func (w *preemptWindow) restore() {
	if !w.locked {
		return
	}
	w.locked = false
	runtime.UnlockOSThread()
}

// asyncPreemptSuppressionSupported reports that this platform cannot suppress
// the register-dumping preemption signal. The window still pins its thread
// (see suppressAsyncPreempt); that is a prerequisite of the vector clear, not a
// suppression, and is not what this constant reports.
const asyncPreemptSuppressionSupported = false
