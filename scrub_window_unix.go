//go:build linux

// scrub_window_unix.go suppresses ASYNCHRONOUS preemption for the duration of a
// Scrub window.
//
// # The residue this closes
//
// Go's non-cooperative preemption is signal-delivered: the runtime sends SIGURG
// to the thread, and the handler runs runtime.asyncPreempt, which — per the
// runtime's own comment — "saves all user registers" onto the goroutine stack
// before calling into the scheduler. That is the entire register file, general
// purpose and vector, spilled at an arbitrary instruction boundary. Land one of
// those in the middle of a cipher round or a scalar multiply and a copy of live
// key material is written to the stack at an offset nothing chose and nothing
// tracks.
//
// Blocking SIGURG on this thread for the window means the handler cannot run, so
// that spill cannot happen. The signal stays pending and is delivered when the
// mask is restored, by which point the window has burned its frame.
//
// # Why this is safe, and the one shape that is not
//
// suspendG (runtime/preempt.go) does NOT rely on the signal alone. Before it
// sends one it sets gp.preempt and gp.stackguard0 = stackPreempt, which is the
// COOPERATIVE request: the next non-NOSPLIT function call sees the poisoned
// stack guard and yields. So a garbage collector trying to scan this goroutine's
// stack still gets there through ordinary function calls, and blocking the
// signal costs it nothing.
//
// The exception, stated plainly because it is a real way to hang a program: a
// window whose fn contains an unbounded loop with NO function calls in it offers
// no cooperative preemption point either, and suspendG will spin waiting. Keep
// fn short and call-bearing — which the borrowing contract already asks for.
//
// # What it does not do
//
//   - It does not stop COOPERATIVE preemption, so a long window can still be
//     descheduled at a call boundary and have its stack scanned, and possibly
//     shrunk (which copies) by the collector afterwards. Blocking the signal
//     removes the arbitrary-instruction register dump, not every stack copy.
//   - It does nothing about a SYNCHRONOUS fault (SIGSEGV/SIGBUS) landing inside
//     the window: the kernel writes a ucontext containing the full register set
//     to the signal stack. That is identical in C and is not fixable here.
//   - It is unavailable on Windows, whose preemption suspends the thread and
//     rewrites its context via SetThreadContext rather than delivering a signal.
//     Nothing in userspace can mask that. It is also unavailable on Darwin,
//     where x/sys/unix exposes no PthreadSigmask; rather than reach for a raw
//     syscall on a platform this cannot be tested on, that stays unsupported and
//     says so. See scrub_window_other.go.
//
// runtime.LockOSThread is mandatory, not incidental: pthread_sigmask sets the
// mask of the CURRENT THREAD, and an unpinned goroutine can migrate to another
// thread mid-window, where the mask was never set.
//
// # fn must leave the pin alone
//
// LockOSThread is counted per goroutine, and the window's call is one count. An
// UnlockOSThread inside fn that fn did not itself pair with a LockOSThread pays
// off the WINDOW's count: the goroutine is unpinned mid-window and can be
// rescheduled onto another thread before restore runs. The saved mask belongs
// to the thread it left, and no syscall sets another thread's mask, so that
// thread keeps SIGURG and SIGPROF blocked for the rest of the process — never
// async-preempted, invisible to the CPU profiler — and nothing reports it:
// UnlockOSThread on a zero count is a documented no-op.
//
// restore therefore compares the thread it runs on with the one the mask was
// taken from, and on a mismatch panics instead of writing a stranger's mask.
// That is a tripwire for the misuse, not a repair of it: once the goroutine has
// moved, the leak is permanent. And it catches only what it can observe. A
// goroutine fn unpinned that is still, by luck, on its entry thread passes the
// check and restores correctly (nothing leaked), and the check is not atomic
// with the write that follows it — a cooperative yield at that call boundary
// could still move an unpinned goroutine in between. Both are misuse; the
// contract is the fix, the check is the alarm.

package secmem

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// preemptSignals are the signals whose handlers dump register state onto the
// goroutine stack.
//
//   - SIGURG is Go's non-cooperative preemption signal (runtime.sigPreempt);
//     its handler spills the whole register file.
//   - SIGPROF is the CPU profiler's; its handler walks and records the stack.
//     Blocking it costs profile samples on this thread for the window's
//     duration and nothing else.
var preemptSignals = []unix.Signal{unix.SIGURG, unix.SIGPROF} //nolint:gochecknoglobals // fixed signal set, read-only.

// sigaddset sets sig's bit in a Sigset_t. x/sys/unix exposes the type and
// PthreadSigmask but no sigaddset, so this does the one line of bit arithmetic
// the C macro does: signals are numbered from 1, and the set is a flat bitmap of
// 64-bit words.
func sigaddset(set *unix.Sigset_t, sig unix.Signal) error {
	n := int(sig) - 1
	if n < 0 || n/64 >= len(set.Val) {
		return unix.EINVAL
	}
	set.Val[n/64] |= 1 << (uint(n) % 64)
	return nil
}

// preemptWindow carries the state needed to undo suppressAsyncPreempt.
//
// It exists so that the caller can keep that state on its OWN stack. The
// obvious API — returning a restore closure — costs two heap allocations per
// call: the closure, and the saved signal mask it has to capture. Scrub wraps
// the hot paths of a crypto library, so two allocations on every call is a real
// cost, and allocating inside a window whose entire purpose is secret hygiene is
// the wrong shape besides. Measured, not guessed: this was caught by
// secmem-crypto's zero-allocation gate on OpenInto, which went from 0 to 2
// allocs/op on Linux the moment the window was added, and `go build -gcflags=-m`
// names both ("moved to heap: prev", "func literal escapes to heap").
type preemptWindow struct {
	// prev is the mask to restore. Passing &w.prev to pthread_sigmask does not
	// force w to the heap — the block mask below already proves that, being
	// passed the same way and staying on the stack.
	prev unix.Sigset_t

	// tid is the kernel thread the mask was taken from, recorded once the pin
	// is in place so it cannot be stale. restore refuses to run anywhere else:
	// the mask is that thread's property and restoring it on another would fix
	// nothing and clobber a stranger. See the file header.
	//
	// The price is two gettid calls per window — raw syscalls, no scheduler
	// involvement, no allocation. Measured on a 20-core Azure VM with go1.26.5:
	// about 100 ns per Scrub on an empty fn (406 to 510 ns on the legacy path,
	// 197 to 300 ns under runtimesecret), allocations unchanged at zero.
	tid int

	// active records that the mask was actually changed, so restore on a failed
	// or never-suppressed window is a no-op rather than an unbalanced
	// UnlockOSThread.
	active bool
}

// suppressAsyncPreempt pins the goroutine to its thread and blocks the
// register-dumping signals, recording in w what restore must undo. The caller
// MUST defer w.restore() — leaking a blocked SIGURG would stop this thread
// being preemptible for the rest of its life.
//
// On any failure it undoes whatever it managed to change and reports false; the
// caller then runs the window unhardened rather than not at all.
func suppressAsyncPreempt(w *preemptWindow) bool {
	runtime.LockOSThread()
	// After the pin, not before: an unpinned goroutine could move between
	// asking and locking, and the record would name a thread it never masked.
	w.tid = unix.Gettid()

	var block unix.Sigset_t
	for _, sig := range preemptSignals {
		if err := sigaddset(&block, sig); err != nil {
			runtime.UnlockOSThread()
			return false
		}
	}
	if err := unix.PthreadSigmask(unix.SIG_BLOCK, &block, &w.prev); err != nil {
		runtime.UnlockOSThread()
		return false
	}

	w.active = true
	return true
}

// restore puts the thread's signal mask back and unpins the goroutine. It is
// idempotent and safe on a window that was never suppressed.
//
// It panics if it finds itself on a thread other than the one the mask was
// taken from — fn unbalanced LockOSThread and the goroutine migrated. The entry
// thread is already leaked by then (see the file header); what restore can
// still do is refuse to make it worse and refuse to be silent about it.
func (w *preemptWindow) restore() {
	if !w.active {
		return
	}
	w.active = false
	// Gettid is a raw syscall with no scheduler round trip, so it cannot itself
	// move the goroutine between this check and the write below.
	if tid := unix.Gettid(); tid != w.tid {
		panic(fmt.Sprintf("secmem: Scrub window opened on OS thread %d but ended on thread %d: "+
			"fn called runtime.UnlockOSThread without a LockOSThread of its own to match, "+
			"unpinning the goroutine mid-window; thread %d is left with SIGURG and SIGPROF "+
			"blocked for the rest of the process", w.tid, tid, w.tid))
	}
	// Restore the exact prior mask rather than unblocking unconditionally: the
	// caller may itself have had these blocked for its own reasons.
	_ = unix.PthreadSigmask(unix.SIG_SETMASK, &w.prev, nil)
	runtime.UnlockOSThread()
}

// asyncPreemptSuppressionSupported reports that this platform can suppress the
// register-dumping preemption signal. Reported through Capabilities so the
// posture is inspectable rather than assumed.
const asyncPreemptSuppressionSupported = true
