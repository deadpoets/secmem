// terminationwipe.go implements the OPT-IN termination-signal wipe.
//
// secmem does not touch process signal state as a side effect of import —
// installing process-global signal handlers is the application's decision. A
// consumer that wants secrets wiped automatically on Ctrl-C / kill opts in with
// InstallTerminationWipe; a consumer that already handles those signals should
// call WipeAllSecrets from its own handler instead.

package secmem

import (
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// TerminationWipeTimeout is how long the handler installed by
// [InstallTerminationWipe] waits for [WipeAllSecrets] before it goes on to
// terminate the process anyway. WipeAllSecrets waits for every borrowing
// callback to return, and one that never does would otherwise hold the handler
// forever, with the signal's default disposition suppressed the whole time.
const TerminationWipeTimeout = 5 * time.Second

// terminationWipeTimeout is the bound the handler uses; a variable so a test
// does not have to wait out the real one.
var terminationWipeTimeout = TerminationWipeTimeout

// wipeAllSecretsBounded runs [WipeAllSecrets] and waits for it for at most
// timeout. It reports whether the wipe finished. When it did not, the wipe is
// still running: everything that was not borrowed is already zeroed (the first
// pass does not wait), and each borrowed region is wiped the moment its
// callback returns, if the process lives that long.
func wipeAllSecretsBounded(timeout time.Duration) (completed bool) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = WipeAllSecrets()
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// errInheritedIgnored stands in for the re-raise's result when the signal
// was already ignored at install time. The kill(2) itself would succeed —
// which is exactly the problem: the kernel accepts the signal and discards it,
// so the "re-raised, the disposition owns the exit" conclusion would be drawn
// about an exit that is never going to happen.
var errInheritedIgnored = errors.New("secmem: the signal was ignored when the handler was installed (an inherited disposition), so re-raising it would be discarded")

// reraiseSignal re-delivers sig to this process. It is the step that terminates
// the process on every platform that can do it.
func reraiseSignal(sig os.Signal) error {
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}
	return proc.Signal(sig)
}

// completeTermination runs after the wipe: re-raise, and if that is impossible,
// either exit or report, per forceExit. It reports whether the handler should
// stay installed: true only when nothing was re-raised and the process was left
// running, so that the next signal is a new event and not the echo of this one.
//
// inheritedIgnore says the signal was ignored when the handler was installed
// (see installTerminationWipeHooks). Then the re-raise is not attempted at
// all: it would succeed as a system call and be discarded by the kernel, and
// the process would run on with every secret zeroed. It is treated exactly
// like a re-raise that failed.
//
// reraise and exit are parameters rather than direct calls so the decision is
// testable without delivering a real signal — a test that actually re-raised
// would terminate the test binary, and one that actually exited would take the
// suite with it. The live behaviour is covered separately by a harness that
// delivers a genuine console Ctrl-Break to a child in its own process group,
// and, for the inherited-ignore case, by a child started with SIGINT ignored.
func completeTermination(sig os.Signal, forceExit, inheritedIgnore bool, reraise func(os.Signal) error, exit func(int)) (rearm bool) {
	var err error
	if inheritedIgnore {
		err = errInheritedIgnored
	} else {
		err = reraise(sig)
	}
	if err == nil {
		return false // re-raised; the restored disposition or a co-handler owns the exit
	} else if !forceExit {
		slog.Warn("secmem: could not re-raise the termination signal — secrets are wiped, but this process will NOT exit on its own",
			slog.String("signal", sig.String()),
			slog.Any("error", err),
			slog.String("advice", "exit from your own handler; InstallTerminationWipe (without NoExit) exits for you"),
		)
		return true
	} else {
		slog.Warn("secmem: termination signal could not be re-raised; exiting after the wipe",
			slog.String("signal", sig.String()),
			slog.Any("error", err),
			slog.Int("status", forcedExitStatus),
		)
	}
	exit(forcedExitStatus)
	return false
}

// InstallTerminationWipe installs a cooperative signal handler that calls
// [WipeAllSecrets] when the process receives a termination signal, then lets the
// process terminate as it otherwise would. It returns a function that uninstalls
// the handler.
//
// This is opt-in: importing secmem installs nothing. Call it once early in main
// if you want automatic wiping on Ctrl-C / kill:
//
//	defer secmem.InstallTerminationWipe()()
//
// With no arguments it handles [os.Interrupt] (SIGINT) and SIGTERM. Pass
// explicit signals to override — note that adding SIGQUIT both suppresses Go's
// default SIGQUIT goroutine dump and re-raises to a core-dumping disposition.
//
// It does NOT clobber other signal handling. It registers its own channel with
// [signal.Notify] (which is additive: a handler you installed with
// signal.Notify still receives the signal too). On the signal it wipes,
// deregisters ONLY its own channel with [signal.Stop] — never the process-global
// signal.Reset/signal.Ignore — and re-raises the signal, so if secmem is the
// only handler the restored default disposition terminates the process, and if
// you have your own handler it receives the signal and decides when to exit.
//
// # The process always terminates
//
// Where the signal cannot be re-raised to any effect, secmem exits the process
// itself, with forcedExitStatus: on Windows STATUS_CONTROL_C_EXIT, which is
// indistinguishable from the un-intercepted signal; elsewhere 130, the shell
// convention for SIGINT. One case is Windows:
// os.Process.Signal there implements only [os.Kill] and rejects os.Interrupt and
// SIGTERM outright, and the console event that triggered the handler has already
// been consumed, so there is nothing left to re-deliver.
//
// It is also any signal the process INHERITED AS IGNORED. The Go runtime
// respects an inherited SIG_IGN for SIGINT and SIGHUP (not SIGTERM): Notify
// still delivers the signal, so the wipe runs, but Stop restores the ignore,
// and a re-raise then succeeds as a system call and is discarded by the
// kernel. A process started with `cmd &` from a non-interactive shell — a
// shell script, a Makefile recipe, a shell-script container entrypoint that
// backgrounds the process — has SIGINT ignored in exactly this way (POSIX
// requires it for asynchronous lists when job control is off), and so does a
// `nohup` child for SIGHUP. Measured before
// this was handled: such a child wiped, reported the re-raise as done, and
// kept running with every secret gone. The installer therefore
// records, once, which of its signals are ignored at the moment it is
// called — [os/signal.Ignored] reports the inherited state only until Notify
// overrides it — and treats one of those as impossible to re-raise: the
// default installer exits, the NoExit one warns and stays installed. The
// exit status is forcedExitStatus's for the platform — 130 here, whichever
// of the handler's signals it was, since an ignored signal has no
// un-intercepted status to match.
//
// Verified behaviour before this was so: a real Ctrl-C wiped every secret and
// the process kept running, exiting only on a SECOND Ctrl-C. That left it in the
// one state [WipeAllSecrets] is not meant for. The wipe deliberately leaves
// regions MAPPED so a retained slice does not fault — a trade justified
// entirely by "the process is terminating imminently". A process that survives
// instead runs on with every key dead: each borrow returns [ErrWiped], so an
// application that treats the signal as "begin shutdown" finds every signing,
// decryption and derivation call failing. That fails closed (it once did not:
// borrows used to succeed and hand out the zeros), but it is still a process
// that can no longer do its job and was told to stop.
//
// Use [InstallTerminationWipeNoExit] if your own handler owns the exit.
//
// # The wipe is bounded
//
// [WipeAllSecrets] waits for every borrowing callback to return, so a callback
// that is blocked (on I/O, on a lock, or on a nested call into its own buffer)
// would hold the handler in the wipe indefinitely: the process would not
// terminate, and with this handler still registered no later signal would
// terminate it either. The handler therefore waits [TerminationWipeTimeout]
// and then proceeds exactly as if the wipe had finished, with a warning
// logged. By then every secret that was not borrowed is already zeroed. The
// one inside the stuck callback is not, and the process is about to end with
// it in memory: a secret that a running callback is reading cannot be zeroed
// underneath it. Keep borrowing callbacks short.
//
// # After the signal
//
// Once it has re-raised, the handler is finished: it does not register again,
// so a co-installed handler that keeps the process alive gets no second wipe
// from secmem on a later signal, and a secret created after the first wipe is
// not covered. This is deliberate. The kernel delivers the re-raised signal
// asynchronously, so a registration made after the re-raise returns can still
// be the one that receives it — which would either loop (wipe, re-raise,
// receive the re-raise, wipe, ...) or, when secmem is the only handler, keep
// alive the process the re-raise was meant to terminate. If your own handler
// keeps the process running, call [WipeAllSecrets] from it on every later
// signal, or install this handler again from it once it has received the
// signal.
//
// Where nothing could be re-raised and the process was left running — that is
// [InstallTerminationWipeNoExit] on Windows, or for a signal inherited as
// ignored — there is no such race and the handler stays installed: every later
// signal wipes again, so a secret created after one wipe does not outlive the
// next signal. Uninstall to stop that.
//
// If you already have a termination handler, prefer calling WipeAllSecrets from
// inside it rather than using this installer.
func InstallTerminationWipe(signals ...os.Signal) (uninstall func()) {
	return installTerminationWipe(true, signals...)
}

// InstallTerminationWipeNoExit is [InstallTerminationWipe] without the forced
// exit: if the signal cannot be re-raised, it wipes, logs, and returns, leaving
// termination entirely to the caller.
//
// Choose it when your own handler performs a graceful shutdown that must not be
// truncated — flushing logs, draining connections — and will exit on its own.
// Read the warning above first: after the wipe your secrets are gone, and a
// shutdown path that keeps doing cryptography gets [ErrWiped] from every key
// operation. Finish what does not need a secret, and exit promptly.
//
// It has an effect only on Windows and for a signal the process inherited as
// ignored (see "The process always terminates" above); everywhere else the
// re-raise is a real kill against a restored default disposition and the
// process terminates through it. In those two cases the handler stays
// installed after the signal (see "After the signal" above), so each Ctrl-C
// wipes again and none of them ends the process: with no handler of your own,
// a second Ctrl-C no longer terminates it the way it did while the handler was
// one-shot. Termination is entirely yours.
func InstallTerminationWipeNoExit(signals ...os.Signal) (uninstall func()) {
	return installTerminationWipe(false, signals...)
}

func installTerminationWipe(forceExit bool, signals ...os.Signal) (uninstall func()) {
	return installTerminationWipeHooks(forceExit, reraiseSignal, os.Exit, nil, signals...)
}

// installTerminationWipeHooks is installTerminationWipe with the re-raise and
// the exit injectable, for the same reason completeTermination takes them, and
// with rearmed called each time the handler has registered again after a
// survived signal. A test needs that last one to know when a second signal is
// safe to send: until the handler is registered again the default disposition
// is live, and a signal landing then is a different event entirely.
func installTerminationWipeHooks(forceExit bool, reraise func(os.Signal) error, exit func(int), rearmed func(), signals ...os.Signal) (uninstall func()) {
	if len(signals) == 0 {
		signals = []os.Signal{os.Interrupt, syscall.SIGTERM}
	}
	// Record which signals the process inherited as ignored BEFORE Notify:
	// Notify overrides an inherited SIG_IGN so the wipe can run, and from then
	// on signal.Ignored reports false for it — including after the Stop that
	// puts the ignore back — so this is the only moment the fact can be read.
	// A signal ignored here cannot be re-raised to any effect (see
	// completeTermination); without this record the handler concluded "the
	// disposition owns the exit" about a disposition that discards it.
	//
	// The record is taken once: a handler another package registers for the
	// same signal AFTER this one does not change it, so with such a late
	// co-handler the default installer still exits itself rather than leave
	// the exit to it — fail-safe, and a reason to install this one first.
	inheritedIgnore := recordInheritedIgnores(signals)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, signals...)
	done := make(chan struct{})

	go func() {
		for {
			select {
			case sig, ok := <-ch:
				if !ok {
					return
				}
				if !wipeAllSecretsBounded(terminationWipeTimeout) {
					slog.Warn("secmem: a borrowing callback did not return in time; every other secret is wiped, the borrowed one is not, and termination proceeds",
						slog.String("signal", sig.String()),
						slog.Duration("waited", terminationWipeTimeout))
				}
				// Deregister only our own channel — never the process-global
				// signal.Reset/Ignore. If we were the last handler the default
				// disposition is restored so the re-raise below terminates the
				// process; otherwise a co-installed handler receives it and owns
				// the exit. Our own Notify registration already suppressed the
				// default disposition until this Stop, so a second signal
				// arriving mid-wipe could not kill us early — no global Ignore is
				// needed.
				signal.Stop(ch)
				// Re-raise so the now-default disposition terminates the process.
				//
				// This cannot work on Windows: os.Process.Signal rejects
				// everything except Kill with "not supported by windows" —
				// verified on go1.26, windows/amd64, for both os.Interrupt and
				// SIGTERM. Discarding that error left the worst of the three
				// possible outcomes: the process sails past Ctrl-C still running,
				// with every secret already zeroed (every borrow returns
				// ErrWiped), while this function's documentation says it
				// terminates.
				//
				// Reported rather than escalated to a forced os.Exit, because
				// the installer promises never to take the exit out from under a
				// co-installed graceful shutdown — and signal.Notify is additive,
				// so any such handler already received this signal
				// independently. On Windows the exit is therefore the
				// application's job, and the log line says so instead of leaving
				// it to be discovered.
				//
				// A signal the process inherited as ignored is the same case
				// on every platform: the kill would succeed and the kernel
				// would drop it. inheritedIgnore was read before Notify, the
				// only moment it can be.
				if !completeTermination(sig, forceExit, inheritedIgnore.ignored(sig), reraise, exit) {
					// Re-raised, or exited. Whether the process dies now or a
					// co-installed handler keeps it alive is not observable from
					// here, and the re-raised signal is still in flight: a fresh
					// registration could be the one that receives it, and this
					// loop would then re-raise again, or hold open a process
					// with no other handler. So this handler is done — the doc
					// comment tells a surviving co-handler what to do instead.
					return
				}
				// Nothing was re-raised and the process was left running (the
				// NoExit installer on Windows). Nothing of ours is in flight, so
				// registering again is safe, and staying installed is what the
				// returned uninstall implies: the next signal wipes whatever was
				// created since this one, instead of the process ending on it
				// with those secrets intact. Between the Stop above and this
				// Notify the default disposition is live — a signal landing in
				// that window ends the process the way every second signal did
				// while the handler was one-shot, but the window is now a few
				// microseconds after a completed wipe rather than the whole
				// remaining lifetime of the process.
				signal.Notify(ch, signals...)
				if rearmed != nil {
					rearmed()
				}
			case <-done:
				signal.Stop(ch)
				return
			}
		}
	}()

	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}
