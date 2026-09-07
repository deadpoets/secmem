// terminationwipe.go implements the OPT-IN termination-signal wipe.
//
// secmem does not touch process signal state as a side effect of import —
// installing process-global signal handlers is the application's decision. A
// consumer that wants secrets wiped automatically on Ctrl-C / kill opts in with
// InstallTerminationWipe; a consumer that already handles those signals should
// call WipeAllSecrets from its own handler instead.

package secmem

import (
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

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
// reraise and exit are parameters rather than direct calls so the decision is
// testable without delivering a real signal — a test that actually re-raised
// would terminate the test binary, and one that actually exited would take the
// suite with it. The live behaviour is covered separately by a harness that
// delivers a genuine console Ctrl-Break to a child in its own process group.
func completeTermination(sig os.Signal, forceExit bool, reraise func(os.Signal) error, exit func(int)) (rearm bool) {
	if err := reraise(sig); err == nil {
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
// Where the signal cannot be re-raised, secmem exits the process itself with a
// status indistinguishable from the un-intercepted signal. That is Windows:
// os.Process.Signal there implements only [os.Kill] and rejects os.Interrupt and
// SIGTERM outright, and the console event that triggered the handler has already
// been consumed, so there is nothing left to re-deliver.
//
// Verified behaviour before this was so: a real Ctrl-C wiped every secret and
// the process kept running, exiting only on a SECOND Ctrl-C. That left it in the
// one state [WipeAllSecrets] does not support. The wipe deliberately leaves
// regions MAPPED so a late read returns zeros instead of faulting — a trade
// justified entirely by "the process is terminating imminently". A process that
// survives instead keeps every key buffer readable and full of zeros, and reads
// still SUCCEED, so an application that treats the signal as "begin shutdown"
// can go on to sign with an all-zero key or derive from zeros, each call
// reporting success. That is worse than either terminating or never wiping.
//
// Use [InstallTerminationWipeNoExit] if your own handler owns the exit.
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
// [InstallTerminationWipeNoExit] on Windows — there is no such race and the
// handler stays installed: every later signal wipes again, so a secret created
// after one wipe does not outlive the next signal. Uninstall to stop that.
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
// Read the warning above first: after the wipe your secrets are gone but still
// READABLE as zeros, so a shutdown path that keeps doing cryptography will get
// silent success on zeroed key material. Exit promptly.
//
// It has no effect anywhere except Windows, since every other platform can
// re-raise and the process terminates through the normal disposition. There it
// stays installed after the signal (see "After the signal" above), so each
// Ctrl-C wipes again and none of them ends the process: with no handler of your
// own, a second Ctrl-C no longer terminates it the way it did while the handler
// was one-shot. Termination is entirely yours.
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
				_ = WipeAllSecrets()
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
				// with every secret already zeroed (reads return zeros, mutations
				// return ErrWiped), while this function's documentation says it
				// terminates.
				//
				// Reported rather than escalated to a forced os.Exit, because
				// the installer promises never to take the exit out from under a
				// co-installed graceful shutdown — and signal.Notify is additive,
				// so any such handler already received this signal
				// independently. On Windows the exit is therefore the
				// application's job, and the log line says so instead of leaving
				// it to be discovered.
				if !completeTermination(sig, forceExit, reraise, exit) {
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
