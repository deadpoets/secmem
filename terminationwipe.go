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
// # Windows does not self-terminate
//
// The re-raise that makes the process exit is a no-op on Windows:
// [os.Process.Signal] there supports only [os.Kill] and rejects both
// [os.Interrupt] and SIGTERM outright. So on Windows this installer wipes and
// then RETURNS — every secret is gone, but the process keeps running and must
// exit on its own. The failure is logged at warn level rather than swallowed.
// Handle the exit in your own handler if you need one on that platform.
//
// It does NOT clobber other signal handling. It registers its own channel with
// [signal.Notify] (which is additive: a handler you installed with
// signal.Notify still receives the signal too). On the signal it wipes,
// deregisters ONLY its own channel with [signal.Stop] — never the process-global
// signal.Reset/signal.Ignore — and re-raises the signal: if secmem is the only
// handler the default disposition is restored and the process terminates; if you
// have your own handler it receives the signal and decides when to exit, so
// secmem never forces the exit out from under your graceful shutdown.
//
// If you already have a termination handler, prefer calling WipeAllSecrets from
// inside it rather than using this installer.
func InstallTerminationWipe(signals ...os.Signal) (uninstall func()) {
	if len(signals) == 0 {
		signals = []os.Signal{os.Interrupt, syscall.SIGTERM}
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, signals...)
	done := make(chan struct{})

	go func() {
		select {
		case sig, ok := <-ch:
			if !ok {
				return
			}
			_ = WipeAllSecrets()
			// Deregister only our own channel — never the process-global
			// signal.Reset/Ignore. If we were the last handler the default
			// disposition is restored so the re-raise below terminates the
			// process; otherwise a co-installed handler receives it and owns the
			// exit. Our own Notify registration already suppressed the default
			// disposition until this Stop, so a second signal arriving mid-wipe
			// could not kill us early — no global Ignore is needed.
			signal.Stop(ch)
			// Re-raise so the now-default disposition terminates the process.
			//
			// This cannot work on Windows: os.Process.Signal rejects everything
			// except Kill with "not supported by windows" — verified on go1.26,
			// windows/amd64, for both os.Interrupt and SIGTERM. Discarding that
			// error left the worst of the three possible outcomes: the process
			// sails past Ctrl-C still running, with every secret already zeroed
			// (reads return zeros, mutations return ErrWiped), while this
			// function's documentation says it terminates.
			//
			// Reported rather than escalated to a forced os.Exit, because the
			// installer promises never to take the exit out from under a
			// co-installed graceful shutdown — and signal.Notify is additive,
			// so any such handler already received this signal independently.
			// On Windows the exit is therefore the application's job, and the
			// log line says so instead of leaving it to be discovered.
			proc, err := os.FindProcess(os.Getpid())
			if err == nil {
				err = proc.Signal(sig)
			}
			if err != nil {
				slog.Warn("secmem: could not re-raise the termination signal — secrets are wiped, but this process will NOT exit on its own",
					slog.String("signal", sig.String()),
					slog.Any("error", err),
					slog.String("advice", "exit from your own signal handler; on Windows os.Process.Signal supports only Kill"),
				)
			}
		case <-done:
			signal.Stop(ch)
		}
	}()

	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}
