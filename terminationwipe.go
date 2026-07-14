// terminationwipe.go implements the OPT-IN termination-signal wipe.
//
// secmem does not touch process signal state as a side effect of import —
// installing process-global signal handlers is the application's decision. A
// consumer that wants secrets wiped automatically on Ctrl-C / kill opts in with
// InstallTerminationWipe; a consumer that already handles those signals should
// call WipeAllSecrets from its own handler instead.

package secmem

import (
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
			if p, err := os.FindProcess(os.Getpid()); err == nil {
				_ = p.Signal(sig)
			}
		case <-done:
			signal.Stop(ch)
		}
	}()

	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}
