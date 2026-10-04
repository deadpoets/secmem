//go:build !plan9

package secmem

import (
	"os"
	"os/signal"
	"syscall"
)

// inheritedIgnores records which signals were ignored when the handler was
// installed. Keyed by syscall.Signal, the only kind os/signal acts on here
// (Notify skips any other implementation of os.Signal, and so does this), so a
// caller's own os.Signal type cannot make the record panic.
type inheritedIgnores map[syscall.Signal]bool

// recordInheritedIgnores reads the inherited disposition of each signal. It
// must run before signal.Notify, the only moment signal.Ignored reports it.
func recordInheritedIgnores(signals []os.Signal) inheritedIgnores {
	rec := make(inheritedIgnores, len(signals))
	for _, sig := range signals {
		if s, ok := sig.(syscall.Signal); ok {
			rec[s] = signal.Ignored(s)
		}
	}
	return rec
}

// ignored reports whether sig was ignored at install time.
func (rec inheritedIgnores) ignored(sig os.Signal) bool {
	s, ok := sig.(syscall.Signal)
	return ok && rec[s]
}
