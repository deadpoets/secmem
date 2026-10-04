//go:build plan9

package secmem

import (
	"os"
	"os/signal"
	"syscall"
)

// inheritedIgnores records which notes were ignored when the handler was
// installed. Plan 9 has notes, not signals: os/signal acts on syscall.Note
// there, and syscall.Signal does not exist.
type inheritedIgnores map[syscall.Note]bool

// recordInheritedIgnores reads the inherited disposition of each note. It must
// run before signal.Notify, the only moment signal.Ignored reports it.
func recordInheritedIgnores(signals []os.Signal) inheritedIgnores {
	rec := make(inheritedIgnores, len(signals))
	for _, sig := range signals {
		if n, ok := sig.(syscall.Note); ok {
			rec[n] = signal.Ignored(n)
		}
	}
	return rec
}

// ignored reports whether sig was ignored at install time.
func (rec inheritedIgnores) ignored(sig os.Signal) bool {
	n, ok := sig.(syscall.Note)
	return ok && rec[n]
}
