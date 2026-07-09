//go:build !linux

package secmem

// hardenProcess is a no-op on non-Linux platforms.
// Linux-specific prctl and seccomp features are not available here.
func hardenProcess() (HardenLevel, error) {
	return HardenNone, nil
}
