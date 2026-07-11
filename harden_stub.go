//go:build !linux && !windows

package secmem

// hardenProcess is a no-op on platforms without process-mitigation
// primitives (Darwin has neither prctl nor SetProcessMitigationPolicy).
func hardenProcess() (HardenLevel, error) {
	return HardenNone, nil
}
