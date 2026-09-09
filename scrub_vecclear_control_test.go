//go:build (!goexperiment.runtimesecret || !(linux && (amd64 || arm64))) && (amd64 || arm64)

package secmem

// vecClearControlAvailable: the legacy window's pieces exist on this build, so
// the vector-clear proof can run its controls (scrub_vecclear_test.go).
const vecClearControlAvailable = true

// legacyWindowNoClear is Scrub's legacy body with the vector clear left out and
// nothing else changed: same pin, same reserve-then-wipe, same recover-then-
// re-raise through scrubCall. It is the control for the vector-clear proof —
// what the window's exit sequence leaves in the registers when nothing clears
// them — and it must stay in step with Scrub in scrub_legacy.go, minus the
// one line under test.
func legacyWindowNoClear(fn func()) {
	var window preemptWindow
	suppressAsyncPreempt(&window)
	defer window.restore()

	wipeScratchFrameFull()
	p := scrubCall(fn)
	wipeScratchFrameFull()
	if p != nil {
		panic(p)
	}
}
