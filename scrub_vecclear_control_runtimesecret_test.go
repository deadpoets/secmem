//go:build goexperiment.runtimesecret && linux && (amd64 || arm64)

package secmem

// vecClearControlAvailable: the legacy window's pieces (the frame wipe) are
// build-tagged out under runtime/secret, and runtime/secret erases registers
// itself, so the sequence the control replicates does not exist on this build.
// The proof runs its subjects only.
const vecClearControlAvailable = false

// legacyWindowNoClear is unreachable on this build; see the constant above.
func legacyWindowNoClear(func()) { panic("secmem: legacyWindowNoClear called under runtime/secret") }
