// scrub.go holds the build-tag-independent Scrub surface: the startup posture
// assertion. The Scrub/ScrubErr/RuntimeSecretActive implementations are split
// across scrub_runtimesecret.go (primary) and scrub_legacy.go (best-effort) by
// build tag.

package secmem

import "errors"

// ErrRuntimeSecretInactive indicates the process was built without
// GOEXPERIMENT=runtimesecret on a platform that supports it — the
// register/stack/heap erasure layer ([Scrub]) is therefore NOT active and
// only the legacy best-effort frame scrub is in force.
var ErrRuntimeSecretInactive = errors.New(
	"runtime/secret erasure inactive: built without GOEXPERIMENT=runtimesecret on a supported platform")

// AssertRuntimeSecret enforces the memory-hardening posture at startup
// (fail-closed).
//
//   - On a supported platform (linux/amd64|arm64) it returns
//     [ErrRuntimeSecretInactive] when the runtimesecret experiment was not
//     compiled in. Production entrypoints MUST treat this as fatal: a binary
//     shipping without the erasure layer on a platform that supports it is a
//     misbuild (build with `GOEXPERIMENT=runtimesecret`, as the Taskfile does).
//   - On unsupported platforms (Windows, Darwin, non-amd64/arm64) the legacy
//     best-effort scrub layer is the expected posture, so it returns nil.
//
// Call early in main(), after [HardenProcess]. Callers that must tolerate an
// inactive layer (e.g. a developer running an ad-hoc `go build` without the
// experiment) can downgrade the error to a warning, but the default posture is
// to refuse to start.
func AssertRuntimeSecret() error {
	if runtimeSecretSupported() && !RuntimeSecretActive() {
		return ErrRuntimeSecretInactive
	}
	return nil
}
