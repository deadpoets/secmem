//go:build linux && (amd64 || arm64)

package secmem

// runtimeSecretSupported reports whether this OS/arch can run runtime/secret
// erasure when built with GOEXPERIMENT=runtimesecret. It is independent of
// whether the experiment was actually compiled in — that is reported by
// [RuntimeSecretActive]. Used by [AssertRuntimeSecret] to distinguish a
// misbuild (supported but inactive) from an expected legacy platform.
func runtimeSecretSupported() bool { return true }
