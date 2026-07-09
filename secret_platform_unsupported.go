//go:build !(linux && (amd64 || arm64))

package secmem

// runtimeSecretSupported reports false on platforms where runtime/secret
// erasure is unavailable (Windows, Darwin, non-amd64/arm64). The legacy
// best-effort scrub layer is expected there. See the supported counterpart in
// secret_platform_supported.go.
func runtimeSecretSupported() bool { return false }
