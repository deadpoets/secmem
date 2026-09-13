//go:build !amd64 && !arm64

package secmem

// clearVectorRegs is a no-op on architectures with no vector-clear assembly.
// There is no register file this package can claim — with the empirical test
// the project requires — to have cleared, so it clears none and Capabilities
// reports the gap (VectorRegisterClear) rather than hiding it. See
// vecclear_amd64.go for what the real implementation does and why.
func clearVectorRegs() {}

// clearGPRegs is a no-op for the same reason: no assembly, no proof, and
// Capabilities.GPRegisterClear says so.
func clearGPRegs() {}
