//go:build !amd64 || purego || !gc

package argon2

// clearVectorRegs is a no-op where this package has no vector assembly: on
// every other architecture blamka is the scalar Go implementation, so block
// state passes through general-purpose registers that the next few
// instructions overwrite, and there is no register file this package can
// claim — with evidence — to have cleared. See vecclear_amd64.go.
func clearVectorRegs() {}
