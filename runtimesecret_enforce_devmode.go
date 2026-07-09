//go:build devmode

package secmem

// RuntimeSecretEnforced returns false in devmode builds: developer and test
// builds legitimately run without GOEXPERIMENT=runtimesecret, so an inactive
// erasure layer is downgraded from fatal to a warning. See the production
// counterpart in runtimesecret_enforce_production.go.
func RuntimeSecretEnforced() bool { return false }
