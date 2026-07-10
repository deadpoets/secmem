//go:build !devmode

package secmem

// RuntimeSecretEnforced reports whether an inactive runtime/secret erasure
// layer on a supported platform should be treated as fatal at startup.
//
// In production (!devmode) builds it returns true: a binary that ships without
// the erasure layer on a platform that supports it is a misbuild and must
// fail-closed. The devmode counterpart returns false so developer and test
// builds (which legitimately run without GOEXPERIMENT=runtimesecret) only warn.
//
// Pair with [AssertRuntimeSecret] in main():
//
//	if err := secmem.AssertRuntimeSecret(); err != nil {
//	    if secmem.RuntimeSecretEnforced() {
//	        // fatal
//	    }
//	    // warn
//	}
func RuntimeSecretEnforced() bool { return true }
