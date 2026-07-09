package secmem

// SecureWipe zeroes the bytes of b using the platform's best available
// wiping primitive (assembly-backed where present, compiler-barrier otherwise).
//
// Unlike [WipeBytes], which is part of the legacy hardening layer and is only
// compiled on non-runtimesecret builds, SecureWipe is available in every build
// and on every platform. Use it from sub-packages (e.g. security/storekey) and
// for transient secret intermediates that are not held in a SecureBuffer.
func SecureWipe(b []byte) {
	secureWipeSlice(b)
}
