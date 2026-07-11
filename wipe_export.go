package secmem

// SecureWipe zeroes the bytes of b using the platform's best available
// wiping primitive (assembly-backed where present, compiler-barrier otherwise).
//
// It is the package's only exported wipe, available in every build and on
// every platform. Use it for transient secret intermediates that are not held
// in a SecureBuffer; for mmap'd SecureBuffer memory, Destroy applies the full
// architectural wipe.
func SecureWipe(b []byte) {
	secureWipeSlice(b)
}
