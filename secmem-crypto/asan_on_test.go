//go:build asan

package secmemcrypto

// asanEnabled reports whether the test binary was built with -asan, whose
// instrumentation allocates: an allocation count taken under it measures the
// sanitizer, so those assertions stand down and the rest of the test runs.
const asanEnabled = true
