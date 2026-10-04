//go:build linux

package secmem

// resetSuppressionFailureForTest clears the sticky failure record so one
// test's injected failure does not change what the rest of the suite reads.
func resetSuppressionFailureForTest() { asyncPreemptSuppressFailed.Store(false) }
