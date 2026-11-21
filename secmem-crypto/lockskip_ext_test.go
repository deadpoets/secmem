package secmemcrypto_test

import (
	"strings"
	"testing"
)

// skipIfLockRefused skips the test when err is the operating system refusing
// to lock memory. That is the environment's lock budget, not a defect: the
// library returned the error instead of placing a secret on unlocked pages,
// which is its contract. Any other error is left for the caller to report.
//
// It matches the stage the allocator names when it wraps the refusal, so it
// builds on every platform. CI pipes its test lanes through
// internal/skipaudit, where a skip that is not allowlisted fails the job, so
// a refusal on a runner with an ordinary budget is still an error there.
func skipIfLockRefused(tb testing.TB, err error) {
	tb.Helper()
	if err == nil {
		return
	}
	msg := err.Error()
	if strings.Contains(msg, "mlock: ") || strings.Contains(msg, "VirtualLock: ") {
		tb.Skipf("the OS refused to lock memory (raise RLIMIT_MEMLOCK or the working-set minimum): %v", err)
	}
}
