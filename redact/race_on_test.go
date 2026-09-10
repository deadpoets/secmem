//go:build race

package redact_test

// raceEnabled reports whether the test binary was built with -race, under
// which absolute timing bounds are not meaningful.
const raceEnabled = true
