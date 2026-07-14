package secmemlint_test

import (
	"testing"

	secmemlint "github.com/deadpoets/secmem/secmem-lint"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	// analysistest loads the testdata packages in GOPATH mode; ignore the
	// enclosing go.work workspace so the fixtures resolve against the stub.
	t.Setenv("GOWORK", "off")
	analysistest.Run(t, analysistest.TestData(), secmemlint.Analyzer,
		"escape", "reentrancy", "suppress")
}

// TestStrict covers the opt-in checks (N1, L1), which are off unless -strict is set.
func TestStrict(t *testing.T) {
	t.Setenv("GOWORK", "off")
	a := secmemlint.Analyzer
	if err := a.Flags.Set("strict", "true"); err != nil {
		t.Fatalf("set strict flag: %v", err)
	}
	t.Cleanup(func() { _ = a.Flags.Set("strict", "false") })
	analysistest.Run(t, analysistest.TestData(), a, "strict")
}
