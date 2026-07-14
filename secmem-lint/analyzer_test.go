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
