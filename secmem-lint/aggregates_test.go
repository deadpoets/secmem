package secmemlint_test

import (
	"testing"

	secmemlint "github.com/deadpoets/secmem/secmem-lint"
	"golang.org/x/tools/go/analysis/analysistest"
)

// TestAggregates covers writes through a local struct or array value: the
// value's own storage is inside the closure, but a slice, pointer or map held
// in one of its fields or elements is wherever it points, and only a field
// whose every stored value is provably fresh counts as inside.
func TestAggregates(t *testing.T) {
	t.Setenv("GOWORK", "off")
	analysistest.Run(t, analysistest.TestData(), secmemlint.Analyzer, "aggregates")
}
