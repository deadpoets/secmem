// Package suppress round-trips the two real //nolint:secmem-lint patterns that
// exist in the secmem tree: the deliberate string egress inside ExposeString,
// and a test copying borrowed bytes into a stack array, plus the golangci-lint
// directive forms. Only the lines marked want, whose directive names some
// other linter, produce a finding.
package suppress

import "github.com/deadpoets/secmem"

var sink string

func exposeStringPattern(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sink = string(b) //nolint:secmem-lint // deliberate egress, mirrors ExposeString
	})
}

func copyIntoStackArray(buf *secmem.SecureBuffer) {
	var out [32]byte
	_ = buf.WithBytes(func(b []byte) {
		copy(out[:], b) //nolint:secmem-lint // intentional copy into a caller array
	})
	_ = out
}

func bareNolint(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sink = string(b) //nolint
	})
}

// nolintAll: golangci-lint's "every linter" spelling is honoured, so a line
// one tool has excused is not failed by the other.
func nolintAll(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sink = string(b) //nolint:all // deliberate egress
	})
}

// The golangci-lint directive grammar: nolint, an optional :list of linters,
// then end of comment or whitespace and an explanation.
func directiveForms(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sink = string(b) //nolint // bare, with an explanation
		sink = string(b) //nolint:secmem-lint // listed, with an explanation
		sink = string(b) //nolint:all // every linter, with an explanation
		sink = string(b) //nolint:gosec,secmem-lint
		sink = string(b) //nolint:gosec,all // every linter, second in the list
	})
}

// Directives that do not name secmem-lint leave the finding in place.
func directiveNegatives(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sink = string(b) //nolint:gosec // want `secmem-lint: string\(\) copies borrowed secret bytes`
		sink = string(b) //nolint:gosec,errcheck // want `secmem-lint: string\(\) copies borrowed secret bytes`
		sink = string(b) //nolint:secmem-lintx // want `secmem-lint: string\(\) copies borrowed secret bytes`
		sink = string(b) //nolintfoo // want `secmem-lint: string\(\) copies borrowed secret bytes`
	})
}
