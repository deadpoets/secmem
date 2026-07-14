// Package suppress round-trips the two real //nolint:secmem-lint patterns that
// exist in the secmem tree: the deliberate string egress inside ExposeString,
// and a test copying borrowed bytes into a stack array. None of these lines
// should produce a finding.
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
