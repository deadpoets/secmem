package secmem

import (
	"regexp"
	"strings"
)

// childReasonLine matches the line testing prints for t.Skip/t.Skipf in a
// child's -test.v output: "    file_test.go:123: reason".
var childReasonLine = regexp.MustCompile(`^\s*[^\s:]+\.go:\d+: ?(.*)$`)

// childSkipReason reports whether a re-exec'd child's -test.v output records
// a skip, and the reason it printed. A parent that only checks the child's
// exit status passes over a child that proved nothing; propagating the skip
// makes it visible to the audit in CI instead.
func childSkipReason(out []byte) (string, bool) {
	var last string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "--- SKIP") {
			return last, true
		}
		if m := childReasonLine.FindStringSubmatch(l); m != nil {
			last = m[1]
		}
	}
	return "", false
}
