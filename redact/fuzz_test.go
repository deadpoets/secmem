package redact_test

import (
	"strings"
	"testing"

	"github.com/deadpoets/secmem/redact"
)

// FuzzSanitize proves the sanitizer's invariants hold for arbitrary input:
// it never panics, its output is idempotent (a second pass is a no-op), and
// no C0/C1 control byte survives — the CWE-117 backstop that must hold even
// when every content rule misses.
func FuzzSanitize(f *testing.F) {
	for _, seed := range []string{
		"",
		"password=hunter2",
		"clean text with no secrets",
		"line1\r\nline2\x00\x07",
		"ghp_" + strings.Repeat("a", 36),
		strings.Repeat("A", 9000),
		// Regression seed: hex run past maxLen, broken by a non-hex word char,
		// so truncation creates the boundary that made rules non-idempotent.
		strings.Repeat("a", 6000) + "r" + strings.Repeat("a", 6000),
		"\x1b[31mred\x1b[0m",
	} {
		f.Add(seed)
	}

	// The strict sanitizer (all rules, no allowlist) is the most aggressive
	// configuration and the right one to fuzz.
	s := redact.NewStrictSanitizer()

	f.Fuzz(func(t *testing.T, in string) {
		out := s.Sanitize(in)

		// Idempotent: re-sanitizing must not change anything.
		if again := s.Sanitize(out); again != out {
			t.Fatalf("not idempotent:\n in:   %q\n out:  %q\n twice:%q", in, out, again)
		}

		// No control characters may survive (they are the injection vector).
		for _, r := range out {
			if r < 32 || r == 127 {
				t.Fatalf("control char %#x survived sanitization of %q -> %q", r, in, out)
			}
		}
	})
}
