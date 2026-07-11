package redact_test

import (
	"bytes"
	"fmt"
	"log/slog"

	"github.com/deadpoets/secmem/redact"
)

// A Sanitizer masks credential-shaped substrings and neutralizes log
// injection in free-form text.
func ExampleSanitizer() {
	s := redact.NewDefaultSanitizer()
	fmt.Println(s.Sanitize("connecting with password=hunter2"))
	// Output: connecting with [REDACTED:password_field]
}

// Named third-party token formats are opt-in via CommonProviderRules.
func ExampleCommonProviderRules() {
	rules := append(redact.DefaultRules(), redact.CommonProviderRules()...)
	s := redact.NewSanitizer(rules, redact.WithAllowlist(redact.DefaultAllowlist()))
	fmt.Println(s.Sanitize("token is ghp_000000000000000000000000000000000000"))
	// Output: token is [REDACTED:github_pat]
}

// Handler wraps any slog.Handler so every log line is scrubbed automatically —
// the whole-logger backstop for a secret that slips into a message or an
// error.
func ExampleNewHandler() {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{} // drop time for a stable example
			}
			return a
		},
	})
	logger := slog.New(redact.NewHandler(inner, nil))

	logger.Info("connecting with password=s3cret to the database")
	fmt.Print(buf.String())
	// Output: level=INFO msg="connecting with [REDACTED:password_field] to the database"
}
