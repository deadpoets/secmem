package redact_test

import (
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/deadpoets/secmem/redact"
)

const sampleJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

const pemBody = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB"

const samplePEM = "-----BEGIN RSA PRIVATE KEY-----\n" + pemBody + "\nxQNJf3XkUoMBpdGuqMq5kJvZ8dkEBqqnKrVLoDVnV0lYRq1ea3FzQdVzSTjTj9\n-----END RSA PRIVATE KEY-----"

// TestSanitize_CredentialShapes pins every credential shape the review found
// the default rules missing. Each case names the secret that must vanish and
// the tag that must name the rule which caught it.
func TestSanitize_CredentialShapes(t *testing.T) {
	t.Parallel()
	s := redact.NewDefaultSanitizer()
	cases := []struct{ name, in, secret, tag string }{
		{"authorization bearer jwt", "Authorization: Bearer " + sampleJWT, sampleJWT, "authorization_header"},
		{"authorization basic", "Authorization: Basic dXNlcjpodW50ZXIy", "dXNlcjpodW50ZXIy", "authorization_header"},
		{"authorization json", `"Authorization": "Bearer abc.def"`, "abc.def", "authorization_header"},
		{"proxy-authorization", "Proxy-Authorization: Basic dXNlcjpodW50ZXIy", "dXNlcjpodW50ZXIy", "authorization_header"},
		{"aws secret", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI", "secret_field"},
		{"passwd", "passwd=hunter2", "hunter2", "password_field"},
		{"pwd", "pwd=hunter2", "hunter2", "password_field"},
		{"pass", "pass=hunter2", "hunter2", "password_field"},
		{"db_pass", "DB_PASS=hunter2", "hunter2", "password_field"},
		{"passphrase", "passphrase: hunter2", "hunter2", "password_field"},
		{"secret_key", "secret_key=hunter2", "hunter2", "secret_field"},
		{"private_key", "private_key=hunter2", "hunter2", "secret_field"},
		{"signing_key", "signing_key=hunter2", "hunter2", "secret_field"},
		{"credentials", "credentials=hunter2", "hunter2", "secret_field"},
		{"url userinfo", "dsn postgres://user:hunter2@db:5432/x", "hunter2", "url_password"},
		{"url userinfo empty user", "redis://:hunter2@cache", "hunter2", "url_password"},
		{"oauth code", "redirect ?code=hunter2&state=abc", "hunter2", "url_query_credential"},
		{"query key", "GET /v1?key=AIzaSyhunter2&x=1", "AIzaSyhunter2", "url_query_credential"},
		{"query sig", "blob?sig=hunter2sig&se=2030", "hunter2sig", "url_query_credential"},
		{"cookie", "Cookie: session=hunter2; theme=dark", "hunter2", "cookie_header"},
		{"set-cookie", "Set-Cookie: sid=hunter2; Path=/; HttpOnly", "hunter2", "cookie_header"},
		{"0x hex", "hash 0x" + sha256hex, sha256hex, "hex_secret"},
		{"unpadded base64", "tok " + strings.Repeat("Ab9", 15), strings.Repeat("Ab9", 15), "base64_secret"},
		{"base64url", "tok " + strings.Repeat("aB3-_", 9), strings.Repeat("aB3-_", 9), "base64_secret"},
		{"ruby hash", "password => hunter2", "hunter2", "password_field"},
		{"escaped json", `{\"password\":\"hunter2\",\"user\":\"bob\"}`, "hunter2", "password_field"},
		{"percent-encoded", "password%3Dhunter2", "hunter2", "password_field"},
		{"pem block", samplePEM, pemBody, "pem_private_key"},
		{"bare bearer", "got bearer " + strings.Repeat("x", 25), strings.Repeat("x", 25), "bearer_token"},
		{"jwt alone", "id " + sampleJWT, sampleJWT, "jwt"},
		{"x-api-key header", "X-Api-Key: hunter2", "hunter2", "api_key_field"},
		{"env api key", "OPENAI_API_KEY=hunter2", "hunter2", "api_key_field"},
	}
	for _, c := range cases {
		got := s.Sanitize(c.in)
		if strings.Contains(got, c.secret) {
			t.Errorf("%s: Sanitize(%q) leaked %q: %q", c.name, c.in, c.secret, got)
		}
		if !strings.Contains(got, "[REDACTED:"+c.tag+"]") {
			t.Errorf("%s: Sanitize(%q) missing tag %q: %q", c.name, c.in, c.tag, got)
		}
	}
}

// TestSanitize_EscapedJSONDoesNotSwallowSiblings: the escaped-quoted value
// alternative must stop at the first \" so the fields after the credential
// survive.
func TestSanitize_EscapedJSONDoesNotSwallowSiblings(t *testing.T) {
	t.Parallel()
	got := redact.NewDefaultSanitizer().Sanitize(`{\"password\":\"hunter2\",\"user\":\"bob\"}`)
	if !strings.Contains(got, `\"user\":\"bob\"`) {
		t.Errorf("sibling field was swallowed: %q", got)
	}
}

// TestSanitize_PEMWithoutFooter: a block cut off before its footer still has
// its header tagged, and the body lines fall to the entropy rule.
func TestSanitize_PEMWithoutFooter(t *testing.T) {
	t.Parallel()
	in := "-----BEGIN EC PRIVATE KEY-----\n" + pemBody + "\n" + pemBody
	got := redact.NewDefaultSanitizer().Sanitize(in)
	if strings.Contains(got, pemBody) {
		t.Errorf("PEM body line survived without a footer: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:pem_private_key]") {
		t.Errorf("PEM header not tagged: %q", got)
	}
}

// TestSanitize_LegitimateTextSurvives is the other direction: identifiers,
// paths, hashes behind an allowlisted label, and words that merely contain a
// credential name must pass through unchanged.
func TestSanitize_LegitimateTextSurvives(t *testing.T) {
	t.Parallel()
	s := redact.NewDefaultSanitizer()
	for _, in := range []string{
		"id 123e4567-e89b-12d3-a456-426614174000",
		"commit=" + sha256hex,
		"pkg github.com/deadpoets/secmem/redact/sanitizer_test/verylongpath/more",
		"/usr/local/lib/python3/dist-packages/foo/bar/baz/qux/quux",
		"fn TestHandler_WithAttrsBeforeGroupStaysOutsideIt",
		"bypass=true compass: north token_type=Bearer status code=200",
		"password_length=12 secret_name=db-creds",
		"https://host:8080/path?x=1&keyword=rust",
		"Bearer authentication required",
		strings.Repeat("-", 48),
		"ordinary message with an em dash — and café",
	} {
		if got := s.Sanitize(in); got != in {
			t.Errorf("legitimate text altered:\n in:  %q\n out: %q", in, got)
		}
	}
}

// TestCommonProviderRules_NewFormats covers the token prefixes added by the
// review, with the provider rules first so the tag names the format.
func TestCommonProviderRules_NewFormats(t *testing.T) {
	t.Parallel()
	rules := append(redact.CommonProviderRules(), redact.DefaultRules()...)
	s := redact.NewSanitizer(rules, redact.WithAllowlist(redact.DefaultAllowlist()))
	cases := []struct{ in, secret, tag string }{
		{"key sk-proj-abcdefghijklmnopqrstuvwxyz0123456789", "abcdefghijklmnopqrstuvwxyz0123456789", "openai_key"},
		{"github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW", "11ABCDEFG0123456789", "github_fine_grained_pat"},
		{"glpat-abcdefghijklmnopqrstuvwx", "abcdefghijklmnopqrstuvwx", "gitlab_pat"},
		{"ASIAIOSFODNN7EXAMPLE", "IOSFODNN7EXAMPLE", "aws_access_key_id"},
		{"AKIAIOSFODNN7EXAMPLE", "IOSFODNN7EXAMPLE", "aws_access_key_id"},
	}
	for _, c := range cases {
		got := s.Sanitize(c.in)
		if strings.Contains(got, c.secret) {
			t.Errorf("Sanitize(%q) leaked %q: %q", c.in, c.secret, got)
		}
		if !strings.Contains(got, "[REDACTED:"+c.tag+"]") {
			t.Errorf("Sanitize(%q) missing tag %q: %q", c.in, c.tag, got)
		}
	}
	// The AWS secret rule stands on its own in a set without DefaultRules.
	alone := redact.NewSanitizer(redact.CommonProviderRules())
	got := alone.Sanitize("aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	if strings.Contains(got, "wJalrXUtnFEMI") || !strings.Contains(got, "[REDACTED:aws_secret_access_key]") {
		t.Errorf("aws_secret_access_key rule did not fire on its own: %q", got)
	}
}

// TestRule_Filter: a Filter that returns false leaves the match in place.
func TestRule_Filter(t *testing.T) {
	t.Parallel()
	rule := redact.Rule{
		Name:     "even",
		Category: redact.CategorySecret,
		Pattern:  regexp.MustCompile(`\d+`),
		Filter:   func(m string) bool { return len(m)%2 == 0 },
	}
	s := redact.NewSanitizer([]redact.Rule{rule})
	if got := s.Sanitize("a 123 b 1234 c"); got != "a 123 b [REDACTED:even] c" {
		t.Errorf("Filter not honoured: %q", got)
	}
}

// TestRule_TagExpansion: Tag is an Expand template, so a rule can keep the
// part of its match that is not the credential.
func TestRule_TagExpansion(t *testing.T) {
	t.Parallel()
	rule := redact.Rule{
		Name:    "kv",
		Pattern: regexp.MustCompile(`(\w+)=(\w+)`),
		Tag:     "${1}=<hidden>",
	}
	s := redact.NewSanitizer([]redact.Rule{rule})
	if got := s.Sanitize("user=bob"); got != "user=<hidden>" {
		t.Errorf("Tag expansion: %q", got)
	}
}

// TestSanitize_TruncatesBeforeRules: WithMaxLen cuts the input before any
// rule runs, so text past the cut is never scanned — it cannot leak, and it
// cannot cost anything. The password below sits past the cut: the output
// must carry neither it nor a password tag.
func TestSanitize_TruncatesBeforeRules(t *testing.T) {
	t.Parallel()
	s := redact.NewSanitizer(redact.DefaultRules(), redact.WithMaxLen(16))
	in := strings.Repeat("x", 20) + " password=hunter2"
	got := s.Sanitize(in)
	if strings.Contains(got, "hunter2") {
		t.Errorf("text past the cut leaked: %q", got)
	}
	if strings.Contains(got, "[REDACTED:password_field]") {
		t.Errorf("rule ran over text past the cut: %q", got)
	}
	if want := strings.Repeat("x", 16) + "[REDACTED:truncated]"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if again := s.Sanitize(got); again != got {
		t.Errorf("not idempotent after truncation:\n once: %q\ntwice: %q", got, again)
	}

	// The cut backs up to a rune boundary rather than splitting a character.
	in = strings.Repeat("é", 20)
	got = s.Sanitize(in)
	if !utf8.ValidString(got) || strings.Contains(got, "invalid_utf8") {
		t.Errorf("truncation split a rune: %q", got)
	}
	if again := s.Sanitize(got); again != got {
		t.Errorf("rune-boundary truncation not idempotent:\n once: %q\ntwice: %q", got, again)
	}
}

// pathological returns a message of about kb kilobytes in the shape that
// made the allowlist quadratic: many entropy matches, each preceded by prose
// that mentions allowlist labels, so every match used to rescan the whole
// prefix with every allowlist pattern.
func pathological(kb int) string {
	unit := "commit mention trace_id note " + strings.Repeat("ab", 25) + " "
	return strings.Repeat(unit, kb*1024/len(unit))
}

// TestSanitize_LinearScaling pins the fix for the quadratic allowlist. On
// the unfixed code 41 KB took 0.85 s and 205 KB 22 s on the development
// host; 410 KB took 145 s. The assertion is on the growth ratio, which a
// slow CI host does not change, plus a generous absolute bound.
func TestSanitize_LinearScaling(t *testing.T) {
	t.Parallel()
	s := redact.NewSanitizer(redact.DefaultRules(), redact.WithAllowlist(redact.DefaultAllowlist()), redact.WithMaxLen(0))
	small, large := pathological(40), pathological(400)

	time40 := timeSanitize(s, small)
	time400 := timeSanitize(s, large)
	t.Logf("40 KB: %v, 400 KB: %v", time40, time400)

	if time400 > 3*time.Second {
		t.Errorf("400 KB took %v, want well under a second on a developer host", time400)
	}
	// Linear is 10x; quadratic is 100x. Allow noise.
	if time400 > 40*time40 && time40 > time.Millisecond {
		t.Errorf("superlinear: 40 KB %v vs 400 KB %v (ratio %.0f)", time40, time400, float64(time400)/float64(time40))
	}
}

func timeSanitize(s *redact.Sanitizer, msg string) time.Duration {
	best := time.Duration(1 << 62)
	for i := 0; i < 3; i++ {
		start := time.Now()
		_ = s.Sanitize(msg)
		if d := time.Since(start); d < best {
			best = d
		}
	}
	return best
}

// TestSanitize_MaxLenBoundsWork: with the default 4096 cap a multi-megabyte
// message costs what 4 KB costs.
func TestSanitize_MaxLenBoundsWork(t *testing.T) {
	t.Parallel()
	s := redact.NewDefaultSanitizer()
	msg := pathological(4096)
	start := time.Now()
	got := s.Sanitize(msg)
	if d := time.Since(start); d > time.Second {
		t.Errorf("4 MB with maxLen 4096 took %v; truncation is not bounding the work", d)
	}
	if len(got) > 4096+len("[REDACTED:truncated]") {
		t.Errorf("output length %d exceeds maxLen plus marker", len(got))
	}
}

func BenchmarkSanitize_400KB(b *testing.B) {
	s := redact.NewSanitizer(redact.DefaultRules(), redact.WithAllowlist(redact.DefaultAllowlist()), redact.WithMaxLen(0))
	msg := pathological(400)
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Sanitize(msg)
	}
}

func BenchmarkSanitize_Default4KB(b *testing.B) {
	s := redact.NewDefaultSanitizer()
	msg := pathological(4)
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Sanitize(msg)
	}
}
