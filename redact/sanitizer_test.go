package redact_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/deadpoets/secmem/redact"
)

// sha256hex is a 64-char hex constant reused across entropy tests.
const sha256hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func TestSanitize_KeyValueCredentials(t *testing.T) {
	t.Parallel()
	s := redact.NewDefaultSanitizer()
	cases := []struct {
		in, secret, tag string
	}{
		{"login password=super-secret-123 done", "super-secret-123", "[REDACTED:password_field]"},
		{"config token=my-api-token rest", "my-api-token", "[REDACTED:token_field]"},
		{"client_secret=abc123xyz here", "abc123xyz", "[REDACTED:secret_field]"},
		{"api_key=deadbeefcafe end", "deadbeefcafe", "[REDACTED:api_key_field]"},
		{"authorization auth=Bearer-xyz done", "Bearer-xyz", "[REDACTED:auth_field]"},
	}
	for _, c := range cases {
		got := s.Sanitize(c.in)
		if strings.Contains(got, c.secret) {
			t.Errorf("Sanitize(%q) leaked %q: %q", c.in, c.secret, got)
		}
		if !strings.Contains(got, c.tag) {
			t.Errorf("Sanitize(%q) missing tag %q: %q", c.in, c.tag, got)
		}
	}
}

func TestSanitize_InjectionNeutralized(t *testing.T) {
	t.Parallel()
	s := redact.NewDefaultSanitizer()

	got := s.Sanitize("line1\r\nFAKE LOG ENTRY")
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("CRLF survived: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:crlf_injection]") {
		t.Errorf("no crlf tag: %q", got)
	}

	got = s.Sanitize("text \x1b[31mred\x1b[0m end")
	if strings.Contains(got, "\x1b") {
		t.Errorf("ANSI escape survived: %q", got)
	}

	got = s.Sanitize("cmd ${HOME} and $(whoami)")
	if strings.Contains(got, "${HOME}") || strings.Contains(got, "$(whoami)") {
		t.Errorf("shell metachar survived: %q", got)
	}
}

func TestSanitize_ControlCharsStripped(t *testing.T) {
	t.Parallel()
	s := redact.NewDefaultSanitizer()
	got := s.Sanitize("before\x00\x07after")
	if strings.ContainsAny(got, "\x00\x07") {
		t.Errorf("control chars survived: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:control_char]") {
		t.Errorf("no control_char tag: %q", got)
	}
}

func TestSanitize_EntropyRedactedButAllowlisted(t *testing.T) {
	t.Parallel()
	s := redact.NewDefaultSanitizer()

	// Bare high-entropy hex is redacted.
	if got := s.Sanitize("digest " + sha256hex); strings.Contains(got, sha256hex) {
		t.Errorf("bare hex not redacted: %q", got)
	}
	// The same hex behind an allowlisted label is spared.
	msg := "commit=" + sha256hex
	if got := s.Sanitize(msg); !strings.Contains(got, sha256hex) {
		t.Errorf("allowlisted commit hash was redacted: %q", got)
	}
	// base64 with padding is redacted.
	b64 := strings.Repeat("QUJD", 12) + "==" // 50 chars + padding
	if got := s.Sanitize("blob " + b64); strings.Contains(got, b64) {
		t.Errorf("base64 secret not redacted: %q", got)
	}
}

func TestSanitize_Idempotent(t *testing.T) {
	t.Parallel()
	s := redact.NewDefaultSanitizer()
	once := s.Sanitize("password=hunter2 and digest " + sha256hex)
	twice := s.Sanitize(once)
	if once != twice {
		t.Errorf("not idempotent:\n once: %q\ntwice: %q", once, twice)
	}
}

// TestSanitize_Idempotent_TruncationBoundary is the regression for the bug the
// fuzzer found: truncation runs after the rules and its marker introduces a
// word boundary, which lets an entropy rule match on a later pass what it
// could not on the first. A run of hex characters longer than maxLen, broken
// by a non-hex word character past the cut point, has no word boundary around
// its hex span originally — but once truncation drops the tail and appends the
// marker, the surviving prefix is bounded by '[' and becomes matchable. A
// single-pass Sanitize was therefore not idempotent; the fixpoint loop fixes
// it.
func TestSanitize_Idempotent_TruncationBoundary(t *testing.T) {
	t.Parallel()
	s := redact.NewSanitizer(redact.DefaultRules(), redact.WithMaxLen(50))

	in := strings.Repeat("a", 60) + "r" + strings.Repeat("a", 60)
	once := s.Sanitize(in)
	twice := s.Sanitize(once)
	if once != twice {
		t.Errorf("truncation-boundary non-idempotence:\n once: %q\ntwice: %q", once, twice)
	}
	// And the surviving prefix must actually be redacted, not left bare.
	if strings.HasPrefix(once, "aaaa") {
		t.Errorf("truncated hex prefix left unredacted: %q", once)
	}
}

func TestSanitize_Truncation(t *testing.T) {
	t.Parallel()
	s := redact.NewSanitizer(redact.DefaultRules(), redact.WithMaxLen(10))
	got := s.Sanitize(strings.Repeat("a", 100))
	if !strings.HasSuffix(got, "[REDACTED:truncated]") {
		t.Errorf("no truncation suffix: %q", got)
	}
	if len(got) != 10+len("[REDACTED:truncated]") {
		t.Errorf("truncated to wrong length: %d", len(got))
	}
}

func TestDefaultRules_NoProviderTokensByDefault(t *testing.T) {
	t.Parallel()
	// A GitHub PAT must pass through DefaultRules untouched — provider rules
	// are opt-in.
	pat := "ghp_" + strings.Repeat("a", 36)
	def := redact.NewDefaultSanitizer()
	if got := def.Sanitize("auth " + pat); !strings.Contains(got, pat) {
		t.Errorf("DefaultRules redacted a provider token it should not know: %q", got)
	}
	// With CommonProviderRules bolted on, it IS redacted.
	rules := append(redact.DefaultRules(), redact.CommonProviderRules()...)
	withProviders := redact.NewSanitizer(rules, redact.WithAllowlist(redact.DefaultAllowlist()))
	if got := withProviders.Sanitize("auth " + pat); strings.Contains(got, pat) {
		t.Errorf("CommonProviderRules did not redact the PAT: %q", got)
	}
}

func TestCommonProviderRules_Formats(t *testing.T) {
	t.Parallel()
	rules := append(redact.DefaultRules(), redact.CommonProviderRules()...)
	s := redact.NewSanitizer(rules)
	secrets := []string{
		"ghp_" + strings.Repeat("A", 36),
		"AKIA" + strings.Repeat("A", 16),
		"xoxb-123456789012-abcdefABCDEF",
		"-----BEGIN RSA PRIVATE KEY-----",
	}
	for _, sec := range secrets {
		if got := s.Sanitize("value: " + sec); strings.Contains(got, sec) {
			t.Errorf("provider secret not redacted: %q -> %q", sec, got)
		}
	}
}

func TestInjectionOnlyRules_RedactsNoSecrets(t *testing.T) {
	t.Parallel()
	s := redact.NewSanitizer(redact.InjectionOnlyRules())
	// A password field passes through — injection-only redacts no secrets.
	if got := s.Sanitize("password=leaked"); !strings.Contains(got, "leaked") {
		t.Errorf("injection-only redacted a secret it should ignore: %q", got)
	}
	// But CRLF is still neutralized.
	if got := s.Sanitize("a\r\nb"); strings.ContainsAny(got, "\r\n") {
		t.Errorf("injection-only did not neutralize CRLF: %q", got)
	}
}

func TestSanitize_EmptyString(t *testing.T) {
	t.Parallel()
	if got := redact.NewDefaultSanitizer().Sanitize(""); got != "" {
		t.Errorf("Sanitize(\"\") = %q, want empty", got)
	}
}

func TestCustomTag(t *testing.T) {
	t.Parallel()
	rule := redact.Rule{
		Name:     "custom",
		Category: redact.CategorySecret,
		Pattern:  regexp.MustCompile(`SEKRIT`),
		Tag:      "***",
	}
	s := redact.NewSanitizer([]redact.Rule{rule})
	if got := s.Sanitize("a SEKRIT b"); got != "a *** b" {
		t.Errorf("custom tag: got %q", got)
	}
}
