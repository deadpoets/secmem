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

// TestSanitize_QuotedCredentialShapes covers the two shapes the original
// `field[=:]\s*\S+` patterns got wrong. Both are the common case in structured
// logs, not an exotic one.
func TestSanitize_QuotedCredentialShapes(t *testing.T) {
	t.Parallel()
	s := redact.NewDefaultSanitizer()
	cases := []struct{ name, in, secret string }{
		// A quoted KEY was missed entirely: the character after the key is a
		// quote, not the separator, so the pattern matched nothing at all.
		{"json quoted key", `{"password": "hunter2", "user": "bob"}`, "hunter2"},
		{"json quoted key, spaced", `{"token" : "abc123"}`, "abc123"},
		{"json api_key", `{"api_key": "deadbeef"}`, "deadbeef"},
		// A quoted MULTI-WORD value was only partly masked: \S+ stopped at the
		// first space and left the remainder in the message.
		{"double-quoted multiword", `password="hunter 2 correct horse"`, "correct horse"},
		{"single-quoted multiword", `secret='two words here'`, "two words here"},
	}
	for _, c := range cases {
		got := s.Sanitize(c.in)
		if strings.Contains(got, c.secret) {
			t.Errorf("%s: Sanitize(%q) leaked %q: %q", c.name, c.in, c.secret, got)
		}
	}
}

// TestSanitize_C1AndInvalidUTF8 covers the half of the CWE-117 backstop that was
// documented but not implemented. U+009B is the single-character CSI: a terminal
// decoding the stream as Latin-1/ISO-2022 acts on it exactly as it would on the
// two-byte ESC-[ that the ansi rule strips.
func TestSanitize_C1AndInvalidUTF8(t *testing.T) {
	t.Parallel()
	s := redact.NewDefaultSanitizer()

	if got := s.Sanitize("before31mafter"); strings.ContainsRune(got, '') {
		t.Errorf("C1 CSI (U+009B) survived the backstop: %q", got)
	}
	if got := s.Sanitize("padpad"); strings.ContainsRune(got, '') {
		t.Errorf("C1 NEL (U+0085) survived the backstop: %q", got)
	}
	// A raw invalid UTF-8 byte must be reported, not silently become U+FFFD.
	// Built from bytes: a source escape is too easy to write as U+00FF by
	// accident, which would test nothing.
	raw := string([]byte{0x76, 0x61, 0x6c, 0xff, 0x69, 0x64})
	got := s.Sanitize(raw)
	if strings.ContainsRune(got, rune(0xfffd)) || strings.Contains(got, string([]byte{0xff})) {
		t.Errorf("invalid UTF-8 byte survived: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:invalid_utf8]") {
		t.Errorf("invalid UTF-8 byte not reported as redacted: %q", got)
	}
	// Printable text, including multi-byte UTF-8, must be untouched.
	const clean = "ordinary message with an em dash — and café"
	if got := s.Sanitize(clean); got != clean {
		t.Errorf("printable UTF-8 was altered: %q -> %q", clean, got)
	}
}

// TestSanitize_AllowlistAfterEarlierLabel pins the allowlist against an earlier
// occurrence of its own label. isAllowlisted used FindStringIndex, which returns
// the EARLIEST match, so a message mentioning the label anywhere before the
// credential compared the wrong match's end position, failed, and silently
// disabled the allowlist for the rest of the message.
//
// Uses an entropy rule because those are the only allowlist-gated category.
func TestSanitize_AllowlistAfterEarlierLabel(t *testing.T) {
	t.Parallel()
	s := redact.NewSanitizer(redact.DefaultRules(), redact.WithAllowlist(redact.DefaultAllowlist()))

	// "commit=" appears once early and again immediately before the hex value
	// it is meant to exempt.
	in := "commit= earlier mention; commit=" + sha256hex
	got := s.Sanitize(in)
	if !strings.Contains(got, sha256hex) {
		t.Errorf("allowlisted hex was redacted because the label also appeared earlier: %q", got)
	}
}
