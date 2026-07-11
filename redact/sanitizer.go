// Package redact sanitizes strings destined for logs and other text sinks:
// it masks credential-shaped substrings and neutralizes log-injection
// sequences (CWE-117). It is the boundary-level complement to secmem.Secret —
// where Secret makes a held value self-redacting, redact scrubs free-form
// text that has already been assembled (a log line, an error message).
//
// HONESTY — what this is and is not:
//
//   - It is a defense-in-depth backstop, NOT a guarantee. Pattern matching
//     catches credential SHAPES (known token formats, key=value pairs, high
//     entropy); it cannot catch a secret that looks like ordinary prose, and
//     a determined format will always slip a regex. Never rely on it as the
//     only thing between a secret and a log — keep secrets in a
//     [secmem.SecureBuffer]/[secmem.Secret] and never format them in the
//     first place. redact exists to reduce blast radius when that discipline
//     slips, not to license slipping.
//
//   - The default rules are deliberately GENERIC (key=value credentials,
//     injection, high-entropy heuristics). Named third-party token formats
//     (GitHub, cloud providers) live in [CommonProviderRules] and are OFF by
//     default — bolt them on when you know your log stream carries them.
//
// The package is stdlib-only and safe for concurrent use: a [Sanitizer] is
// immutable after construction.
package redact

import (
	"regexp"
	"strings"
)

// Category classifies why a [Rule] exists — useful for building or filtering
// a rule set (e.g. "injection only", "everything except entropy").
type Category string

const (
	// CategoryInjection covers CWE-117 log-injection neutralization (CRLF,
	// ANSI escapes, shell metacharacters). Not a secrecy control.
	CategoryInjection Category = "injection"

	// CategorySecret covers credential-shaped substrings — key=value pairs
	// and known token formats.
	CategorySecret Category = "secret"

	// CategoryEntropy covers high-entropy heuristics (long base64/hex runs).
	// Lowest confidence; allowlist-gated to spare legitimate hashes and IDs.
	CategoryEntropy Category = "entropy"
)

// Rule is one sanitization rule: a regex whose matches are replaced by a tag.
type Rule struct {
	// Name is a stable identifier, surfaced in the default tag (e.g. "github_pat").
	Name string
	// Category classifies why the rule exists.
	Category Category
	// Pattern detects the sensitive substring.
	Pattern *regexp.Regexp
	// Tag is the replacement. Defaults to "[REDACTED:<Name>]" when empty.
	Tag string
}

// tag returns the effective replacement for r.
func (r Rule) tag() string {
	if r.Tag != "" {
		return r.Tag
	}
	return "[REDACTED:" + r.Name + "]"
}

// Sanitizer applies an ordered set of rules to a string. It is immutable
// after construction and safe for concurrent use.
type Sanitizer struct {
	rules     []Rule
	allowlist []*regexp.Regexp
	maxLen    int
}

// Option configures a [Sanitizer].
type Option func(*Sanitizer)

// WithMaxLen caps the output length. A message longer than n is truncated and
// suffixed with "[REDACTED:truncated]". Zero (the default when unset via this
// option) disables truncation. The constructor default is 4096.
func WithMaxLen(n int) Option {
	return func(s *Sanitizer) { s.maxLen = n }
}

// WithAllowlist sets prefix patterns that exempt an immediately-following
// entropy match from redaction — e.g. a "commit=" prefix before a hex SHA.
// Only [CategoryEntropy] matches consult the allowlist.
func WithAllowlist(patterns []*regexp.Regexp) Option {
	return func(s *Sanitizer) { s.allowlist = patterns }
}

// NewSanitizer builds a Sanitizer from rules and options. Rules are applied in
// slice order, so put higher-confidence rules first. The default max length is
// 4096 characters.
func NewSanitizer(rules []Rule, opts ...Option) *Sanitizer {
	s := &Sanitizer{rules: rules, maxLen: 4096}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// maxSanitizePasses bounds the fixpoint iteration in [Sanitize]. Tags never
// re-match a rule, so convergence is normally 1–3 passes; the bound only
// guards against a pathological rule set and is never expected to be reached.
const maxSanitizePasses = 16

// Sanitize applies every rule to message and returns the result. It is
// idempotent — Sanitize(Sanitize(x)) == Sanitize(x) — because it iterates to a
// fixpoint. That matters: truncation runs after the rules and its marker
// creates a word boundary, which can let a rule match on a later pass what it
// could not on the first; a single pass would therefore not be stable, and
// callers (including [Handler], which may see already-sanitized text) rely on
// re-sanitizing being a no-op. Control characters are replaced and an
// over-length result is truncated within each pass.
func (s *Sanitizer) Sanitize(message string) string {
	if message == "" {
		return message
	}
	prev := message
	for i := 0; i < maxSanitizePasses; i++ {
		cur := s.onePass(prev)
		if cur == prev {
			return cur // fixpoint reached
		}
		prev = cur
	}
	return prev
}

// onePass applies the rules once, strips control characters, and truncates.
func (s *Sanitizer) onePass(message string) string {
	result := message
	for _, rule := range s.rules {
		if rule.Category == CategoryEntropy && len(s.allowlist) > 0 {
			result = s.applyWithAllowlist(result, rule)
		} else {
			result = rule.Pattern.ReplaceAllString(result, rule.tag())
		}
	}
	result = stripNonPrintable(result)
	if s.maxLen > 0 && len(result) > s.maxLen {
		result = result[:s.maxLen] + "[REDACTED:truncated]"
	}
	return result
}

// applyWithAllowlist replaces rule's matches except those directly preceded by
// an allowlisted prefix.
func (s *Sanitizer) applyWithAllowlist(message string, rule Rule) string {
	matches := rule.Pattern.FindAllStringIndex(message, -1)
	if len(matches) == 0 {
		return message
	}
	tag := rule.tag()
	var b strings.Builder
	b.Grow(len(message))
	lastEnd := 0
	for _, loc := range matches {
		if s.isAllowlisted(message, loc[0]) {
			continue
		}
		b.WriteString(message[lastEnd:loc[0]])
		b.WriteString(tag)
		lastEnd = loc[1]
	}
	b.WriteString(message[lastEnd:])
	return b.String()
}

// isAllowlisted reports whether an allowlist pattern matches the text ending
// exactly at matchStart.
func (s *Sanitizer) isAllowlisted(message string, matchStart int) bool {
	prefix := message[:matchStart]
	for _, allow := range s.allowlist {
		if loc := allow.FindStringIndex(prefix); len(loc) >= 2 && loc[1] == matchStart {
			return true
		}
	}
	return false
}

// stripNonPrintable replaces C0/C1-range control characters (and DEL) with a
// tag, preserving valid printable UTF-8. This is the final CWE-117 backstop:
// any injection byte a rule missed cannot reach the sink intact.
func stripNonPrintable(s string) string {
	var b strings.Builder
	changed := false
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		} else {
			b.WriteString("[REDACTED:control_char]")
			changed = true
		}
	}
	if !changed {
		return s
	}
	return b.String()
}

// ── Generic default rules (provider-agnostic) ────────────────────────────────

var (
	// Tier 1: key=value credential fields (high confidence).
	passwordRe    = regexp.MustCompile(`(?i)password[=:]\s*\S+`)
	secretFieldRe = regexp.MustCompile(`(?i)secret[=:]\s*\S+`)
	tokenFieldRe  = regexp.MustCompile(`(?i)token[=:]\s*\S+`)
	apiKeyRe      = regexp.MustCompile(`(?i)\bapi[_-]?key[=:]\s*\S+`)
	authFieldRe   = regexp.MustCompile(`(?i)auth[=:]\s*\S+`)

	// Tier 2: injection neutralization (CWE-117).
	crlfRe     = regexp.MustCompile(`[\r\n]+`)
	ansiRe     = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	shellVarRe = regexp.MustCompile(`\$\{[^}]*\}`)
	shellCmdRe = regexp.MustCompile(`\$\([^)]*\)`)

	// Tier 3: high-entropy heuristic (lowest confidence, allowlist-gated).
	// Base64 requires = padding to avoid matching module paths; hex requires
	// 40+ chars to spare UUIDs (32 hex) and short container IDs.
	base64Re = regexp.MustCompile(`[a-zA-Z0-9+/]{40,}={1,2}`)
	hexRe    = regexp.MustCompile(`\b[0-9a-fA-F]{40,}\b`)
)

// DefaultRules returns the provider-agnostic rule set: key=value credential
// fields, CWE-117 injection neutralization, and high-entropy heuristics.
// Named third-party token formats are NOT included — add [CommonProviderRules]
// when your log stream carries them.
func DefaultRules() []Rule {
	return []Rule{
		{Name: "password_field", Category: CategorySecret, Pattern: passwordRe},
		{Name: "secret_field", Category: CategorySecret, Pattern: secretFieldRe},
		{Name: "token_field", Category: CategorySecret, Pattern: tokenFieldRe},
		{Name: "api_key_field", Category: CategorySecret, Pattern: apiKeyRe},
		{Name: "auth_field", Category: CategorySecret, Pattern: authFieldRe},

		{Name: "crlf_injection", Category: CategoryInjection, Pattern: crlfRe},
		{Name: "ansi_escape", Category: CategoryInjection, Pattern: ansiRe},
		{Name: "shell_variable", Category: CategoryInjection, Pattern: shellVarRe},
		{Name: "shell_command", Category: CategoryInjection, Pattern: shellCmdRe},

		{Name: "base64_secret", Category: CategoryEntropy, Pattern: base64Re},
		{Name: "hex_secret", Category: CategoryEntropy, Pattern: hexRe},
	}
}

var (
	ghpRe     = regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)
	ghoRe     = regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`)
	ghuRe     = regexp.MustCompile(`ghu_[a-zA-Z0-9]{36}`)
	ghsRe     = regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`)
	ghrRe     = regexp.MustCompile(`ghr_[a-zA-Z0-9]{36}`)
	awsAkiaRe = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	slackRe   = regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)
	pemKeyRe  = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
)

// CommonProviderRules returns rules for well-known third-party token formats
// (GitHub, AWS access-key IDs, Slack, PEM private-key headers). They are OFF
// by default — the shapes are specific enough to false-negative on unrelated
// vendors and to grow stale, so opting in is a deliberate choice:
//
//	rules := append(redact.DefaultRules(), redact.CommonProviderRules()...)
//	s := redact.NewSanitizer(rules, redact.WithAllowlist(redact.DefaultAllowlist()))
//
// The set is intentionally small and vendor-neutral; it is not a
// comprehensive secret scanner and makes no attempt to be one.
func CommonProviderRules() []Rule {
	return []Rule{
		{Name: "github_pat", Category: CategorySecret, Pattern: ghpRe},
		{Name: "github_oauth", Category: CategorySecret, Pattern: ghoRe},
		{Name: "github_user", Category: CategorySecret, Pattern: ghuRe},
		{Name: "github_server", Category: CategorySecret, Pattern: ghsRe},
		{Name: "github_refresh", Category: CategorySecret, Pattern: ghrRe},
		{Name: "aws_access_key_id", Category: CategorySecret, Pattern: awsAkiaRe},
		{Name: "slack_token", Category: CategorySecret, Pattern: slackRe},
		{Name: "pem_private_key", Category: CategorySecret, Pattern: pemKeyRe},
	}
}

// DefaultAllowlist returns prefix patterns for legitimate high-entropy strings
// that entropy rules should NOT redact — git commit hashes, container/build
// IDs, request/trace IDs, and fingerprints. These are field-name prefixes, not
// the values themselves, so they exempt only a value that directly follows a
// recognized label.
func DefaultAllowlist() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)commit[=:\s]+`),
		regexp.MustCompile(`(?i)container_id[=:\s]+`),
		regexp.MustCompile(`(?i)build_id[=:\s]+`),
		regexp.MustCompile(`(?i)request_id[=:\s]+`),
		regexp.MustCompile(`(?i)trace_id[=:\s]+`),
		regexp.MustCompile(`(?i)span_id[=:\s]+`),
		regexp.MustCompile(`(?i)fingerprint[=:\s]+`),
	}
}

// NewDefaultSanitizer builds a Sanitizer with [DefaultRules] and
// [DefaultAllowlist] — the recommended general-purpose configuration. Add
// [CommonProviderRules] to the rule set when named token formats apply.
func NewDefaultSanitizer() *Sanitizer {
	return NewSanitizer(DefaultRules(), WithAllowlist(DefaultAllowlist()))
}

// NewStrictSanitizer builds a Sanitizer with the default rules and NO
// allowlist: every entropy match is redacted, at the cost of false positives
// on legitimate hashes.
func NewStrictSanitizer() *Sanitizer {
	return NewSanitizer(DefaultRules())
}

// InjectionOnlyRules returns just the CWE-117 injection rules, for callers
// who handle secret redaction themselves but still want log-injection
// neutralization. WARNING: this redacts NO secrets — do not use it as a
// secret backstop.
func InjectionOnlyRules() []Rule {
	var out []Rule
	for _, r := range DefaultRules() {
		if r.Category == CategoryInjection {
			out = append(out, r)
		}
	}
	return out
}
