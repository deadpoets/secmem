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
//   - Every call to [Sanitizer.Sanitize] makes ordinary heap copies of the
//     UNREDACTED text on its way to the redacted one: the input string the
//     caller built, the intermediate result of each pass, and every regexp
//     scratch buffer. None of them is wiped — Go strings cannot be — so the
//     secret the sanitizer removed from the log line is still in process
//     memory until the collector reclaims those copies. This is inherent to
//     operating on strings and is the reason redact is a backstop rather than
//     a place to hold secrets.
//
//   - The default rules are deliberately GENERIC: key=value credentials
//     (password, secret, token, api_key, auth and their common spellings),
//     Authorization and Cookie header values, URL userinfo passwords and
//     credential-bearing query parameters, JWTs, bare Bearer tokens, PEM
//     private-key blocks, CWE-117 injection, and high-entropy heuristics.
//     Named third-party token formats (GitHub, GitLab, OpenAI, cloud
//     providers) live in [CommonProviderRules] and are OFF by default — bolt
//     them on when you know your log stream carries them.
//
//   - Covered: the shapes above, in plain, quoted, JSON-escaped, `=>` and
//     `%3D`-separated forms. NOT covered: a credential whose key and value
//     are separated across two log attributes (`"k", "password=", "v", "x"`);
//     a secret embedded in prose with no key and no recognizable format; a
//     low-entropy or short secret (fewer than 40 base64/hex characters) with
//     no key; a key name outside the built-in list unless you add a rule; a
//     PEM body whose header was cut off by truncation before the sanitizer
//     saw it. The [Handler] adds KEY-based redaction for structured log
//     attributes, which covers the first gap for attributes with a
//     credential-shaped key but not for a value logged under an innocent one.
//
// The package is stdlib-only and safe for concurrent use: a [Sanitizer] is
// immutable after construction.
package redact

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
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
	// Tag is the replacement. Defaults to "[REDACTED:<Name>]" when empty. It
	// is expanded with [regexp.Regexp.Expand] semantics, so "${1}" re-emits
	// the first submatch — the built-in URL rules use that to keep the part of
	// a match that is not the credential. Write "$$" for a literal dollar.
	Tag string
	// Filter, when non-nil, is consulted for every match of Pattern and the
	// match is replaced only if it returns true. It exists for heuristics a
	// regex cannot express (the built-in base64 rule uses it to require a
	// mixed-case, digit-bearing run before it will redact an unpadded one).
	// It must be safe for concurrent use.
	Filter func(match string) bool
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

// truncatedTag is appended to a message cut by [WithMaxLen].
const truncatedTag = "[REDACTED:truncated]"

// WithMaxLen caps the length of the text the rules run over and of the
// output. A message longer than n bytes is cut at n (backing up to a UTF-8
// rune boundary) BEFORE any rule runs, and the cut is suffixed with
// "[REDACTED:truncated]"; that is what bounds the work a hostile input can
// cause. The result is cut again the same way if replacement tags grew it
// past n, so the output is never longer than n plus the marker. Zero disables
// truncation. The constructor default is 4096.
func WithMaxLen(n int) Option {
	return func(s *Sanitizer) { s.maxLen = n }
}

// WithAllowlist sets patterns that exempt a [CategoryEntropy] match from
// redaction. Each pattern is matched over the whole message once; an entropy
// match is spared when an allowlist match ends exactly where it begins (a
// label such as "commit=" directly before a hash) or contains it entirely (a
// pattern that matches label and value together). Only entropy matches
// consult the allowlist.
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
// fixpoint. That matters: a replacement tag creates a word boundary, which
// can let a rule match on a later pass what it could not on the first; a
// single pass would therefore not be stable, and callers (including
// [Handler], which may see already-sanitized text) rely on re-sanitizing
// being a no-op. An over-length message is truncated before the first pass
// (see [WithMaxLen]); control characters are replaced and an over-length
// result is truncated within each pass.
func (s *Sanitizer) Sanitize(message string) string {
	if message == "" {
		return message
	}
	prev := s.truncate(message)
	for i := 0; i < maxSanitizePasses; i++ {
		cur := s.onePass(prev)
		if cur == prev {
			return cur // fixpoint reached
		}
		prev = cur
	}
	return prev
}

// truncate cuts m to maxLen bytes at a rune boundary and appends the marker.
// A string that is already a truncation result — it ends with the marker and
// the text before it fits — is left alone, which is what keeps Sanitize
// idempotent when the rune-boundary backup left the cut short of maxLen.
func (s *Sanitizer) truncate(m string) string {
	if s.maxLen <= 0 || len(m) <= s.maxLen {
		return m
	}
	if strings.HasSuffix(m, truncatedTag) && len(m)-len(truncatedTag) <= s.maxLen {
		return m
	}
	cut := s.maxLen
	for cut > 0 && !utf8.RuneStart(m[cut]) {
		cut--
	}
	return m[:cut] + truncatedTag
}

// onePass applies the rules once, strips control characters, and truncates.
func (s *Sanitizer) onePass(message string) string {
	result := message
	for _, rule := range s.rules {
		result = s.applyRule(result, rule)
	}
	result = stripNonPrintable(result)
	return s.truncate(result)
}

// applyRule replaces rule's matches in message. A rule with no Filter and no
// allowlist gating is a plain ReplaceAllString; otherwise matches are walked
// one by one and each is kept or replaced on its own merits.
func (s *Sanitizer) applyRule(message string, rule Rule) string {
	gated := rule.Category == CategoryEntropy && len(s.allowlist) > 0
	tag := rule.tag()
	if !gated && rule.Filter == nil {
		return rule.Pattern.ReplaceAllString(message, tag)
	}
	matches := rule.Pattern.FindAllStringSubmatchIndex(message, -1)
	if len(matches) == 0 {
		return message
	}
	// The allowlist is indexed ONCE per rule application. It used to be
	// re-scanned over message[:matchStart] for every match, which made a
	// message with many entropy matches quadratic: 200 KB took over twenty
	// seconds on the default configuration.
	var allow allowIndex
	if gated {
		allow = s.indexAllowlist(message)
	}
	out := make([]byte, 0, len(message))
	lastEnd := 0
	for _, m := range matches {
		if gated && allow.exempts(m[0], m[1]) {
			continue
		}
		if rule.Filter != nil && !rule.Filter(message[m[0]:m[1]]) {
			continue
		}
		out = append(out, message[lastEnd:m[0]]...)
		out = rule.Pattern.ExpandString(out, tag, message, m)
		lastEnd = m[1]
	}
	out = append(out, message[lastEnd:]...)
	return string(out)
}

// allowIndex answers "is this span exempt?" for every entropy match of one
// rule application from a single scan of the allowlist patterns.
type allowIndex struct {
	ends   []int // every allowlist match end, sorted
	starts []int // every allowlist match start, sorted
	maxEnd []int // maxEnd[i] = max end over starts[0..i]
}

// indexAllowlist runs every allowlist pattern over message once and builds
// the index. Cost is one FindAllStringIndex per pattern, independent of how
// many entropy matches will consult it.
func (s *Sanitizer) indexAllowlist(message string) allowIndex {
	type span struct{ start, end int }
	var spans []span
	for _, allow := range s.allowlist {
		for _, loc := range allow.FindAllStringIndex(message, -1) {
			spans = append(spans, span{loc[0], loc[1]})
		}
	}
	if len(spans) == 0 {
		return allowIndex{}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	idx := allowIndex{
		ends:   make([]int, len(spans)),
		starts: make([]int, len(spans)),
		maxEnd: make([]int, len(spans)),
	}
	for i, sp := range spans {
		idx.ends[i] = sp.end
		idx.starts[i] = sp.start
		if i == 0 || sp.end > idx.maxEnd[i-1] {
			idx.maxEnd[i] = sp.end
		} else {
			idx.maxEnd[i] = idx.maxEnd[i-1]
		}
	}
	sort.Ints(idx.ends)
	return idx
}

// exempts reports whether the match [start, end) is spared: an allowlist
// match ends exactly at start, or one contains the whole span.
func (a allowIndex) exempts(start, end int) bool {
	if len(a.ends) == 0 {
		return false
	}
	if i := sort.SearchInts(a.ends, start); i < len(a.ends) && a.ends[i] == start {
		return true
	}
	// Containment: some span with span.start <= start has span.end >= end.
	// starts is sorted, so the candidates are a prefix, and maxEnd over that
	// prefix answers the question in one lookup.
	i := sort.SearchInts(a.starts, start+1) - 1 // last span starting at or before start
	return i >= 0 && a.maxEnd[i] >= end
}

// stripNonPrintable replaces C0/C1-range control characters, DEL, and bytes
// that are not valid UTF-8 with a tag, preserving valid printable UTF-8. This
// is the final CWE-117 backstop: any injection byte a rule missed cannot reach
// the sink intact.
//
// The C1 range (U+0080–U+009F) is the half this used to miss while claiming to
// cover it. `r >= 32 && r != 127` passes every C1 code point, and C1 carries
// real terminal control — most notably U+009B, the single-character CSI, which
// a terminal decoding the output as ISO-2022/Latin-1 treats exactly as the
// two-byte ESC-[ sequence the ansi rule strips. A backstop that lets the
// alternate spelling through is not a backstop.
//
// Invalid UTF-8 is handled explicitly rather than left to range's implicit
// U+FFFD substitution, so a raw injection byte is reported as redacted instead
// of silently becoming a replacement character.
func stripNonPrintable(s string) string {
	var b strings.Builder
	changed := false
	for i, r := range s {
		if r == utf8.RuneError {
			// range yields RuneError both for a real U+FFFD and for an invalid
			// byte; width 1 distinguishes the invalid byte.
			if _, w := utf8.DecodeRuneInString(s[i:]); w == 1 {
				b.WriteString("[REDACTED:invalid_utf8]")
				changed = true
				continue
			}
		}
		if r < 32 || r == 127 || (r >= 0x80 && r <= 0x9f) {
			b.WriteString("[REDACTED:control_char]")
			changed = true
			continue
		}
		b.WriteRune(r)
	}
	if !changed {
		return s
	}
	return b.String()
}

// ── Credential field grammar ────────────────────────────────────────────────

// credSep is what may stand between a credential key and its value: an
// optional closing quote on the key (plain or JSON-escaped), then "=", ":",
// "=>" or the URL-encoded "%3D"/"%3A", with whitespace on either side.
const credSep = `(?:\\?")?\s*(?:=>|[=:]|%3[dDaA])\s*` //nolint:gosec // G101: a regex naming credential KEYS, not a credential

// credValue is the value part. The alternation is ordered so a quoted literal
// is consumed whole — a JSON-escaped one (\"...\") first, then a plain
// double- or single-quoted one — before falling back to a run of
// non-whitespace. \S+ stops at the first space, which is what used to leave
// ` 2"` behind from password="hunter 2".
//
// The escaped-quoted alternative stops at the first \" so that one value in
// an escaped JSON document does not swallow every field after it.
const credValue = `(?:\\"(?:[^"\\]|\\[^"])*\\"|"(?:[^"\\]|\\.)*"|'[^']*'|\S+)` //nolint:gosec // G101: a regex naming credential KEYS, not a credential

// credRe builds the matcher for one key=value credential field. field is a
// regex fragment for the key name(s); it is applied case-insensitively.
//
// A key is deliberately NOT anchored at a word boundary in general, because
// the common spellings glue a qualifier on with an underscore (client_secret,
// access_token, DB_PASSWORD) and "_" is a word character. The short names
// that would otherwise fire inside ordinary words (pass, pwd, key, bearer)
// carry their own `(?:\b|_)` guard.
func credRe(field string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)` + field + credSep + credValue)
}

// Key-name alternations for the key=value tier. Longest spelling first so
// the tag says what was matched, though the overall match would be found
// either way.
const (
	passwordNames = `(?:password|passwd|passphrase|(?:\b|_)pass|(?:\b|_)pwd)`
	secretNames   = `(?:secret(?:[_-]?access)?(?:[_-]?key)?|(?:\b|_)private[_-]?key|(?:\b|_)signing[_-]?key|credentials?)` //nolint:gosec // G101: a regex naming credential KEYS, not a credential
	tokenNames    = `(?:token|(?:\b|_)bearer)`                                                                             //nolint:gosec // G101: a regex naming credential KEYS, not a credential
	apiKeyNames   = `(?:\b|_)api[_-]?key`                                                                                  //nolint:gosec // G101: a regex naming credential KEYS, not a credential
	authNames     = `auth`
)

// ── Generic default rules (provider-agnostic) ────────────────────────────────

var (
	// Tier 0: a PEM private-key block, header through footer, as one match.
	// This must run before the CRLF rule: with the line breaks already
	// replaced by tags the block is no longer contiguous, and only its header
	// line was being redacted while every base64 body line went through. A
	// block whose footer is missing (cut off by truncation) still has its
	// header tagged, and the body lines are left to the entropy rules.
	pemKeyRe = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)?`)

	// Tier 1: header and URL forms. The Authorization value is "<scheme>
	// <credential>" — the old auth rule needed "=" or ":" right after "auth"
	// and so never saw "Authorization: Bearer ..." or "Basic ..." at all.
	authorizationRe = regexp.MustCompile(`(?i)(?:\b|_)(?:proxy[_-])?authorization` + credSep +
		`(?:\\"(?:[^"\\]|\\[^"])*\\"|"(?:[^"\\]|\\.)*"|'[^']*'|(?:[a-z0-9_-]+\s+)?\S+)`)
	cookieRe = regexp.MustCompile(`(?i)(?:\b|_)(?:set[_-])?cookies?` + credSep +
		`(?:\\"(?:[^"\\]|\\[^"])*\\"|"(?:[^"\\]|\\.)*"|'[^']*'|[^\s;]+(?:;\s*[^\s;]+)*)`)
	// userinfo password: scheme://user:PASSWORD@host. Group 1 (scheme, user
	// and the colon) is re-emitted by the tag so the URL stays readable.
	urlPasswordRe = regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://[^\s/?#@:]*:)[^\s/?#@]+@`)
	// Query parameters that carry a credential; "code" is an OAuth
	// authorization code, "key" a bare API key, "sig"/"signature" a signed
	// URL's proof. Group 1 (separator and name) is re-emitted.
	urlQueryRe = regexp.MustCompile(`(?i)([?&](?:code|token|access_token|id_token|refresh_token|` +
		`client_secret|secret|password|passwd|pwd|api_key|apikey|key|sig|signature|` +
		`x-amz-signature|x-amz-security-token|auth|authorization)=)[^\s&#"']+`)

	// Tier 1: key=value credential fields (high confidence). Built by credRe
	// so the quoting rules stay identical across all of them.
	passwordRe    = credRe(passwordNames)
	secretFieldRe = credRe(secretNames)
	tokenFieldRe  = credRe(tokenNames)
	apiKeyRe      = credRe(apiKeyNames)
	authFieldRe   = credRe(authNames)

	// Tier 1: standard token formats with no vendor. A JWT is three
	// base64url segments, the first two of which are JSON objects and so
	// start with "eyJ". A bare "Bearer <token>" outside an Authorization
	// header needs 20+ token characters so "Bearer authentication" in prose
	// is left alone.
	jwtRe    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	bearerRe = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}`)

	// Tier 2: injection neutralization (CWE-117).
	crlfRe     = regexp.MustCompile(`[\r\n]+`)
	ansiRe     = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	shellVarRe = regexp.MustCompile(`\$\{[^}]*\}`)
	shellCmdRe = regexp.MustCompile(`\$\([^)]*\)`)

	// Tier 3: high-entropy heuristic (lowest confidence, allowlist-gated).
	// The base64 class admits the base64url alphabet and no longer requires
	// "=" padding — JWT segments, base64url tokens and most modern API keys
	// are unpadded — so [looksLikeBase64Secret] does the false-positive
	// screening the padding requirement used to. Hex requires 40+ chars to
	// spare UUIDs (32 hex) and short container IDs, and accepts a 0x prefix:
	// \b does not fall between "x" and a hex digit, so "0x" + 64 hex was
	// never matched.
	base64Re = regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}={0,2}`)
	hexRe    = regexp.MustCompile(`\b(?:0[xX])?[0-9a-fA-F]{40,}\b`)
)

// looksLikeBase64Secret is the [Rule.Filter] for the base64 entropy rule. A
// padded run is redacted unconditionally, as before. An unpadded run must
// contain a digit, an upper-case and a lower-case letter: random base64 of
// 40+ characters fails that with probability around 1e-3 (the digit is the
// scarce class), while the false positives the padding requirement guarded
// against — file paths, module paths, long snake_case or CamelCase
// identifiers, separator lines of dashes — almost never satisfy all three.
func looksLikeBase64Secret(m string) bool {
	if strings.HasSuffix(m, "=") {
		return true
	}
	var digit, upper, lower bool
	for i := 0; i < len(m); i++ {
		switch c := m[i]; {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		}
		if digit && upper && lower {
			return true
		}
	}
	return false
}

// DefaultRules returns the provider-agnostic rule set: PEM private-key
// blocks, Authorization and Cookie headers, URL userinfo and query
// credentials, key=value credential fields, JWTs and bare Bearer tokens,
// CWE-117 injection neutralization, and high-entropy heuristics. Named
// third-party token formats are NOT included — add [CommonProviderRules]
// when your log stream carries them.
func DefaultRules() []Rule {
	return []Rule{
		{Name: "pem_private_key", Category: CategorySecret, Pattern: pemKeyRe},

		{Name: "authorization_header", Category: CategorySecret, Pattern: authorizationRe},
		{Name: "cookie_header", Category: CategorySecret, Pattern: cookieRe},
		{Name: "url_password", Category: CategorySecret, Pattern: urlPasswordRe, Tag: "${1}[REDACTED:url_password]@"},

		{Name: "password_field", Category: CategorySecret, Pattern: passwordRe},
		{Name: "secret_field", Category: CategorySecret, Pattern: secretFieldRe},
		{Name: "token_field", Category: CategorySecret, Pattern: tokenFieldRe},
		{Name: "api_key_field", Category: CategorySecret, Pattern: apiKeyRe},
		{Name: "auth_field", Category: CategorySecret, Pattern: authFieldRe},
		{Name: "url_query_credential", Category: CategorySecret, Pattern: urlQueryRe, Tag: "${1}[REDACTED:url_query_credential]"},

		{Name: "jwt", Category: CategorySecret, Pattern: jwtRe},
		{Name: "bearer_token", Category: CategorySecret, Pattern: bearerRe},

		{Name: "crlf_injection", Category: CategoryInjection, Pattern: crlfRe},
		{Name: "ansi_escape", Category: CategoryInjection, Pattern: ansiRe},
		{Name: "shell_variable", Category: CategoryInjection, Pattern: shellVarRe},
		{Name: "shell_command", Category: CategoryInjection, Pattern: shellCmdRe},

		{Name: "base64_secret", Category: CategoryEntropy, Pattern: base64Re, Filter: looksLikeBase64Secret},
		{Name: "hex_secret", Category: CategoryEntropy, Pattern: hexRe},
	}
}

var (
	ghpRe       = regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)
	ghoRe       = regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`)
	ghuRe       = regexp.MustCompile(`ghu_[a-zA-Z0-9]{36}`)
	ghsRe       = regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`)
	ghrRe       = regexp.MustCompile(`ghr_[a-zA-Z0-9]{36}`)
	githubPatRe = regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{22,}`)
	gitlabPatRe = regexp.MustCompile(`glpat-[a-zA-Z0-9_-]{20,}`)
	openAIRe    = regexp.MustCompile(`\bsk-(?:[a-z]+-)*[a-zA-Z0-9_-]{20,}`)
	awsKeyIDRe  = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	// The secret half of an AWS key pair, keyed by its conventional name. The
	// generic secret_field rule catches the same text when both sets are in
	// use; this one is for a rule set assembled without DefaultRules.
	awsSecretRe = regexp.MustCompile(`(?i)(?:aws[_-]?)?secret[_-]?access[_-]?key` + credSep + `(?:\\?"|')?[A-Za-z0-9/+]{40}`)
	slackRe     = regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)
)

// CommonProviderRules returns rules for well-known third-party token formats
// (GitHub classic and fine-grained PATs, GitLab PATs, OpenAI-style "sk-"
// keys, AWS access-key IDs and secret keys, Slack). They are OFF by default —
// the shapes are specific enough to false-negative on unrelated vendors and
// to grow stale, so opting in is a deliberate choice:
//
//	rules := append(redact.CommonProviderRules(), redact.DefaultRules()...)
//	s := redact.NewSanitizer(rules, redact.WithAllowlist(redact.DefaultAllowlist()))
//
// Put them FIRST: the default base64 heuristic no longer needs "=" padding,
// so a real provider token is usually caught by it too — redacted either
// way, but tagged "base64_secret" rather than by name if the entropy rule
// gets there first.
//
// The set is intentionally limited to a few ubiquitous formats; it is not a
// comprehensive secret scanner and makes no attempt to be one. PEM
// private-key blocks are vendor-neutral and live in [DefaultRules].
func CommonProviderRules() []Rule {
	return []Rule{
		{Name: "github_pat", Category: CategorySecret, Pattern: ghpRe},
		{Name: "github_oauth", Category: CategorySecret, Pattern: ghoRe},
		{Name: "github_user", Category: CategorySecret, Pattern: ghuRe},
		{Name: "github_server", Category: CategorySecret, Pattern: ghsRe},
		{Name: "github_refresh", Category: CategorySecret, Pattern: ghrRe},
		{Name: "github_fine_grained_pat", Category: CategorySecret, Pattern: githubPatRe},
		{Name: "gitlab_pat", Category: CategorySecret, Pattern: gitlabPatRe},
		{Name: "openai_key", Category: CategorySecret, Pattern: openAIRe},
		{Name: "aws_access_key_id", Category: CategorySecret, Pattern: awsKeyIDRe},
		{Name: "aws_secret_access_key", Category: CategorySecret, Pattern: awsSecretRe},
		{Name: "slack_token", Category: CategorySecret, Pattern: slackRe},
	}
}

// DefaultAllowlist returns prefix patterns for legitimate high-entropy strings
// that entropy rules should NOT redact — git commit hashes, content digests,
// container/build IDs, request/trace IDs, and fingerprints. These are
// field-name prefixes, not the values themselves, so they exempt only a value
// that directly follows a recognized label.
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
