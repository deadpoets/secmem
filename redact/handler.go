package redact

import (
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"unicode"
)

// Handler wraps an [slog.Handler] and runs every record through a
// [Sanitizer] before forwarding. It is the automatic, whole-logger form of
// redaction: install it once and every log line is scrubbed, so a stray
// secret in a format string or an error value is masked at the boundary
// instead of hitting the sink.
//
// Two independent mechanisms apply to each attribute:
//
//   - KEY-based: an attribute whose key is credential-shaped (see
//     [DefaultSensitiveKeys]) has its value replaced wholesale with
//     "[REDACTED:key]", whatever the value's kind — string, []byte, number,
//     group, LogValuer, Any. A group whose own name is sensitive is replaced
//     as a whole; so is everything beneath a [Handler.WithGroup] name that
//     is. The key is compared case-insensitively, as a whole and as
//     components split on "_", "-", ".", "/", ":", space, digit runs and
//     CamelCase boundaries, so "DB_PASSWORD", "db.password", "accessToken"
//     and "x-api-key" all match; a multi-component entry such as "api_key"
//     matches the same components across an enclosing group ("api" group,
//     "key" key). A sensitive LogValuer is not resolved. Extend the set with
//     [WithSensitiveKeys]; drop the defaults with
//     [WithoutDefaultSensitiveKeys].
//
//   - VALUE-based: the message and every string-shaped value go through the
//     Sanitizer. A [slog.KindAny] value is rendered to text first, in a
//     %+v-like form, by a reflection walk that applies the key set to struct
//     field names and map keys along the way and treats []byte as text; the
//     sanitized rendering is then emitted as ONE STRING attribute. The
//     structured shape of an Any value is therefore lost at the sink — a
//     JSON handler writes a string where it used to write an object or an
//     array, and a []byte is written as text rather than base64. That trade
//     is deliberate: a struct or map passed through untouched carried its
//     secrets straight to the sink in both text and JSON output.
//
//     The walk follows the pointers it can Interface() at every depth,
//     which is more than fmt does (fmt prints a nested pointer as an
//     address), because a secret two structs down is still a secret. Where
//     it can call them it honours a value's own rendering methods as fmt's
//     %v does — [fmt.Formatter], error, [fmt.Stringer] — plus
//     [encoding.TextMarshaler]; a [slog.LogValuer] is resolved at the
//     attribute level before the walk. It cannot call methods on a value
//     reached through an UNEXPORTED field, so there it does two things fmt
//     does too: a pointer is printed as "<ptr>" and not followed, and a
//     value whose type has any such method (or GoString, LogValue,
//     MarshalJSON) is not walked into either — it is replaced by
//     "[REDACTED:unexported]". A type that redacts itself in print —
//     secmem's SecureBuffer, Secret and ArenaSlot among them — is
//     therefore never taken apart field by field, whichever way it was
//     reached, and neither is anything behind an unexported pointer.
//     (Before these rules the walk did take them apart: it printed the
//     buffer's bytes, then read into the guard page and faulted.) The one
//     shape left is the one fmt shares: a defined type over such a struct
//     ("type mine secmem.SecureBuffer") has no methods, and held BY VALUE
//     in a nested struct it is a plain struct to the walk and to fmt alike.
//     Rendering stops at a fixed size, so a very large value costs a
//     bounded amount of text before the Sanitizer truncates it.
//
// Same honesty caveat as the package: this reduces blast radius, it does not
// guarantee no secret ever escapes. What it cannot see: a credential split
// across two attributes ("k", "password=", "v", "hunter2" — neither key is
// sensitive and neither value is credential-shaped on its own); a secret
// under an innocent key with no recognizable shape; whatever the inner
// handler's own ReplaceAttr or a custom Marshaler adds after this handler
// is done. Prefer [secmem.Secret] for values you hold; use Handler as the
// backstop.
type Handler struct {
	inner     slog.Handler
	sanitizer *Sanitizer
	keys      *keySet
	// path holds the split, lower-cased components of every open WithGroup
	// name, outermost first; redactAll is set once any of them was sensitive.
	path      []string
	redactAll bool
}

// HandlerOption configures a [Handler].
type HandlerOption func(*handlerConfig)

type handlerConfig struct {
	keys       []string
	noDefaults bool
}

// WithSensitiveKeys adds keys to the set whose values [Handler] redacts
// wholesale. Each entry is matched like the defaults: case-insensitively, as
// a whole key or as a run of "_"/"-"/"."-separated (or CamelCase) components.
func WithSensitiveKeys(keys ...string) HandlerOption {
	return func(c *handlerConfig) { c.keys = append(c.keys, keys...) }
}

// WithoutDefaultSensitiveKeys drops [DefaultSensitiveKeys] so that only keys
// added with [WithSensitiveKeys] are redacted by key. Value-based
// sanitization is unaffected.
func WithoutDefaultSensitiveKeys() HandlerOption {
	return func(c *handlerConfig) { c.noDefaults = true }
}

// keyTag replaces the value of an attribute whose key is sensitive.
const keyTag = "[REDACTED:key]"

// DefaultSensitiveKeys returns the attribute keys whose values [Handler]
// redacts by default. Each is matched as a whole key or as a component of
// one, so "password" also covers "db_password", "user.password" and
// "adminPassword"; "api_key" covers "x-api-key" and "OPENAI_API_KEY".
func DefaultSensitiveKeys() []string {
	return []string{
		"password", "passwd", "pwd", "pass", "passphrase", "passcode",
		"secret", "secret_key", "client_secret", "api_secret",
		"token", "access_token", "refresh_token", "id_token", "session_token", "jwt",
		"api_key", "apikey", "x_api_key",
		"authorization", "auth", "bearer",
		"cookie", "set_cookie", "session",
		"private_key", "privatekey", "signing_key", "secret_access_key",
		"credential", "credentials",
	}
}

// NewHandler wraps inner so all output is sanitized by s. A nil inner discards
// output; a nil s uses [NewDefaultSanitizer]. opts adjust the sensitive key
// set.
func NewHandler(inner slog.Handler, s *Sanitizer, opts ...HandlerOption) *Handler {
	if inner == nil {
		inner = discardHandler{}
	}
	if s == nil {
		s = NewDefaultSanitizer()
	}
	var cfg handlerConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	var names []string
	if !cfg.noDefaults {
		names = DefaultSensitiveKeys()
	}
	names = append(names, cfg.keys...)
	return &Handler{inner: inner, sanitizer: s, keys: newKeySet(names)}
}

// Enabled delegates to the inner handler.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle sanitizes the record's message and inline attributes and forwards to
// the inner handler. WithAttrs attributes are NOT re-added here — they were
// handed to the inner handler when WithAttrs was called, which is what keeps
// them outside any group opened afterwards.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	clean := slog.NewRecord(r.Time, r.Level, h.sanitizer.Sanitize(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(h.sanitizeAttr(h.path, h.redactAll, a))
		return true
	})
	return h.inner.Handle(ctx, clean)
}

// WithAttrs pre-sanitizes attrs once, so repeated records do not re-scan them,
// and hands them straight to the inner handler.
//
// Holding them locally and re-adding them to every record — which is what this
// used to do — misfiles them into any group opened later. slog's contract is
// positional: attributes added before WithGroup belong OUTSIDE that group, but a
// record attribute is emitted by the inner handler at whatever nesting it has
// reached by then, so
//
//	log.With("req", id).WithGroup("db").Info("query", "table", t)
//
// produced {"db":{"req":...,"table":...}} instead of {"req":...,"db":{"table":...}}.
// Delegating to inner.WithAttrs pins each attribute at the nesting level it was
// added at, which is the inner handler's job and not something this wrapper
// should be re-deciding.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	sanitized := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		sanitized[i] = h.sanitizeAttr(h.path, h.redactAll, a)
	}
	return &Handler{
		inner:     h.inner.WithAttrs(sanitized),
		sanitizer: h.sanitizer,
		keys:      h.keys,
		path:      h.path,
		redactAll: h.redactAll,
	}
}

// WithGroup opens a group on the inner handler. The group name becomes part
// of the key path used for key-based redaction: a sensitive name redacts
// every attribute beneath it, and a multi-component entry may match across
// the group name and an attribute key.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	comps := splitKey(name)
	path := appendPath(h.path, comps)
	return &Handler{
		inner:     h.inner.WithGroup(name),
		sanitizer: h.sanitizer,
		keys:      h.keys,
		path:      path,
		redactAll: h.redactAll || h.keys.match(path, len(comps)),
	}
}

// sanitizeAttr sanitizes one attribute recursively. path is the key path of
// the enclosing groups; redactAll means an enclosing group was sensitive.
//
// The key is checked first, whatever the value: a sensitive key replaces the
// entire value, including a group (as a whole) and a LogValuer (unresolved).
// Otherwise string values are scrubbed directly; groups are scrubbed
// element-wise with the group name added to the path; an error value is
// scrubbed via its Error() string; a [slog.LogValuer] is resolved first so a
// lazily-built string is still caught; any other Any value is rendered by
// [Handler.render] and scrubbed as text. Numeric, bool, time, and duration
// values pass through untouched.
func (h *Handler) sanitizeAttr(path []string, redactAll bool, a slog.Attr) slog.Attr {
	comps := splitKey(a.Key)
	full := appendPath(path, comps)
	if redactAll || h.keys.match(full, len(comps)) {
		return slog.Attr{Key: a.Key, Value: slog.StringValue(keyTag)}
	}
	switch a.Value.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(h.sanitizer.Sanitize(a.Value.String()))
	case slog.KindGroup:
		// An empty key is an inline group: slog flattens its members into
		// the enclosing level, so full == path and the members inherit it.
		src := a.Value.Group()
		out := make([]slog.Attr, len(src))
		for i, ga := range src {
			out[i] = h.sanitizeAttr(full, false, ga)
		}
		a.Value = slog.GroupValue(out...)
	case slog.KindLogValuer:
		return h.sanitizeAttr(path, redactAll, slog.Attr{Key: a.Key, Value: a.Value.Resolve()})
	case slog.KindAny:
		v := a.Value.Any()
		if v == nil {
			return a
		}
		a.Value = slog.StringValue(h.sanitizer.Sanitize(h.render(v, full)))
	default:
		// Numeric, bool, duration, time — nothing string-shaped to redact.
	}
	return a
}

// appendPath returns path + comps in a fresh slice, so a child's extension
// never aliases a sibling's.
func appendPath(path, comps []string) []string {
	if len(comps) == 0 {
		return path
	}
	out := make([]string, 0, len(path)+len(comps))
	out = append(out, path...)
	return append(out, comps...)
}

// ── Any rendering ───────────────────────────────────────────────────────────

// renderCap bounds the text produced for one Any value. Sanitize truncates
// at its own maxLen afterwards; the cap only keeps a huge slice from being
// rendered in full first. Every write into the builder goes through
// capWriter, so a single []byte, String() or MarshalText result larger than
// the cap is cut too, not only the sum of many small ones.
const renderCap = 1 << 16

// maxRenderDepth bounds pointer and container nesting, which also breaks
// cycles.
const maxRenderDepth = 8

// unexportedTag replaces a value the walk may not take apart: one reached
// through an unexported field whose type renders itself (see selfRendering).
const unexportedTag = "[REDACTED:unexported]"

// capWriter is the builder behind an io.Writer that discards everything past
// renderCap. It reports the full length written so fmt never sees an error.
type capWriter struct{ b *strings.Builder }

func (w capWriter) Write(p []byte) (int, error) {
	n := len(p)
	if room := renderCap - w.b.Len(); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		w.b.Write(p)
	}
	return n, nil
}

// panicTag replaces a value whose own rendering method panicked.
const panicTag = "[REDACTED:panic]"

// callGuarded runs call, which invokes a method of the value rv holds, and
// recovers a panic from it as fmt and slog's own handlers do: a logging call
// must not take the program down because a value's method did. It reports
// whether call returned normally. After a panic it has written the stand-in —
// "<nil>" for a nil pointer, whose value-receiver method panics on the
// dereference, and panicTag otherwise — and the value must not be walked
// instead: its type asked to render itself.
func callGuarded(b *strings.Builder, rv reflect.Value, call func()) (ok bool) {
	defer func() {
		if recover() == nil {
			return
		}
		if rv.Kind() == reflect.Pointer && rv.IsNil() {
			b.WriteString("<nil>")
		} else {
			b.WriteString(panicTag)
		}
	}()
	call()
	return true
}

// selfRenderingTypes are the interfaces through which fmt, slog and the
// encoders let a value control its own textual form. A value implementing
// one has said how it wants to appear — for a secret-holding type, that is
// "[REDACTED]" — and rendering its fields instead would override that.
//
//nolint:gochecknoglobals // fixed interface table, read-only.
var selfRenderingTypes = [...]reflect.Type{
	reflect.TypeFor[fmt.Formatter](),
	reflect.TypeFor[fmt.Stringer](),
	reflect.TypeFor[fmt.GoStringer](),
	reflect.TypeFor[error](),
	reflect.TypeFor[slog.LogValuer](),
	reflect.TypeFor[encoding.TextMarshaler](),
	reflect.TypeFor[json.Marshaler](),
}

// selfRendering reports whether t, or a pointer to it, implements one of
// selfRenderingTypes. Checked at the TYPE level, so it answers for a value the
// walk cannot Interface(): the method set is a property of the type, not of
// how the value was reached.
//
// Pointer-to-t is included because Go promotes value-receiver methods into
// the pointer method set and a field of type T is addressable inside its
// struct, so fmt would find the method on &field; the walk mirrors that.
func selfRendering(t reflect.Type) bool {
	for _, it := range selfRenderingTypes {
		if t.Implements(it) {
			return true
		}
		if t.Kind() != reflect.Pointer && t.Kind() != reflect.Interface && reflect.PointerTo(t).Implements(it) {
			return true
		}
	}
	return false
}

// render produces a %+v-like text form of v with the key set applied to
// struct field names and map keys (as components appended to path), []byte
// treated as text, and error/Stringer/TextMarshaler honoured where fmt and
// slog would honour them. The result is meant for the Sanitizer, not for
// round-tripping.
func (h *Handler) render(v any, path []string) string {
	var b strings.Builder
	h.renderValue(&b, reflect.ValueOf(v), path, 0)
	return b.String()
}

func (h *Handler) renderValue(b *strings.Builder, rv reflect.Value, path []string, depth int) {
	if b.Len() > renderCap {
		return
	}
	if !rv.IsValid() {
		b.WriteString("<nil>")
		return
	}
	if depth > maxRenderDepth {
		b.WriteString("...")
		return
	}
	w := capWriter{b}
	if rv.CanInterface() {
		switch x := rv.Interface().(type) {
		case []byte:
			_, _ = w.Write(x)
			return
		case fmt.Formatter, error, fmt.Stringer:
			// What fmt's %v honours, in fmt's order: Format first, then Error
			// and String. Through fmt rather than a direct call, because fmt
			// recovers a panicking method and this would not.
			_, _ = fmt.Fprint(w, x)
			return
		case encoding.TextMarshaler:
			var text []byte
			var err error
			if !callGuarded(b, rv, func() { text, err = x.MarshalText() }) {
				return
			}
			if err == nil {
				_, _ = w.Write(text)
				return
			}
		}
	} else if selfRendering(rv.Type()) {
		// Reached through an unexported field, so none of the methods above
		// can be called — and the type has one, so it must not be taken
		// apart instead. This is what keeps a *secmem.SecureBuffer (whose
		// Format redacts, and whose fields are slices over guarded, possibly
		// PROT_NONE memory) or a secmem.Secret in an unexported field from
		// being printed byte by byte, or faulting on the guard page, by the
		// very handler installed to stop secrets reaching the log.
		b.WriteString(unexportedTag)
		return
	}
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			b.WriteString("<nil>")
			return
		}
		if rv.Kind() == reflect.Pointer && !rv.CanInterface() {
			// fmt's own rule for a nested pointer, applied to the pointers
			// this walk cannot Interface(): print a marker, do not follow.
			// The pointee's methods cannot be called from here, so a type
			// that would redact itself cannot; and a pointee whose fields are
			// views over guarded memory — a *SecureBuffer with its methods
			// stripped by a type definition — would be taken apart and read
			// into its guard page. Exported pointers are still followed,
			// because there the pointee's methods can be honoured and a
			// secret two structs down is still a secret. fmt prints an
			// address here; the marker carries no information at all.
			b.WriteString("<ptr>")
			return
		}
		if rv.Kind() == reflect.Pointer && rv.Elem().Kind() == reflect.Struct {
			b.WriteByte('&')
		}
		h.renderValue(b, rv.Elem(), path, depth+1)
	case reflect.Struct:
		b.WriteByte('{')
		t := rv.Type()
		for i := 0; i < rv.NumField(); i++ {
			if i > 0 {
				b.WriteByte(' ')
			}
			name := t.Field(i).Name
			b.WriteString(name)
			b.WriteByte(':')
			h.renderField(b, name, rv.Field(i), path, depth)
		}
		b.WriteByte('}')
	case reflect.Map:
		b.WriteString("map[")
		keys := rv.MapKeys()
		names := make([]string, len(keys))
		for i, k := range keys {
			names[i] = fmt.Sprint(k)
		}
		order := make([]int, len(keys))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(i, j int) bool { return names[order[i]] < names[order[j]] })
		for n, i := range order {
			if n > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(names[i])
			b.WriteByte(':')
			h.renderField(b, names[i], rv.MapIndex(keys[i]), path, depth)
		}
		b.WriteByte(']')
	case reflect.Slice, reflect.Array:
		b.WriteByte('[')
		for i := 0; i < rv.Len(); i++ {
			if i > 0 {
				b.WriteByte(' ')
			}
			h.renderValue(b, rv.Index(i), path, depth+1)
			if b.Len() > renderCap {
				break
			}
		}
		b.WriteByte(']')
	default:
		// fmt prints the value a reflect.Value holds, unexported or not.
		// Through the capped writer: a string field is the most common
		// carrier of large text, and the cap must bound it too.
		_, _ = fmt.Fprint(w, rv)
	}
}

// renderField renders a named member (struct field or map entry), redacting
// it wholesale when the name — as components on top of path — is sensitive.
func (h *Handler) renderField(b *strings.Builder, name string, rv reflect.Value, path []string, depth int) {
	comps := splitKey(name)
	full := appendPath(path, comps)
	if h.keys.match(full, len(comps)) {
		b.WriteString(keyTag)
		return
	}
	h.renderValue(b, rv, full, depth+1)
}

// ── Sensitive key matching ──────────────────────────────────────────────────

// keySet is the compiled sensitive-key list: each entry split into
// lower-cased components.
type keySet struct {
	entries [][]string
}

func newKeySet(names []string) *keySet {
	ks := &keySet{}
	for _, n := range names {
		if comps := splitKey(n); len(comps) > 0 {
			ks.entries = append(ks.entries, comps)
		}
	}
	return ks
}

// match reports whether some entry occurs as a contiguous run of components
// in path that overlaps the last keyComps components — the key's own. The
// components before those belong to enclosing groups, which were judged on
// their own when they were opened; they take part here only so that a
// multi-component entry can span a group name and a key.
func (ks *keySet) match(path []string, keyComps int) bool {
	if ks == nil || keyComps == 0 || len(path) == 0 {
		return false
	}
	keyStart := len(path) - keyComps
	for _, e := range ks.entries {
		if len(e) > len(path) {
			continue
		}
		// The run must reach into the key: its end lies past keyStart.
		for i := max(0, keyStart-len(e)+1); i+len(e) <= len(path); i++ {
			if equalComps(path[i:i+len(e)], e) {
				return true
			}
		}
	}
	return false
}

func equalComps(a, b []string) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// splitKey lower-cases key and splits it into components on "_", "-", ".",
// "/", ":", whitespace, letter/digit boundaries and CamelCase boundaries
// ("accessToken" → access, token; "HTTPPassword" → http, password).
func splitKey(key string) []string {
	if key == "" {
		return nil
	}
	runes := []rune(key)
	var comps []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			comps = append(comps, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == '.' || r == '/' || r == ':' || unicode.IsSpace(r):
			flush()
			continue
		case i > 0 && len(cur) > 0:
			prev := runes[i-1]
			switch {
			case unicode.IsDigit(r) != unicode.IsDigit(prev):
				flush()
			case unicode.IsUpper(r) && unicode.IsLower(prev):
				flush()
			case unicode.IsUpper(r) && unicode.IsUpper(prev) && i+1 < len(runes) && unicode.IsLower(runes[i+1]):
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return comps
}

// discardHandler is a minimal slog.Handler that drops everything.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (h discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h discardHandler) WithGroup(string) slog.Handler           { return h }
