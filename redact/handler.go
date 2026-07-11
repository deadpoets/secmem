package redact

import (
	"context"
	"log/slog"
)

// Handler wraps an [slog.Handler] and runs every record's message and string
// attributes through a [Sanitizer] before forwarding. It is the automatic,
// whole-logger form of redaction: install it once and every log line is
// scrubbed, so a stray secret in a format string or an error value is masked
// at the boundary instead of hitting the sink.
//
// Same honesty caveat as the package: this reduces blast radius, it does not
// guarantee no secret ever escapes. It sanitizes strings; a secret placed in
// a non-string attribute (e.g. a []byte or a struct logged with %v inside a
// custom LogValuer) is only reached if it surfaces as a string. Prefer
// [secmem.Secret] for values you hold; use Handler as the backstop.
type Handler struct {
	inner     slog.Handler
	sanitizer *Sanitizer
	attrs     []slog.Attr
}

// NewHandler wraps inner so all output is sanitized by s. A nil inner discards
// output; a nil s uses [NewDefaultSanitizer].
func NewHandler(inner slog.Handler, s *Sanitizer) *Handler {
	if inner == nil {
		inner = discardHandler{}
	}
	if s == nil {
		s = NewDefaultSanitizer()
	}
	return &Handler{inner: inner, sanitizer: s}
}

// Enabled delegates to the inner handler.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle sanitizes the record's message and inline attributes, prepends the
// pre-sanitized WithAttrs attributes, and forwards to the inner handler.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	clean := slog.NewRecord(r.Time, r.Level, h.sanitizer.Sanitize(r.Message), r.PC)
	if len(h.attrs) > 0 {
		clean.AddAttrs(h.attrs...)
	}
	r.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(h.sanitizeAttr(a))
		return true
	})
	return h.inner.Handle(ctx, clean)
}

// WithAttrs pre-sanitizes attrs once so repeated records do not re-scan them.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	sanitized := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		sanitized[i] = h.sanitizeAttr(a)
	}
	return &Handler{
		inner:     h.inner,
		sanitizer: h.sanitizer,
		attrs:     append(cloneAttrs(h.attrs), sanitized...),
	}
}

// WithGroup opens a group on the inner handler. Inline record attributes are
// sanitized before they reach it, so grouping composes cleanly.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{
		inner:     h.inner.WithGroup(name),
		sanitizer: h.sanitizer,
		attrs:     cloneAttrs(h.attrs),
	}
}

// sanitizeAttr sanitizes one attribute recursively. String values are scrubbed
// directly; groups are scrubbed element-wise; an error value is scrubbed via
// its Error() string; a [slog.LogValuer] is resolved first so a lazily-built
// string is still caught. Numeric, bool, time, and duration values pass
// through untouched.
func (h *Handler) sanitizeAttr(a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(h.sanitizer.Sanitize(a.Value.String()))
	case slog.KindGroup:
		src := a.Value.Group()
		out := make([]slog.Attr, len(src))
		for i, ga := range src {
			out[i] = h.sanitizeAttr(ga)
		}
		a.Value = slog.GroupValue(out...)
	case slog.KindLogValuer:
		return h.sanitizeAttr(slog.Attr{Key: a.Key, Value: a.Value.Resolve()})
	case slog.KindAny:
		if err, ok := a.Value.Any().(error); ok {
			a.Value = slog.StringValue(h.sanitizer.Sanitize(err.Error()))
		}
	default:
		// Numeric, bool, duration, time — nothing string-shaped to redact.
	}
	return a
}

func cloneAttrs(attrs []slog.Attr) []slog.Attr {
	if attrs == nil {
		return nil
	}
	out := make([]slog.Attr, len(attrs))
	copy(out, attrs)
	return out
}

// discardHandler is a minimal slog.Handler that drops everything.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (h discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h discardHandler) WithGroup(string) slog.Handler           { return h }
