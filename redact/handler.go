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

// Handle sanitizes the record's message and inline attributes and forwards to
// the inner handler. WithAttrs attributes are NOT re-added here — they were
// handed to the inner handler when WithAttrs was called, which is what keeps
// them outside any group opened afterwards.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	clean := slog.NewRecord(r.Time, r.Level, h.sanitizer.Sanitize(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(h.sanitizeAttr(a))
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
		sanitized[i] = h.sanitizeAttr(a)
	}
	return &Handler{
		inner:     h.inner.WithAttrs(sanitized),
		sanitizer: h.sanitizer,
	}
}

// WithGroup opens a group on the inner handler. Inline record attributes are
// sanitized before they reach it, so grouping composes cleanly.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{
		inner:     h.inner.WithGroup(name),
		sanitizer: h.sanitizer,
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

// discardHandler is a minimal slog.Handler that drops everything.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (h discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h discardHandler) WithGroup(string) slog.Handler           { return h }
