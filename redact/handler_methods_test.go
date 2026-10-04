package redact_test

import (
	"strings"
	"testing"
)

// textMode marshals itself as text through a value receiver and has no
// String, so a nil *textMode satisfies encoding.TextMarshaler and the call
// dereferences nil.
type textMode int

func (m textMode) MarshalText() ([]byte, error) {
	if m == 0 {
		return []byte("off"), nil
	}
	return []byte("on"), nil
}

// panicText has a MarshalText that panics outright.
type panicText struct{ Inner string }

func (panicText) MarshalText() ([]byte, error) { panic("marshal blew up") }

// TestHandler_PanickingMarshalTextStaysInsideHandle: a MarshalText that
// panics — the nil-pointer case above all — must not take the caller's
// logger.Info down with it. slog's own handlers recover it; so does this one.
func TestHandler_PanickingMarshalTextStaysInsideHandle(t *testing.T) {
	t.Parallel()
	on := textMode(1)
	cases := []struct {
		name  string
		value any
		want  string
	}{
		{"nil pointer at the top", (*textMode)(nil), "<nil>"},
		{"nil pointer in an exported field", struct{ Mode *textMode }{}, "Mode:<nil>"},
		{"live pointer still marshals", struct{ Mode *textMode }{Mode: &on}, "Mode:on"},
		{"panicking method", panicText{Inner: "innerval"}, "[REDACTED:panic]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic escaped Handle: %v", r)
				}
			}()
			text, js, tbuf, jbuf := sinks()
			text.Info("m", "v", c.value)
			js.Info("m", "v", c.value)
			for sink, out := range map[string]string{"text": tbuf.String(), "json": jbuf.String()} {
				if !strings.Contains(out, c.want) {
					t.Errorf("%s: want %q in %s", sink, c.want, out)
				}
				if strings.Contains(out, "innerval") {
					t.Errorf("%s: a value whose method panicked was taken apart: %s", sink, out)
				}
			}
		})
	}
}
