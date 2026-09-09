package redact_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/deadpoets/secmem/redact"
)

// sinks returns a text and a JSON logger writing through a redact.Handler
// built with opts, each with its own buffer.
func sinks(opts ...redact.HandlerOption) (text, js *slog.Logger, tbuf, jbuf *bytes.Buffer) {
	tbuf, jbuf = &bytes.Buffer{}, &bytes.Buffer{}
	text = slog.New(redact.NewHandler(slog.NewTextHandler(tbuf, nil), nil, opts...))
	js = slog.New(redact.NewHandler(slog.NewJSONHandler(jbuf, nil), nil, opts...))
	return text, js, tbuf, jbuf
}

// TestHandler_RedactsBySensitiveKey: an attribute whose KEY is
// credential-shaped is redacted whatever its value looks like. The values
// here are chosen so that no value rule would catch them — they are plain
// words — which is exactly the case the value rules used to let through.
func TestHandler_RedactsBySensitiveKey(t *testing.T) {
	t.Parallel()
	attrs := []struct {
		name   string
		attr   slog.Attr
		secret string
	}{
		{"password string", slog.String("password", "hunter2"), "hunter2"},
		{"token string", slog.String("token", "plainword"), "plainword"},
		{"nested group", slog.Group("db", slog.String("password", "dbpw")), "dbpw"},
		{"camelCase", slog.String("accessToken", "camelval"), "camelval"},
		{"header style", slog.String("X-Api-Key", "headerval"), "headerval"},
		{"dotted", slog.String("db.password", "dotval"), "dotval"},
		{"upper snake", slog.String("DB_PASSWORD", "snakeval"), "snakeval"},
		{"bytes", slog.Any("secret", []byte("bytesval")), "bytesval"},
		{"any struct", slog.Any("client_secret", struct{ V string }{"structval"}), "structval"},
		{"int", slog.Int("pin_code_passcode", 123456), "123456"},
		{"authorization", slog.String("authorization", "Bearer x"), "Bearer"},
		{"cookie", slog.String("cookie", "sid=cookieval"), "cookieval"},
		{"private_key", slog.String("private_key", "keyval"), "keyval"},
	}
	for _, c := range attrs {
		text, js, tbuf, jbuf := sinks()
		text.Info("m", c.attr)
		js.Info("m", c.attr)
		for _, out := range []string{tbuf.String(), jbuf.String()} {
			if strings.Contains(out, c.secret) {
				t.Errorf("%s: value leaked: %s", c.name, out)
			}
			if !strings.Contains(out, "[REDACTED:key]") {
				t.Errorf("%s: no key tag: %s", c.name, out)
			}
		}
	}
}

func TestHandler_WithAttrsSensitiveKey(t *testing.T) {
	t.Parallel()
	text, js, tbuf, jbuf := sinks()
	text.With("password", "withval").Info("m")
	js.With("password", "withval").Info("m")
	for _, out := range []string{tbuf.String(), jbuf.String()} {
		if strings.Contains(out, "withval") || !strings.Contains(out, "[REDACTED:key]") {
			t.Errorf("With() secret leaked or untagged: %s", out)
		}
	}
}

// TestHandler_KeyMatchAcrossWithGroup: a multi-component entry matches across
// a WithGroup name and the attribute key ("api" group + "key" = api_key).
func TestHandler_KeyMatchAcrossWithGroup(t *testing.T) {
	t.Parallel()
	_, js, _, jbuf := sinks()
	js.WithGroup("api").Info("m", "key", "groupedval", "user", "bob")
	out := jbuf.String()
	if strings.Contains(out, "groupedval") {
		t.Errorf("api.key leaked: %s", out)
	}
	if !strings.Contains(out, `"user":"bob"`) {
		t.Errorf("innocent sibling was not preserved: %s", out)
	}
}

// TestHandler_SensitiveGroupRedactedWhole: a group attribute whose own name
// is sensitive is replaced as one value; a WithGroup with a sensitive name
// redacts everything beneath it.
func TestHandler_SensitiveGroupRedactedWhole(t *testing.T) {
	t.Parallel()
	_, js, _, jbuf := sinks()
	js.Info("m", slog.Group("credentials", "user", "bob", "password", "p"))
	var got map[string]any
	if err := json.Unmarshal(jbuf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal %q: %v", jbuf.String(), err)
	}
	if got["credentials"] != "[REDACTED:key]" {
		t.Errorf("credentials group not replaced whole: %s", jbuf.String())
	}

	jbuf.Reset()
	js.WithGroup("credentials").Info("m", "user", "bob")
	if strings.Contains(jbuf.String(), "bob") {
		t.Errorf("attr beneath a sensitive WithGroup leaked: %s", jbuf.String())
	}
}

// TestHandler_SensitiveLogValuerNotResolved: a LogValuer under a sensitive
// key is replaced without being resolved.
func TestHandler_SensitiveLogValuerNotResolved(t *testing.T) {
	t.Parallel()
	_, js, _, jbuf := sinks()
	v := &countingValuer{}
	js.Info("m", "password", v)
	if v.calls != 0 {
		t.Errorf("LogValue was resolved %d time(s) under a sensitive key", v.calls)
	}
	if strings.Contains(jbuf.String(), "resolved") {
		t.Errorf("resolved value leaked: %s", jbuf.String())
	}
}

type countingValuer struct{ calls int }

func (c *countingValuer) LogValue() slog.Value {
	c.calls++
	return slog.StringValue("resolved")
}

func TestHandler_KeyOptions(t *testing.T) {
	t.Parallel()
	// Extend: a custom key is redacted alongside the defaults.
	text, _, tbuf, _ := sinks(redact.WithSensitiveKeys("magic"))
	text.Info("m", "magic", "abracadabra", "password", "pw")
	if strings.Contains(tbuf.String(), "abracadabra") || strings.Contains(tbuf.String(), "pw\n") {
		t.Errorf("custom or default key leaked: %s", tbuf.String())
	}
	// Replace: without the defaults, only the custom key is redacted by key.
	text, _, tbuf, _ = sinks(redact.WithoutDefaultSensitiveKeys(), redact.WithSensitiveKeys("magic"))
	text.Info("m", "magic", "abracadabra", "password", "plainword")
	if strings.Contains(tbuf.String(), "abracadabra") {
		t.Errorf("custom key leaked: %s", tbuf.String())
	}
	if !strings.Contains(tbuf.String(), "password=plainword") {
		t.Errorf("defaults still applied after WithoutDefaultSensitiveKeys: %s", tbuf.String())
	}
	if len(redact.DefaultSensitiveKeys()) == 0 {
		t.Error("DefaultSensitiveKeys is empty")
	}
}

// TestHandler_InnocentKeysUntouched: a key that merely contains a sensitive
// spelling inside one component is not a match.
func TestHandler_InnocentKeysUntouched(t *testing.T) {
	t.Parallel()
	text, _, tbuf, _ := sinks()
	text.Info("m", "author", "bob", "bypass", "yes", "tokenizer", "bpe", "passenger", "ann", "keyboard", "qwerty")
	out := tbuf.String()
	for _, want := range []string{"author=bob", "bypass=yes", "tokenizer=bpe", "passenger=ann", "keyboard=qwerty"} {
		if !strings.Contains(out, want) {
			t.Errorf("innocent attr %q was altered: %s", want, out)
		}
	}
	if strings.Contains(out, "[REDACTED") {
		t.Errorf("something was redacted: %s", out)
	}
}

// ── KindAny ─────────────────────────────────────────────────────────────────

type creds struct {
	User     string
	Password string
}

type lazyStruct struct{}

func (lazyStruct) LogValue() slog.Value { return slog.AnyValue(creds{"bob", "password=lazyval"}) }

type stringerSecret struct{}

func (stringerSecret) String() string { return "password=stringerval" }

type withUnexported struct {
	inner struct{ token string }
}

// TestHandler_AnyValuesSanitized: values of kind Any used to pass through the
// handler untouched in both text and JSON output. They are now rendered to
// text, walked for sensitive keys, sanitized and emitted as one string.
func TestHandler_AnyValuesSanitized(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		value  any
		secret string
	}{
		{"struct field name", creds{"bob", "structval"}, "structval"},
		{"struct pointer", &creds{"bob", "ptrval"}, "ptrval"},
		{"map key", map[string]string{"password": "mapval"}, "mapval"},
		{"map value shape", map[string]any{"note": "password=mapshape"}, "mapshape"},
		{"slice element", []string{"ok", "password=sliceval"}, "sliceval"},
		{"logvaluer to struct", lazyStruct{}, "lazyval"},
		{"bytes text", []byte("password=bytesval"), "bytesval"},
		{"stringer", stringerSecret{}, "stringerval"},
		{"nested unexported field", func() withUnexported {
			var w withUnexported
			w.inner.token = "unexportedval"
			return w
		}(), "unexportedval"},
		{"error", fmt.Errorf("dial: password=errval"), "errval"},
	}
	for _, c := range cases {
		text, js, tbuf, jbuf := sinks()
		text.Info("m", "v", c.value)
		js.Info("m", "v", c.value)
		for sink, out := range map[string]string{"text": tbuf.String(), "json": jbuf.String()} {
			if strings.Contains(out, c.secret) {
				t.Errorf("%s (%s): leaked %q: %s", c.name, sink, c.secret, out)
			}
			if !strings.Contains(out, "[REDACTED:") {
				t.Errorf("%s (%s): nothing redacted: %s", c.name, sink, out)
			}
		}
	}
}

// TestHandler_AnyWalkAppliesCustomKeys: key-based redaction reaches struct
// fields and map keys inside an Any value, including keys only the caller
// knows about.
func TestHandler_AnyWalkAppliesCustomKeys(t *testing.T) {
	t.Parallel()
	type spell struct{ Magic string }
	_, js, _, jbuf := sinks(redact.WithSensitiveKeys("magic"))
	js.Info("m", "v", spell{"abracadabra"}, "w", map[string]int{"magic": 42})
	if strings.Contains(jbuf.String(), "abracadabra") || strings.Contains(jbuf.String(), "42") {
		t.Errorf("custom key inside an Any value leaked: %s", jbuf.String())
	}
}

// TestHandler_AnyRenderingIsOneString documents the shape trade: the JSON
// handler writes a string where it used to write an object.
func TestHandler_AnyRenderingIsOneString(t *testing.T) {
	t.Parallel()
	_, js, _, jbuf := sinks()
	js.Info("m", "v", creds{"bob", "x"})
	var got map[string]any
	if err := json.Unmarshal(jbuf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal %q: %v", jbuf.String(), err)
	}
	s, ok := got["v"].(string)
	if !ok {
		t.Fatalf("Any value was not emitted as a string: %s", jbuf.String())
	}
	// The key walk writes Password:[REDACTED:key]; the value rules then see
	// "Password:<non-space>" and re-tag it as a password field. Either tag
	// is fine — what matters is that the value is gone and the sibling
	// field survived.
	if !strings.Contains(s, "User:bob") || !strings.Contains(s, "[REDACTED:") || strings.Contains(s, "Password:x") {
		t.Errorf("unexpected rendering: %q", s)
	}
}

func TestHandler_AnyNilPassesThrough(t *testing.T) {
	t.Parallel()
	_, js, _, jbuf := sinks()
	js.Info("m", slog.Any("v", nil))
	if !strings.Contains(jbuf.String(), `"v":null`) {
		t.Errorf("nil Any was altered: %s", jbuf.String())
	}
}
