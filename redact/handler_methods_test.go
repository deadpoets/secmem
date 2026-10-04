package redact_test

import (
	"errors"
	"log/slog"
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

// jsonKey redacts itself in JSON only, the way a type written for an API
// response does.
type jsonKey struct{ v string }

func (jsonKey) MarshalJSON() ([]byte, error) { return []byte(`"***"`), nil }

// ptrJSONKey does the same through a pointer receiver.
type ptrJSONKey struct{ v string }

func (*ptrJSONKey) MarshalJSON() ([]byte, error) { return []byte(`"***"`), nil }

// failingJSONKey refuses to marshal.
type failingJSONKey struct{ v string }

func (failingJSONKey) MarshalJSON() ([]byte, error) { return nil, errors.New("no") }

// logUser says how it wants to be logged, and that form leaves v out.
type logUser struct{ v string }

func (logUser) LogValue() slog.Value { return slog.StringValue("user#1") }

// logGroup resolves to a group carrying a sensitive key.
type logGroup struct{ v string }

func (g logGroup) LogValue() slog.Value {
	return slog.GroupValue(slog.String("name", "bob"), slog.String("password", g.v))
}

// goKey redacts itself through GoString alone.
type goKey struct{ v string }

func (goKey) GoString() string { return "goKey{***}" }

// TestHandler_SelfRenderingTypesAreNotTakenApart: a type whose only say over
// its own text is MarshalJSON, LogValue or GoString used to be walked field
// by field wherever the walk could reach it, so "***" behind a bare JSON
// handler became "{v:abc123}" behind this one.
func TestHandler_SelfRenderingTypesAreNotTakenApart(t *testing.T) {
	t.Parallel()
	const secret = "abc123val"
	cases := []struct {
		name  string
		value any
		want  string
	}{
		{"MarshalJSON at the top", jsonKey{v: secret}, "***"},
		{"MarshalJSON in an exported field", struct{ K jsonKey }{K: jsonKey{v: secret}}, "***"},
		{"MarshalJSON in a slice", []jsonKey{{v: secret}}, "***"},
		{"MarshalJSON in a map", map[string]jsonKey{"k": {v: secret}}, "***"},
		{"pointer-receiver MarshalJSON held by value", struct{ K ptrJSONKey }{K: ptrJSONKey{v: secret}}, "***"},
		{"pointer-receiver MarshalJSON held by pointer", struct{ K *ptrJSONKey }{K: &ptrJSONKey{v: secret}}, "***"},
		{"MarshalJSON that fails", struct{ K failingJSONKey }{K: failingJSONKey{v: secret}}, "[REDACTED:marshal_error]"},
		{"nested LogValuer", struct{ U logUser }{U: logUser{v: secret}}, "user#1"},
		{"nested LogValuer resolving to a group", struct{ U logGroup }{U: logGroup{v: secret}}, "name=bob"},
		{"GoStringer", struct{ K goKey }{K: goKey{v: secret}}, "goKey{***}"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text, js, tbuf, jbuf := sinks()
			text.Info("m", "v", c.value)
			js.Info("m", "v", c.value)
			for sink, out := range map[string]string{"text": tbuf.String(), "json": jbuf.String()} {
				if strings.Contains(out, secret) {
					t.Errorf("%s: the value was taken apart: %s", sink, out)
				}
				if !strings.Contains(out, c.want) {
					t.Errorf("%s: want %q in %s", sink, c.want, out)
				}
			}
		})
	}
}

// rawBody is a defined byte-slice type with no methods, as json.RawMessage
// was before go1.27 and ed25519.PrivateKey is.
type rawBody []byte

type bytesHolder struct {
	id  string
	raw []byte
}

type arrayHolder struct {
	id  string
	key [16]byte
}

// TestHandler_ByteShapesAreText: the walk treats []byte as text so the value
// rules can see it. A defined byte-slice type, a []byte in an unexported
// field and a byte array used to miss that case and reach the sink as a list
// of decimals, which no rule matches and anyone can decode.
func TestHandler_ByteShapesAreText(t *testing.T) {
	t.Parallel()
	const body = "password=hunter2x"
	var arr [16]byte
	copy(arr[:], "pwd=hunter2x")
	cases := []struct {
		name  string
		value any
	}{
		{"defined byte slice", rawBody(body)},
		{"defined byte slice in an exported field", struct{ Body rawBody }{Body: rawBody(body)}},
		{"byte slice in an unexported field", bytesHolder{id: "x", raw: []byte(body)}},
		{"byte array", arr},
		{"pointer to byte array", &arr},
		{"byte array in an unexported field", arrayHolder{id: "x", key: arr}},
		{"slice of byte arrays", [][16]byte{arr}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text, js, tbuf, jbuf := sinks()
			text.Info("m", "v", c.value)
			js.Info("m", "v", c.value)
			for sink, out := range map[string]string{"text": tbuf.String(), "json": jbuf.String()} {
				if strings.Contains(out, "hunter2x") {
					t.Errorf("%s: secret reached the sink: %s", sink, out)
				}
				// "hun" as fmt prints bytes one by one.
				if strings.Contains(out, "104 117 110") {
					t.Errorf("%s: bytes reached the sink as decimals: %s", sink, out)
				}
				if !strings.Contains(out, "[REDACTED:password_field]") {
					t.Errorf("%s: the value rule did not see the bytes as text: %s", sink, out)
				}
			}
		})
	}
}
