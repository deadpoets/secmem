package redact

import (
	"bytes"
	"fmt"
	"log/slog"
	"reflect"
	"testing"
)

type bigStringer struct{ s string }

func (b bigStringer) String() string { return b.s }

type bigMarshaler struct{ s string }

func (b bigMarshaler) MarshalText() ([]byte, error) { return []byte(b.s), nil }

// TestRender_CapBoundsASingleLargeValue pins that the render cap applies to
// one value, not only to the sum of many: a []byte, a String() result and a
// MarshalText result larger than the cap used to be copied into the builder
// whole, and only then truncated by the Sanitizer — a 100 MB slice logged
// through the handler cost two more copies of itself before it was cut to
// 4 KiB.
func TestRender_CapBoundsASingleLargeValue(t *testing.T) {
	t.Parallel()
	h := NewHandler(nil, nil)
	big := bytes.Repeat([]byte("x"), 4*renderCap)
	type named string
	type unexportedStr struct{ s string }
	cases := map[string]any{
		"bytes":                         big,
		"stringer":                      bigStringer{s: string(big)},
		"text marshaler":                bigMarshaler{s: string(big)},
		"struct with bytes":             struct{ B []byte }{B: big},
		"slice of bytes":                [][]byte{big, big},
		"struct with string":            struct{ S string }{S: string(big)},
		"struct with unexported string": unexportedStr{s: string(big)},
		"named string type":             named(big),
		"map of strings":                map[string]string{"k": string(big)},
	}
	for name, v := range cases {
		out := h.render(v, nil)
		if len(out) > renderCap+64 {
			t.Errorf("%s: rendered %d bytes, cap is %d", name, len(out), renderCap)
		}
		if len(out) < renderCap/2 {
			t.Errorf("%s: rendered only %d bytes; the cap cut far more than it should", name, len(out))
		}
	}
}

// TestRender_CapBoundsManyMembers is the cap over the other axis: many small
// members, each with a name. The names of a map with a great many keys, or of
// a slice of small structs, used to be written past the cap in full even
// though every value after it was skipped.
func TestRender_CapBoundsManyMembers(t *testing.T) {
	t.Parallel()
	h := NewHandler(nil, nil)
	const n = 50_000
	m := make(map[string]int, n)
	nested := make(map[int]struct{ A, B int }, n)
	for i := range n {
		m[fmt.Sprintf("member-%06d", i)] = i
		nested[i] = struct{ A, B int }{i, i}
	}
	type wide struct{ A, B, C, D, E, F, G, H int }
	cases := map[string]any{
		"map with many keys":      m,
		"map of small structs":    nested,
		"slice of small structs":  make([]wide, n),
		"one long map key":        map[string]int{string(bytes.Repeat([]byte("k"), 4*renderCap)): 1},
		"slice of maps":           []map[string]int{m, m},
		"struct holding the maps": struct{ M, N map[string]int }{m, m},
	}
	for name, v := range cases {
		out := h.render(v, nil)
		if len(out) > renderCap+64 {
			t.Errorf("%s: rendered %d bytes, cap is %d", name, len(out), renderCap)
		}
		if len(out) < renderCap/2 {
			t.Errorf("%s: rendered only %d bytes; the cap cut far more than it should", name, len(out))
		}
	}
}

// TestSelfRendering pins the type-level check behind the unexported-field
// rule: the interfaces fmt, slog and the encoders honour, on the type or on a
// pointer to it, and nothing else.
func TestSelfRendering(t *testing.T) {
	t.Parallel()
	type plain struct{ N int }
	type ptrStringer struct{}
	yes := []reflect.Type{
		reflect.TypeFor[bigStringer](),
		reflect.TypeFor[*bigStringer](),
		reflect.TypeFor[bigMarshaler](),
		reflect.TypeFor[error](),
		reflect.TypeFor[fmt.Stringer](),
		reflect.TypeFor[slog.LogValuer](),
		reflect.TypeFor[*valueReceiverFormatter](),
		reflect.TypeFor[valueReceiverFormatter](),
		reflect.TypeFor[pointerReceiverStringer](), // value type, method on *T: promoted through addressability
		reflect.TypeFor[*pointerReceiverStringer](),
	}
	no := []reflect.Type{
		reflect.TypeFor[plain](),
		reflect.TypeFor[*plain](),
		reflect.TypeFor[ptrStringer](),
		reflect.TypeFor[int](),
		reflect.TypeFor[[]byte](),
		reflect.TypeFor[map[string]string](),
		reflect.TypeFor[any](),
	}
	for _, typ := range yes {
		if !selfRendering(typ) {
			t.Errorf("%v: want self-rendering", typ)
		}
	}
	for _, typ := range no {
		if selfRendering(typ) {
			t.Errorf("%v: want NOT self-rendering", typ)
		}
	}
}

type valueReceiverFormatter struct{}

func (valueReceiverFormatter) Format(fmt.State, rune) {}

type pointerReceiverStringer struct{}

func (*pointerReceiverStringer) String() string { return "" }
