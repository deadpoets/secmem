package secmem

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// Compile-time proof the leak-safe surface is actually wired to the
// interfaces fmt, encoding/json, and log/slog dispatch on.
var (
	_ fmt.Stringer           = Secret{}
	_ fmt.GoStringer         = Secret{}
	_ encoding.TextMarshaler = Secret{}
	_ json.Marshaler         = Secret{}
	_ slog.LogValuer         = Secret{}
	_ io.WriterTo            = Secret{}
)

const secretPlaintext = "hunter2-super-secret-token"

func mustSecret(t *testing.T) Secret {
	t.Helper()
	s, err := NewSecret([]byte(secretPlaintext))
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	return s
}

// TestNewSecret_CopiesAndWipesInput verifies the ingest contract: the secret
// round-trips, and the caller's slice is zeroed after the call.
func TestNewSecret_CopiesAndWipesInput(t *testing.T) {
	t.Parallel()
	input := []byte(secretPlaintext)
	s, err := NewSecret(input)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	defer func() { _ = s.Destroy() }()

	for i, v := range input {
		if v != 0 {
			t.Fatalf("input byte %d = %#x, want 0 (input must be wiped)", i, v)
		}
	}
	if err := s.WithBytes(func(b []byte) {
		if string(b) != secretPlaintext {
			t.Errorf("contents = %q, want %q", b, secretPlaintext)
		}
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
}

// TestNewSecret_EmptyInput verifies the NewBuffer validation propagates.
func TestNewSecret_EmptyInput(t *testing.T) {
	t.Parallel()
	if _, err := NewSecret(nil); err == nil {
		t.Fatal("NewSecret(nil) succeeded, want error")
	}
}

// TestSecret_NeverLeaksThroughFormatting drives every fmt path a Secret can
// take — direct, pointer, struct field, %v/%s/%+v/%#v — and asserts the
// plaintext never appears and the sentinel always does.
func TestSecret_NeverLeaksThroughFormatting(t *testing.T) {
	t.Parallel()
	s := mustSecret(t)
	defer func() { _ = s.Destroy() }()

	type wrapper struct {
		Name  string
		Token Secret
		Ptr   *Secret
	}
	w := wrapper{Name: "db", Token: s, Ptr: &s}

	// Route through any so the verb dispatches at runtime exactly as a caller's
	// would (fmt still invokes String/Format/GoString), while the static
	// analyzer cannot fold "%s of a Stringer" into a direct String() call —
	// which would defeat the very path under test.
	sf := func(format string, v any) string { return fmt.Sprintf(format, v) }
	outputs := map[string]string{
		"%v direct":     sf("%v", s),
		"%s direct":     sf("%s", s),
		"%#v direct":    sf("%#v", s),
		"%v pointer":    sf("%v", &s),
		"%s pointer":    sf("%s", &s),
		"%v struct":     sf("%v", w),
		"%+v struct":    sf("%+v", w),
		"%#v struct":    sf("%#v", w),
		"Sprint":        fmt.Sprint(any(s)),
		"string concat": s.String(),
	}
	for name, out := range outputs {
		if strings.Contains(out, secretPlaintext) {
			t.Errorf("%s leaked the plaintext: %q", name, out)
		}
		if !strings.Contains(out, redacted) {
			t.Errorf("%s did not contain the sentinel: %q", name, out)
		}
	}
}

// TestSecret_NeverLeaksThroughMarshalling covers encoding/json and
// encoding.TextMarshaler, on both value and pointer fields.
func TestSecret_NeverLeaksThroughMarshalling(t *testing.T) {
	t.Parallel()
	s := mustSecret(t)
	defer func() { _ = s.Destroy() }()

	type payload struct {
		Token Secret  `json:"token"`
		Ptr   *Secret `json:"ptr"`
	}
	out, err := json.Marshal(payload{Token: s, Ptr: &s})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if bytes.Contains(out, []byte(secretPlaintext)) {
		t.Fatalf("json.Marshal leaked the plaintext: %s", out)
	}
	want := `{"token":"[REDACTED]","ptr":"[REDACTED]"}`
	if string(out) != want {
		t.Errorf("json.Marshal = %s, want %s", out, want)
	}

	txt, err := s.MarshalText()
	if err != nil || string(txt) != redacted {
		t.Errorf("MarshalText = %q, %v; want %q, nil", txt, err, redacted)
	}
}

// TestSecret_NeverLeaksThroughSlog logs a Secret through a real slog logger
// and asserts the record carries the sentinel, not the plaintext.
func TestSecret_NeverLeaksThroughSlog(t *testing.T) {
	t.Parallel()
	s := mustSecret(t)
	defer func() { _ = s.Destroy() }()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("connecting", "token", s)

	out := buf.String()
	if strings.Contains(out, secretPlaintext) {
		t.Fatalf("slog leaked the plaintext: %q", out)
	}
	if !strings.Contains(out, redacted) {
		t.Errorf("slog output missing the sentinel: %q", out)
	}
}

// TestSecret_Equal covers the constant-time comparison semantics.
func TestSecret_Equal(t *testing.T) {
	t.Parallel()

	a := mustSecret(t)
	defer func() { _ = a.Destroy() }()
	b := mustSecret(t)
	defer func() { _ = b.Destroy() }()

	other, err := NewSecret([]byte("a-different-secret-entirely"))
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	defer func() { _ = other.Destroy() }()

	short, err := NewSecret([]byte("short"))
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	defer func() { _ = short.Destroy() }()

	if !a.Equal(b) {
		t.Error("Equal(same contents, distinct backings) = false, want true")
	}
	if !a.Equal(a) {
		t.Error("Equal(self) = false, want true")
	}
	copyOfA := a // value copy shares the backing store
	if !a.Equal(copyOfA) {
		t.Error("Equal(shared backing copy) = false, want true")
	}
	if a.Equal(other) {
		t.Error("Equal(different contents) = true, want false")
	}
	if a.Equal(short) {
		t.Error("Equal(different lengths) = true, want false")
	}
	if a.Equal(Secret{}) || (Secret{}).Equal(a) || (Secret{}).Equal(Secret{}) {
		t.Error("zero-value Secret compared equal to something")
	}
}

// TestSecret_Equal_Destroyed verifies a destroyed Secret is equal to nothing,
// including itself.
func TestSecret_Equal_Destroyed(t *testing.T) {
	t.Parallel()
	a := mustSecret(t)
	b := mustSecret(t)
	defer func() { _ = b.Destroy() }()

	if err := a.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if a.Equal(b) || b.Equal(a) || a.Equal(a) {
		t.Error("destroyed Secret compared equal to something")
	}
}

// TestSecret_WriteTo verifies the deliberate plaintext egress path.
func TestSecret_WriteTo(t *testing.T) {
	t.Parallel()
	s := mustSecret(t)
	defer func() { _ = s.Destroy() }()

	var sink bytes.Buffer
	n, err := s.WriteTo(&sink)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != int64(len(secretPlaintext)) || sink.String() != secretPlaintext {
		t.Errorf("WriteTo wrote %d bytes %q, want %d bytes %q",
			n, sink.String(), len(secretPlaintext), secretPlaintext)
	}
}

// TestSecret_CopiesShareDestroy pins the documented sharp edge: destroying a
// value copy destroys the original too.
func TestSecret_CopiesShareDestroy(t *testing.T) {
	t.Parallel()
	s := mustSecret(t)
	copyOfS := s

	if err := copyOfS.Destroy(); err != nil {
		t.Fatalf("Destroy via copy: %v", err)
	}
	if err := s.WithBytes(func([]byte) {}); !errors.Is(err, ErrDestroyed) {
		t.Errorf("WithBytes on original after copy.Destroy() = %v, want ErrDestroyed", err)
	}
	// Idempotent across copies.
	if err := s.Destroy(); err != nil {
		t.Errorf("second Destroy via original = %v, want nil", err)
	}
}

// TestSecret_ZeroValue verifies the zero value behaves like a destroyed
// Secret: no panics, access refused, redaction intact.
func TestSecret_ZeroValue(t *testing.T) {
	t.Parallel()
	var s Secret

	if err := s.WithBytes(func([]byte) {}); !errors.Is(err, ErrDestroyed) {
		t.Errorf("zero WithBytes = %v, want ErrDestroyed", err)
	}
	if _, err := s.WriteTo(io.Discard); !errors.Is(err, ErrDestroyed) {
		t.Errorf("zero WriteTo = %v, want ErrDestroyed", err)
	}
	if err := s.Destroy(); err != nil {
		t.Errorf("zero Destroy = %v, want nil (idempotent no-op)", err)
	}
	if s.String() != redacted || s.GoString() != redacted {
		t.Error("zero value redaction broken")
	}
	if v := s.LogValue(); v.String() != redacted {
		t.Errorf("zero LogValue = %q, want %q", v.String(), redacted)
	}
}

// TestSecret_RedactionIgnoresState verifies the sentinel is identical before
// and after Destroy — lifecycle state is not inferable from the redacted form.
func TestSecret_RedactionIgnoresState(t *testing.T) {
	t.Parallel()
	s := mustSecret(t)
	before := fmt.Sprintf("%v %#v %s", s, s, s)
	if err := s.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	after := fmt.Sprintf("%v %#v %s", s, s, s)
	if before != after {
		t.Errorf("redacted form changed across Destroy: %q -> %q", before, after)
	}
}
