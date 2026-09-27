package redact_test

import (
	"strings"
	"testing"

	"github.com/deadpoets/secmem"
)

// TestHandler_SecmemTypesInUnexportedFieldsNeverReachTheSink is the regression
// test for the defect that motivated the unexported-field rule, run against the
// real types. Before the rule, logging a struct that held a *SecureBuffer in an
// unexported field through this handler either killed the process — the walk
// printed the buffer's data field byte by byte, then indexed region.outer,
// whose first element is the PROT_NONE guard page — or, for a secret large
// enough to hit the render cap first, wrote the secret to the sink as decimal
// numbers. The stdlib handler alone printed a harmless pointer address.
//
// If the rule regresses, this test does not fail gracefully: the binary dies
// with an unrecoverable fault, which is the correct signal for what it guards.
//
// The insecure fallback is requested so the test also runs on a platform with
// no lockable memory; there is no guard page there, but the bytes would still
// be printed, and that is asserted.
func TestHandler_SecmemTypesInUnexportedFieldsNeverReachTheSink(t *testing.T) {
	secret := []byte("SUPERSECRET-0123456789-abcdefghij-KEY")
	decimal := decimalBytes(secret[:6]) // "83 85 80 69 82 83"

	buf, err := secmem.NewBuffer(append([]byte(nil), secret...), secmem.WithInsecureFallback())
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()
	tok, err := secmem.NewSecret(append([]byte(nil), secret...), secmem.WithInsecureFallback())
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	defer func() { _ = tok.Destroy() }()
	arena, err := secmem.NewArena(len(secret), 2, secmem.WithInsecureFallback())
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = arena.Destroy() }()
	slot, err := arena.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := slot.WithBytes(func(b []byte) { copy(b, secret) }); err != nil {
		t.Fatalf("fill slot: %v", err)
	}

	// Every secmem type, each in an unexported field, in one ordinary struct.
	// stripped is a defined type over SecureBuffer: it has none of the
	// methods, so the self-rendering rule cannot see it, and only the rule
	// that an unexported pointer is not followed stands between the walk and
	// its guard page.
	type stripped secmem.SecureBuffer
	type holder struct {
		id    string
		key   *secmem.SecureBuffer
		tok   secmem.Secret
		slot  *secmem.ArenaSlot
		arena *secmem.SecureArena
		bare  *stripped
	}
	h := holder{id: "x", key: buf, tok: tok, slot: slot, arena: arena, bare: (*stripped)(buf)}

	for _, name := range []string{"c", "conn", "h"} { // keys that are NOT on the sensitive list
		text, js, tbuf, jbuf := sinks()
		text.Info("m", name, h)
		js.Info("m", name, h)
		for sink, out := range map[string]string{"text": tbuf.String(), "json": jbuf.String()} {
			if strings.Contains(out, string(secret)) {
				t.Errorf("%s key %q: secret reached the sink verbatim: %s", sink, name, out)
			}
			if strings.Contains(out, decimal) {
				t.Errorf("%s key %q: secret reached the sink as decimal bytes: %s", sink, name, out)
			}
			if !strings.Contains(out, "[REDACTED:unexported]") {
				t.Errorf("%s key %q: secmem values were not tagged: %s", sink, name, out)
			}
		}
	}

	// The same types in EXPORTED fields render through their own Format.
	type open struct {
		Key  *secmem.SecureBuffer
		Tok  secmem.Secret
		Slot *secmem.ArenaSlot
	}
	text, _, tbuf, _ := sinks()
	text.Info("m", "c", open{Key: buf, Tok: tok, Slot: slot})
	out := tbuf.String()
	if strings.Contains(out, string(secret)) || strings.Contains(out, decimal) {
		t.Errorf("secret reached the sink through an exported field: %s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("the types' own redaction was not honoured on exported fields: %s", out)
	}
}
