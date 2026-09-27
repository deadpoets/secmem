package redact_test

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

// vault stands in for a type that redacts itself in print — secmem's
// SecureBuffer is the real one: its bytes are the secret and its Format method
// is the promise that no formatter shows them.
type vault struct{ data []byte }

func (v *vault) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "[REDACTED]") }

// plainVault redacts through a value-receiver String, as secmem.Secret does.
type plainVault struct{ data []byte }

func (plainVault) String() string { return "[REDACTED]" }

// The shapes a real program has: the redacting type held in an UNEXPORTED
// field, by pointer, by value, and behind an interface.
type conn struct {
	id  string
	key *vault
}

type session struct {
	user string
	tok  plainVault
}

type boxed struct {
	label string
	inner any
}

// openConn holds the same type in an EXPORTED field, where the walk can call
// Format and must keep doing so.
type openConn struct {
	ID  string
	Key *vault
}

// decimalBytes is how fmt prints a []byte element by element — the form the
// walk used to emit for a secret it had taken apart.
func decimalBytes(b []byte) string {
	s := fmt.Sprintf("%d", b)
	return strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
}

// TestHandler_UnexportedSelfRenderingFieldIsNotWalked pins the rule that closed
// a real leak: a value reached through an unexported field cannot have its
// Format/String called, and the walk used to take it apart field by field
// instead — printing a SecureBuffer's bytes as decimals, then reading into its
// guard page and faulting. A type that has such a method is now replaced by a
// fixed tag and never descended into, however it was reached.
func TestHandler_UnexportedSelfRenderingFieldIsNotWalked(t *testing.T) {
	t.Parallel()
	secret := []byte("vaultsecret-0123456789abcdef")
	decimal := decimalBytes(secret[:6])

	cases := []struct {
		name  string
		value any
	}{
		{"pointer field", conn{id: "x", key: &vault{data: secret}}},
		{"pointer to struct with pointer field", &conn{id: "x", key: &vault{data: secret}}},
		{"value field with value-receiver String", session{user: "u", tok: plainVault{data: secret}}},
		{"interface field holding the pointer", boxed{label: "l", inner: &vault{data: secret}}},
		{"interface field holding the value", boxed{label: "l", inner: plainVault{data: secret}}},
		{"inside a slice", []conn{{id: "x", key: &vault{data: secret}}}},
		{"inside a map", map[string]conn{"c": {id: "x", key: &vault{data: secret}}}},
		{"two structs down", struct{ a struct{ c conn } }{a: struct{ c conn }{c: conn{id: "x", key: &vault{data: secret}}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text, js, tbuf, jbuf := sinks()
			text.Info("m", "c", c.value)
			js.Info("m", "c", c.value)
			for sink, out := range map[string]string{"text": tbuf.String(), "json": jbuf.String()} {
				if strings.Contains(out, string(secret)) {
					t.Errorf("%s: secret bytes reached the sink verbatim: %s", sink, out)
				}
				if strings.Contains(out, decimal) {
					t.Errorf("%s: secret bytes reached the sink as decimals: %s", sink, out)
				}
				if !strings.Contains(out, "[REDACTED:unexported]") {
					t.Errorf("%s: the self-rendering value was not tagged: %s", sink, out)
				}
			}
		})
	}
}

// TestHandler_ExportedSelfRenderingFieldStillFormats is the other half: where
// the walk CAN call the method it must keep doing so, and a struct with an
// unexported field that has no method of its own is still walked (that is
// where the key-based redaction of nested fields comes from).
func TestHandler_ExportedSelfRenderingFieldStillFormats(t *testing.T) {
	t.Parallel()
	secret := []byte("vaultsecret-0123456789abcdef")
	text, _, tbuf, _ := sinks()
	text.Info("m", "c", openConn{ID: "x", Key: &vault{data: secret}})
	out := tbuf.String()
	if strings.Contains(out, string(secret)) || strings.Contains(out, decimalBytes(secret[:6])) {
		t.Errorf("secret reached the sink through an exported field: %s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("Format was not honoured on the exported field: %s", out)
	}
	if strings.Contains(out, "[REDACTED:unexported]") {
		t.Errorf("an exported field was tagged as unexported: %s", out)
	}

	// No method anywhere: the plain struct is still walked, so a credential
	// under a sensitive field name two levels down is still caught. (By key
	// first; the rendered "password:[REDACTED:key]" is itself credential-
	// shaped, so the value rule may re-tag it — either way the value is gone.)
	type inner struct{ password string }
	type outer struct{ in inner }
	tbuf.Reset()
	text.Info("m", "v", outer{in: inner{password: "walkedval"}})
	if strings.Contains(tbuf.String(), "walkedval") || !strings.Contains(tbuf.String(), "[REDACTED:") {
		t.Errorf("plain unexported struct field was not walked and redacted: %s", tbuf.String())
	}
	// A pointer in an unexported field is NOT followed, as fmt does not
	// follow a nested pointer: the pointee's methods cannot be called from
	// there, so it prints as a marker and nothing behind it reaches the sink.
	type deep struct{ p *creds }
	tbuf.Reset()
	text.Info("m", "v", deep{p: &creds{User: "bob", Password: "deepval"}})
	if strings.Contains(tbuf.String(), "deepval") || strings.Contains(tbuf.String(), "bob") || !strings.Contains(tbuf.String(), "<ptr>") {
		t.Errorf("pointer in an unexported field was followed or not marked: %s", tbuf.String())
	}
	// An EXPORTED pointer still is, and its pointee's sensitive field is
	// still caught — that reach is the reason the walk exists.
	type open struct{ P *creds }
	tbuf.Reset()
	text.Info("m", "v", open{P: &creds{User: "bob", Password: "openval"}})
	if strings.Contains(tbuf.String(), "openval") || !strings.Contains(tbuf.String(), "[REDACTED:") {
		t.Errorf("pointer in an exported field was not walked and redacted: %s", tbuf.String())
	}
}
