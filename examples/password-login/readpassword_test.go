package main

import (
	"os"
	"path/filepath"
	"testing"
)

// typed runs readPassword over input as if those bytes had come from the
// keyboard, and returns the password it ended up with. A regular file
// stands in for the terminal: readPassword's editing does not depend on
// which it is reading.
func typed(t *testing.T, input string) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatalf("writing input: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening input: %v", err)
	}
	defer func() { _ = f.Close() }()

	buf, err := readPassword(f)
	if err != nil {
		return "", err
	}
	defer func() { _ = buf.Destroy() }()
	var got string
	if err := buf.WithBytesErr(func(b []byte) error {
		got = string(b) //nolint:secmem-lint // a test password, compared in the open
		return nil
	}); err != nil {
		t.Fatalf("WithBytesErr: %v", err)
	}
	return got, nil
}

// TestReadPassword_EditingKeys: in raw mode the terminal does no line
// editing, so readPassword does it, and what it stores must be what the
// user meant. A backspace removes one character, however many bytes that
// is; ^U starts over; ^D ends the input; and a key that is neither text nor
// one of those is refused instead of becoming part of the password.
func TestReadPassword_EditingKeys(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{"plain", "hunter2\n", "hunter2"},
		{"multi-byte kept", "pässwörd\r", "pässwörd"},
		{"backspace over ASCII", "abc\x7f\x7fd\n", "ad"},
		{"backspace over two bytes", "é\x7fe\n", "e"},
		{"backspace over three bytes", "a€\x08b\n", "ab"},
		{"backspace over four bytes", "x\U0001F511\x7f\n", "x"},
		{"backspace on nothing", "\x7f\x7fok\n", "ok"},
		{"backspace over a stray continuation byte", "a\x80\x7fb\n", "ab"},
		{"^U starts over", "first try\x15second\n", "second"},
		{"^D ends the input", "done\x04ignored\n", "done"},
	} {
		got, err := typed(t, tc.input)
		if err != nil {
			t.Errorf("%s: readPassword(%q): %v", tc.name, tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: readPassword(%q) = %q, want %q", tc.name, tc.input, got, tc.want)
		}
	}

	for _, tc := range []struct {
		name, input string
	}{
		{"an arrow key", "ab\x1b[Dc\n"},
		{"^W", "two words\x17\n"},
		{"a tab", "a\tb\n"},
	} {
		if got, err := typed(t, tc.input); err == nil {
			t.Errorf("%s: readPassword(%q) = %q, want it refused", tc.name, tc.input, got)
		}
	}
}
