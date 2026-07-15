//go:build linux || darwin || windows

package secmem

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// safeFormat runs fn (a fmt/slog call against a secret-holding value) behind
// the faults() guard from guard_canary_test.go. If redact.go ever regresses,
// fmt reflecting into the guarded region crashes the process outright — that
// is not a recoverable panic testing.T can catch on its own. Routing through
// faults() (debug.SetPanicOnFault + recover) turns that crash into a clean
// test failure instead of taking down the whole test binary.
func safeFormat(t *testing.T, fn func() string) string {
	t.Helper()
	var out string
	if faults(func() { out = fn() }) {
		t.Fatal("formatting faulted — redaction regressed to raw reflection into the guarded region")
	}
	return out
}

// assertRedacted checks every common formatting/logging path for a value,
// failing if the secret ever appears in the output or if any path faults.
func assertRedacted(t *testing.T, secret string, v any) {
	t.Helper()
	paths := map[string]func() string{
		"%v":     func() string { return fmt.Sprintf("%v", v) },
		"%+v":    func() string { return fmt.Sprintf("%+v", v) },
		"%#v":    func() string { return fmt.Sprintf("%#v", v) },
		"%s":     func() string { return fmt.Sprintf("%s", v) }, //nolint:gosimple // deliberately exercising %s, not just %v.
		"%x":     func() string { return fmt.Sprintf("%x", v) },
		"Sprint": func() string { return fmt.Sprint(v) },
		"Errorf": func() string { return fmt.Errorf("wrapped: %v", v).Error() },
		"slog": func() string {
			var sb strings.Builder
			slog.New(slog.NewTextHandler(&sb, nil)).Info("x", "v", v)
			return sb.String()
		},
	}
	for name, fn := range paths {
		out := safeFormat(t, fn)
		if secret != "" && strings.Contains(out, secret) {
			t.Errorf("%s: secret content reached output: %q", name, out)
		}
	}
	// %v/%+v/%s/%x/Sprint must be the exact redacted sentinel (not just
	// secret-free — e.g. an internal pointer address is also "secret-free"
	// but is not the redaction contract).
	for name, fn := range map[string]func() string{
		"%v": paths["%v"], "%+v": paths["%+v"], "%s": paths["%s"], "%x": paths["%x"], "Sprint": paths["Sprint"],
	} {
		if out := safeFormat(t, fn); out != redacted {
			t.Errorf("%s = %q, want %q", name, out, redacted)
		}
	}
}

// TestRedact_SecureBuffer_NoCrashNoLeak is the regression for the pre-release
// finding: printing a live *SecureBuffer with fmt's default struct printer
// reflected into the guarded region and crashed the process with an
// unrecoverable hardware fault (not a leak — a fault). Covers both the
// pointer and an accidental value dereference (the value-receiver dual
// coverage redact.go depends on).
func TestRedact_SecureBuffer_NoCrashNoLeak(t *testing.T) {
	t.Parallel()
	const secret = "TOP-SECRET-VALUE-DO-NOT-LEAK"
	buf, err := NewBuffer([]byte(secret))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	assertRedacted(t, secret, buf)
	assertRedacted(t, secret, *buf)
}

// TestRedact_SecureArena_NoCrashNoLeak covers SecureArena itself, via the
// embedded-arenaRedactor path. Only the pointer form is exercised: unlike
// SecureBuffer, copying a SecureArena BY VALUE is already a go vet copylocks
// error (it holds a value sync.Mutex) — go vet main.go with a bare
// fmt.Printf("%v", *arena) confirms vet rejects that call outright, so
// lint-clean code can never produce the dereferenced-value case redact.go's
// embedding also happens to cover. Only the pointer path is a real scenario.
func TestRedact_SecureArena_NoCrashNoLeak(t *testing.T) {
	t.Parallel()
	a, err := NewArena(32, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	assertRedacted(t, "", a)
}

// TestRedact_ArenaSlot_NoCrashNoLeak covers a LIVE slot from a real Acquire
// call, holding actual secret bytes, not just the zero value.
func TestRedact_ArenaSlot_NoCrashNoLeak(t *testing.T) {
	t.Parallel()
	const secret = "ARENA-SLOT-SECRET-VALUE"
	a, err := NewArena(32, 2)
	if err != nil {
		t.Fatalf("NewArena: %v", err)
	}
	defer func() { _ = a.Destroy() }()

	slot, err := a.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := slot.WithBytes(func(b []byte) { copy(b, secret) }); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}

	assertRedacted(t, secret, slot)
	assertRedacted(t, secret, *slot)
}

// TestRedact_ReadsNoFields proves the redaction methods are safe to call from
// inside a WithBytes callback (the whole point of reading no fields — they
// must never lock, since the buffer's lock is already held by the callback).
func TestRedact_ReadsNoFields(t *testing.T) {
	t.Parallel()
	buf, err := NewBuffer([]byte("does-not-matter"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if err := buf.WithBytes(func([]byte) {
		if buf.String() != redacted {
			t.Error("String() from inside WithBytes did not redact")
		}
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
}

// TestRedact_SurvivesDestroy proves the redaction is identical before and
// after Destroy — mirrors TestSecret_RedactionIgnoresState: lifecycle state
// must not be inferable from the redacted form, and — more importantly here —
// calling these methods post-Destroy (region.inner == nil) must not fault.
func TestRedact_SurvivesDestroy(t *testing.T) {
	t.Parallel()
	buf, err := NewBuffer([]byte("secret"))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	before := safeFormat(t, func() string { return fmt.Sprintf("%v %#v %s", buf, buf, buf) }) //nolint:gosimple
	if err := buf.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	after := safeFormat(t, func() string { return fmt.Sprintf("%v %#v %s", buf, buf, buf) }) //nolint:gosimple
	if before != after {
		t.Errorf("redacted form changed across Destroy: %q -> %q", before, after)
	}
}
