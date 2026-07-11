package redact_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/deadpoets/secmem/redact"
)

// newTextLogger returns a slog.Logger writing sanitized text to buf.
func newTextLogger(buf *bytes.Buffer) *slog.Logger {
	inner := slog.NewTextHandler(buf, &slog.HandlerOptions{
		// Drop time so assertions are stable.
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	return slog.New(redact.NewHandler(inner, nil))
}

func TestHandler_SanitizesMessage(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	newTextLogger(&buf).Info("login password=hunter2 done")
	if strings.Contains(buf.String(), "hunter2") {
		t.Errorf("handler leaked secret in message: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "[REDACTED:password_field]") {
		t.Errorf("handler did not tag message: %q", buf.String())
	}
}

func TestHandler_SanitizesStringAttr(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	newTextLogger(&buf).Info("connect", "creds", "token=abc-secret-123")
	if strings.Contains(buf.String(), "abc-secret-123") {
		t.Errorf("handler leaked secret in attr: %q", buf.String())
	}
}

func TestHandler_SanitizesErrorAttr(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := errors.New("failed with password=leaked")
	newTextLogger(&buf).Error("boom", "err", err)
	if strings.Contains(buf.String(), "leaked") {
		t.Errorf("handler leaked secret in error attr: %q", buf.String())
	}
}

func TestHandler_SanitizesInjectionInAttr(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	newTextLogger(&buf).Info("req", "path", "a\r\nInjected: fake")
	// The text handler quotes values, so a raw newline must not appear.
	if strings.Contains(buf.String(), "\r") {
		t.Errorf("CRLF survived into output: %q", buf.String())
	}
}

func TestHandler_SanitizesGroupAndWithAttrs(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	logger := slog.New(redact.NewHandler(inner, nil)).
		With("session", "token=with-attrs-secret").
		WithGroup("req")
	logger.Info("handled", "body", "password=inline-secret")

	out := buf.String()
	if strings.Contains(out, "with-attrs-secret") {
		t.Errorf("WithAttrs secret leaked: %q", out)
	}
	if strings.Contains(out, "inline-secret") {
		t.Errorf("grouped inline secret leaked: %q", out)
	}
}

// TestHandler_SanitizesLogValuer proves a lazily-resolved LogValuer string is
// still scrubbed — the resolution happens inside the handler.
func TestHandler_SanitizesLogValuer(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	newTextLogger(&buf).Info("lazy", "v", lazySecret{})
	if strings.Contains(buf.String(), "lazy-leaked") {
		t.Errorf("LogValuer secret leaked: %q", buf.String())
	}
}

type lazySecret struct{}

func (lazySecret) LogValue() slog.Value { return slog.StringValue("password=lazy-leaked") }

func TestHandler_NilInnerDiscards(t *testing.T) {
	t.Parallel()
	// Must not panic; output goes nowhere.
	slog.New(redact.NewHandler(nil, nil)).Info("password=whatever")
}

func TestHandler_PassesNumericAttrsThrough(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	newTextLogger(&buf).Info("metrics", "count", 42, "ratio", 3.14)
	if !strings.Contains(buf.String(), "count=42") || !strings.Contains(buf.String(), "ratio=3.14") {
		t.Errorf("numeric attrs mangled: %q", buf.String())
	}
}

// TestHandler_Enabled proves level filtering delegates to the inner handler.
func TestHandler_Enabled(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	h := redact.NewHandler(inner, nil)
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Enabled(Info) = true, want false (inner is Warn)")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Enabled(Error) = false, want true")
	}
}
