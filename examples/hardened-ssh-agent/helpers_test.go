//go:build unix

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"testing"
)

// testLogger discards output; the tests assert behavior, not log lines.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// generateSmallRSA makes a deliberately small RSA key — it exists only to
// be refused by the agent, so key strength is irrelevant and speed wins.
func generateSmallRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}
