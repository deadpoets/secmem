//go:build unix

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
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

// startServer runs the agent's real accept loop — serve, with its connection
// cap and per-message deadline — on a fresh unix socket and returns the
// socket path, the keyring behind it, and a stop function. stop halts the
// server the way a signal does (context cancellation) and WAITS for serve to
// return, failing the test if it does not; it runs at cleanup whether or not
// the test called it. Because it waits, cleanups registered before
// startServer — the ones that restore messageTimeout or maxConns — run after
// the last goroutine that could read those variables has ended.
func startServer(t *testing.T, allowHeapTransients bool) (sock string, keyring *Keyring, stop func()) {
	t.Helper()
	sock = filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	keyring = NewKeyring(allowHeapTransients)
	t.Cleanup(keyring.DestroyAll)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln, keyring, testLogger()) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("serve returned %v, want nil on an orderly stop", err)
				}
			case <-time.After(10 * time.Second):
				t.Errorf("serve did not return within 10s of cancellation")
			}
		})
	}
	t.Cleanup(stop)
	return sock, keyring, stop
}

// dialAgent connects to the agent socket; the connection is closed at the
// end of the test.
func dialAgent(t *testing.T, sock string) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// setForTest assigns v to *p for the duration of the test. Call it BEFORE
// startServer: cleanups run last-registered first, so the restore then
// happens after the server has stopped, never concurrently with it.
func setForTest[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// rawRequest writes one agent message on conn and reads the reply, giving
// the agent at most wait to answer. It speaks the wire format directly, with
// the agent's own framing helpers, so a test can observe what the reference
// client hides: a reply that does not come, or a connection the agent closed.
func rawRequest(t *testing.T, conn net.Conn, msg []byte, wait time.Duration) ([]byte, error) {
	t.Helper()
	if err := writeMessage(conn, msg); err != nil {
		t.Fatalf("writing request: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	return readMessage(conn)
}

// requestIdentities is the smallest complete request the agent answers:
// SSH_AGENTC_REQUEST_IDENTITIES, whose reply on an empty keyring is a
// five-byte SSH_AGENT_IDENTITIES_ANSWER with a count of zero.
var requestIdentities = []byte{agentcRequestIdentities}
