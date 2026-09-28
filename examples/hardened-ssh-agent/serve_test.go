//go:build unix

// serve_test.go proves the two availability controls in main.go, the way
// agent_test.go proves the memory ones: by doing to the agent what a hostile
// or broken local client would do and observing what happens on the wire,
// not by inspecting the semaphore or the deadline.
//
// Both controls are timed, so the tests shorten messageTimeout (a variable
// for exactly this purpose) and every "did not happen" observation is
// paired with a "then did happen" one on the same connection, so a pass
// cannot come from the agent simply being slow.
package main

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// TestServe_StalledClientIsDisconnectedAtDeadline: a client that connects and
// never completes a request is cut off when messageTimeout lapses — not
// before (it is a deadline, not a refusal) and not much after (it is this
// deadline, not some other limit). Three shapes of stall, because the
// deadline covers the whole message: nothing at all, part of the length
// prefix, and a length prefix whose body never arrives.
func TestServe_StalledClientIsDisconnectedAtDeadline(t *testing.T) {
	const timeout = 400 * time.Millisecond
	setForTest(t, &messageTimeout, timeout)
	sock, _, _ := startServer(t, false)

	cases := map[string][]byte{
		"silent":      nil,
		"half-header": {0, 0},
		"half-body":   {0, 0, 0, 10, agentcRequestIdentities, 1, 2},
	}
	for name, partial := range cases {
		t.Run(name, func(t *testing.T) {
			// start is taken before the dial, not after it: the agent arms
			// its deadline as soon as its accept goroutine wakes, which can
			// be before Dial has returned to this goroutine, so a start taken
			// after the dial could postdate the arming and make the lower
			// bound below flaky. Nothing can happen before the dial begins.
			start := time.Now()
			conn := dialAgent(t, sock)
			if len(partial) > 0 {
				if _, err := conn.Write(partial); err != nil {
					t.Fatalf("writing partial message: %v", err)
				}
			}
			// ...and then nothing. The agent must hang up on its own.
			if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			var b [1]byte
			n, err := conn.Read(b[:])
			elapsed := time.Since(start)
			if n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("stalled client read = (%d, %v) after %v, want (0, EOF): the agent did not disconnect it", n, err, elapsed)
			}
			if elapsed < timeout {
				t.Fatalf("disconnected after %v, before the %v deadline had passed", elapsed, timeout)
			}
			if elapsed > 10*timeout {
				t.Fatalf("disconnected after %v, far beyond the %v deadline", elapsed, timeout)
			}
		})
	}
}

// TestServe_DeadlineIsPerMessage: the deadline is re-armed for every request,
// so a long-lived client that pauses between requests — for less than the
// deadline each time but more than it in total — is served throughout. This
// is the guarantee that makes the deadline safe for real clients.
func TestServe_DeadlineIsPerMessage(t *testing.T) {
	const timeout = 400 * time.Millisecond
	setForTest(t, &messageTimeout, timeout)
	sock, _, _ := startServer(t, false)
	conn := dialAgent(t, sock)

	// Three requests with a pause of half the deadline before each: 600ms
	// of idling in total against a 400ms deadline.
	for i := 0; i < 3; i++ {
		time.Sleep(timeout / 2)
		reply, err := rawRequest(t, conn, requestIdentities, 5*time.Second)
		if err != nil {
			t.Fatalf("request %d after %v idle: %v; the deadline was not re-armed per message", i+1, timeout/2, err)
		}
		if len(reply) == 0 || reply[0] != agentIdentitiesAnswer {
			t.Fatalf("request %d: reply %v, want an identities answer", i+1, reply)
		}
	}
}

// TestServe_ConnectionCapMakesExcessWait: with the cap at two, a third
// connection is neither served nor refused — it waits — and is served as soon
// as one of the first two ends. Its request is written while it waits, so the
// eventual reply proves the connection was queued intact, not dropped and
// re-dialled.
func TestServe_ConnectionCapMakesExcessWait(t *testing.T) {
	setForTest(t, &maxConns, 2)
	sock, _, _ := startServer(t, false)

	first := dialAgent(t, sock)
	second := dialAgent(t, sock)
	for i, conn := range []net.Conn{first, second} {
		if _, err := rawRequest(t, conn, requestIdentities, 5*time.Second); err != nil {
			t.Fatalf("connection %d, within the cap, was not served: %v", i+1, err)
		}
	}

	// The third connection completes at the kernel (it sits in the listen
	// backlog), so dialling and writing succeed; what must NOT happen is a
	// reply, and what must not happen either is a hang-up.
	third := dialAgent(t, sock)
	_, err := rawRequest(t, third, requestIdentities, 500*time.Millisecond)
	switch {
	case err == nil:
		t.Fatal("third connection was served with the cap at two")
	case errors.Is(err, io.EOF):
		t.Fatal("third connection was refused (EOF); maxConns documents that excess connections wait")
	case !errors.Is(err, os.ErrDeadlineExceeded):
		t.Fatalf("third connection: %v, want a read timeout (waiting, unserved)", err)
	}

	// Free a slot. The queued connection must now be served, and the
	// request it wrote while waiting answered.
	if err := first.Close(); err != nil {
		t.Fatalf("closing first connection: %v", err)
	}
	if err := third.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	reply, err := readMessage(third)
	if err != nil {
		t.Fatalf("third connection after a slot freed: %v, want the reply to the request it queued", err)
	}
	if len(reply) == 0 || reply[0] != agentIdentitiesAnswer {
		t.Fatalf("third connection reply %v, want an identities answer", reply)
	}

	// The connection that stayed within the cap throughout is unaffected.
	if _, err := rawRequest(t, second, requestIdentities, 5*time.Second); err != nil {
		t.Fatalf("second connection after the reshuffle: %v", err)
	}
}

// TestServe_ShutdownClosesLiveConnections: stopping the server disconnects a
// client that is sitting inside its (here, full-length) 30 s deadline, and
// serve returns without waiting for that deadline — stop fails the test if
// serve takes more than 10 s, a third of it. This is what lets run() exit
// promptly on SIGTERM with idle clients attached.
func TestServe_ShutdownClosesLiveConnections(t *testing.T) {
	sock, _, stop := startServer(t, false)
	conn := dialAgent(t, sock)
	// Prove the connection is live and being served before shutting down.
	if _, err := rawRequest(t, conn, requestIdentities, 5*time.Second); err != nil {
		t.Fatalf("request before shutdown: %v", err)
	}

	stop()

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var b [1]byte
	if n, err := conn.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("client read after shutdown = (%d, %v), want (0, EOF): the connection was left open", n, err)
	}
}
