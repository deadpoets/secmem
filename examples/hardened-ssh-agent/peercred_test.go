//go:build unix

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestPeerUID_ReportsOurOwnUID guards the check that now gates every
// connection. If peerUID returns an error or the wrong uid, authorizePeer
// rejects everything and the agent silently stops working — a failure that
// presents as a networking problem, not as a security control misfiring.
//
// The reject path (a peer with a different uid) needs a second user and is not
// reachable from a test process.
func TestPeerUID_ReportsOurOwnUID(t *testing.T) {
	if !peerCredSupported {
		t.Skip("peer credentials are unavailable on this platform")
	}
	sock := filepath.Join(t.TempDir(), "peer.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	client, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer func() { _ = server.Close() }()

	uid, err := peerUID(server.(*net.UnixConn))
	if err != nil {
		t.Fatalf("peerUID: %v", err)
	}
	if want := uint32(os.Getuid()); uid != want {
		t.Errorf("peerUID = %d, want %d", uid, want)
	}
	if err := authorizePeer(server, testLogger()); err != nil {
		t.Errorf("authorizePeer rejected a connection from our own uid: %v", err)
	}
}
