//go:build linux

package main

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCredSupported reports whether peerUID can identify the process on the
// other end of a unix socket.
const peerCredSupported = true

// peerUID returns the effective uid of the process connected to c.
func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		cred *unix.Ucred
		serr error
	)
	if cerr := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); cerr != nil {
		return 0, cerr
	}
	if serr != nil {
		return 0, fmt.Errorf("SO_PEERCRED: %w", serr)
	}
	return cred.Uid, nil
}
