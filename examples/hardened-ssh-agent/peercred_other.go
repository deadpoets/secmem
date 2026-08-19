//go:build unix && !linux && !darwin && !freebsd

package main

import (
	"errors"
	"net"
)

// The remaining unix platforms each expose peer credentials differently and
// x/sys/unix has no typed accessor for them: OpenBSD wants SO_PEERCRED with
// struct sockpeercred, NetBSD LOCAL_PEEREID with struct unpcbid. Both are
// straightforward to add; until someone needs one, this agent refuses to start
// rather than serve connections it cannot attribute.
const peerCredSupported = false

func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials are not available on this platform")
}
