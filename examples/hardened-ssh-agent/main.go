//go:build unix

// secmem-agent: a minimal SSH agent whose keys are never at rest on the Go
// heap. The wire message an add arrives in is one heap buffer, wiped after
// dispatch.
//
//	$ go run . &
//	$ export SSH_AUTH_SOCK=/run/user/1000/secmem-agent/agent.sock  # printed at start
//	$ ssh-add ~/.ssh/id_ed25519
//	$ ssh somewhere
//
// What "hardened" means here, concretely — each item is a secmem feature
// doing load-bearing work, not decoration:
//
//	keys off-heap, mlocked, guard-paged   secmem.SecureBuffer     keyring.go
//	kernel-invisible where possible       memfd_secret (probed)   secmem alloc
//	sealed PROT_NONE while idle           Seal/Unseal             keyring.go Sign
//	lock passphrase never stored          Argon2id → SecureBuffer keyring.go Lock
//	constant-time unlock comparison       ConstantTimeEqual       keyring.go Unlock
//	no core dumps, no new privs           HardenProcess           main.go
//	mlock budget raised up front          EnsureMemlockLimit      main.go
//	wipe on SIGINT/SIGTERM                InstallTerminationWipe  main.go
//	wire transients wiped every message   SecureWipe              serveConn
//	log output is filtered                redact.NewHandler       main.go
//	honest capability report at boot      Probe().Warnings()      main.go
//
// Two plain-Go controls guard the socket's availability rather than the
// keys' confidentiality, because an agent that can be pinned by anyone who
// connects is not hardened either: every client gets messageTimeout to
// deliver each request (serveConn), and at most maxConns clients are
// served at once (serve). Both are stated, with what they do not cover,
// in README.md's threat-model section.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/redact"
	secmemcrypto "github.com/deadpoets/secmem/secmem-crypto"
)

// messageTimeout is how long a connected client has to deliver one complete
// request — from the moment the agent is ready for it to the last byte of
// its body — and, symmetrically, how long the agent gives itself to hand
// the reply to the kernel. It is re-armed for every message, so a client
// that stays busy is never cut off; a client that connects and sends
// nothing, or stalls halfway through a message, is disconnected when it
// lapses. Without it one idle connection pins a goroutine and a connection
// slot for as long as the client cares to hold the socket open.
//
// 30 s is far above the round-trip any real client needs (ssh-add and ssh
// send their request as soon as they connect) while short enough that a
// stalled connection releases its slot before anyone notices the wait.
// OpenSSH's own clients hold an agent connection only while using it and
// are unaffected. What this does disconnect is any client that holds a
// connection idle for that long — including a long-lived program on an
// agent-forwarding (ssh -A) host that opens SSH_AUTH_SOCK once and reuses
// it — whose next request then fails (EOF or EPIPE) and which must
// reconnect. OpenSSH's ssh-agent has no such timeout.
//
// A variable rather than a constant only so the tests can shorten it;
// nothing outside the tests assigns to it.
var messageTimeout = 30 * time.Second

// maxConns is the number of client connections served at once. The
// (maxConns+1)th connection is not refused: it stays in the kernel's listen
// backlog — completed, but with nothing read from it — until a served
// connection ends, and is then served in turn. That holds up to the size
// of the listen backlog (net.core.somaxconn, 4096 by default on Linux 5.4
// and later, 128 before); connections beyond it fail at the kernel with
// EAGAIN, a limit no user-space cap can move. Waiting rather than refusing keeps a legitimate
// burst (a parallel deploy opening dozens of sessions) working instead of
// failing at random, and with messageTimeout above an idle slot is
// reclaimed within that interval, so waiting behind idle connections is
// bounded. Waiting behind maxConns *active* connections is not; see the
// README's threat model.
//
// Taking a slot before accept, rather than after, is what bounds the
// process: a connection that is never accepted costs it no goroutine and
// no file descriptor. 64 is generous for a human-rate service and small
// against any descriptor limit.
//
// A variable rather than a constant only so the tests can lower it;
// nothing outside the tests assigns to it.
var maxConns = 64

func main() {
	socketPath := flag.String("socket", "", "unix socket path (default: private dir under $XDG_RUNTIME_DIR or the system temp dir)")
	allowHeapTransients := flag.Bool("allow-heap-transients", false,
		"accept ECDSA keys on a build where each ECDSA signature leaves unwiped copies of the private scalar on the heap "+
			"(every build without GOEXPERIMENT=runtimesecret); Ed25519 keys are unaffected")
	flag.Parse()

	// Logging first, through the redaction handler: even a future bug
	// that logs the wrong variable passes through a sanitizer that
	// redacts credential-shaped and high-entropy strings. Defense in
	// depth for the observability channel, which is where in-memory
	// secrets most often actually escape.
	logger := slog.New(redact.NewHandler(
		slog.NewTextHandler(os.Stderr, nil),
		redact.NewDefaultSanitizer(),
	))
	slog.SetDefault(logger)

	if err := run(*socketPath, *allowHeapTransients, logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(socketPath string, allowHeapTransients bool, logger *slog.Logger) error {
	// ---- Process hardening, before any key exists ----------------------

	// Core dumps off, no-new-privs on (Linux; best effort per platform).
	// A crash after this point does not write key pages to disk.
	level, err := secmem.HardenProcess(context.Background())
	if err != nil {
		// Report and continue: partial hardening beats refusing to run,
		// but the operator must see exactly what they did not get.
		logger.Warn("process hardening incomplete", "achieved", level, "err", err)
	} else {
		logger.Info("process hardened", "level", level)
	}

	// Raise RLIMIT_MEMLOCK so key allocations never silently lose mlock.
	// 8 MiB covers hundreds of keys plus lock state.
	if achieved, err := secmem.EnsureMemlockLimit(8 << 20); err != nil {
		logger.Warn("memlock limit not raised", "achieved_bytes", achieved, "err", err)
	}

	// Honesty at boot: print what this platform actually guarantees.
	// A reviewer or operator should never have to guess.
	caps := secmem.Probe()
	logger.Info("secure memory capabilities", "report", caps.String())
	for _, w := range caps.Warnings() {
		logger.Warn("capability warning", "warning", w)
	}

	// Which identities this build will hold without breaking the "keys
	// never at rest on the heap" claim. Ed25519 signs in place everywhere; ECDSA
	// signs through the standard library, whose per-signature copies of
	// the scalar only runtime/secret erases.
	switch {
	case secmem.RuntimeSecretActive():
		logger.Info("ECDSA identities accepted", "why", "runtime/secret erases each signature's heap copies of the scalar")
	case allowHeapTransients:
		logger.Warn("ECDSA identities accepted by -allow-heap-transients",
			"residual", "each ECDSA signature leaves unwiped copies of the private scalar on the heap, one cached until the collector evicts it")
	default:
		logger.Info("ECDSA identities will be refused on this build; Ed25519 only",
			"remedy", "build with GOEXPERIMENT=runtimesecret on linux/amd64 or linux/arm64, or pass -allow-heap-transients to accept the residual")
	}

	// Backstop: if the process is killed by SIGINT/SIGTERM before the
	// orderly shutdown below runs, registered secure buffers are wiped
	// in the signal path.
	uninstallWipe := secmem.InstallTerminationWipe(syscall.SIGINT, syscall.SIGTERM)
	defer uninstallWipe()

	// ---- Socket --------------------------------------------------------

	if socketPath == "" {
		base := os.Getenv("XDG_RUNTIME_DIR")
		if base == "" {
			base = os.TempDir()
		}
		dir := filepath.Join(base, fmt.Sprintf("secmem-agent-%d", os.Getpid()))
		//nolint:gosec // G703: dir is $XDG_RUNTIME_DIR (or the temp dir) joined with our own pid — not attacker-controlled path input.
		if err := os.Mkdir(dir, 0o700); err != nil {
			return fmt.Errorf("creating socket dir: %w", err)
		}
		socketPath = filepath.Join(dir, "agent.sock")
	}

	// 0077 umask around Listen so the socket is never world-connectable,
	// even for an instant; then belt-and-braces chmod.
	oldMask := syscall.Umask(0o077)
	ln, err := net.Listen("unix", socketPath)
	syscall.Umask(oldMask)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", socketPath, err)
	}
	defer func() { _ = ln.Close() }()
	//nolint:gosec // G703: socketPath is our generated path or the operator's own --socket value (as with ssh-agent -a); cleaning it up is intended.
	defer func() { _ = os.Remove(socketPath) }()
	//nolint:gosec // G703: see above — the operator names the socket they run; chmod'ing it is intended.
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("restricting socket permissions: %w", err)
	}

	keyring := NewKeyring(allowHeapTransients)
	defer keyring.DestroyAll()

	// Orderly shutdown: destroy keys (full wipe + unmap), then cancel the
	// context, which makes serve close the listener and every live
	// connection and return; the deferred calls above remove the socket.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		logger.Info("shutting down", "signal", s.String())
		keyring.DestroyAll()
		cancel()
	}()

	logger.Info("agent ready", "socket", socketPath)
	fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", socketPath)

	return serve(ctx, ln, keyring, logger)
}

// serve accepts connections on ln and serves each on its own goroutine, at
// most maxConns at a time, until ctx is canceled or ln fails. It returns
// only after every connection goroutine it started has ended: canceling
// ctx closes the listener and every live connection, so a client that is
// mid-request cannot hold the process open, and once serve has returned
// nothing it started is still running. An orderly stop returns nil.
func serve(ctx context.Context, ln net.Listener, keyring *Keyring, logger *slog.Logger) error {
	ctx, cancel := context.WithCancel(ctx)
	var conns sync.WaitGroup
	defer func() {
		cancel()     // closes the listener and every live connection (AfterFunc below)
		conns.Wait() // ...and outlives none of their goroutines
	}()
	stopListener := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stopListener()

	// slots is the connection semaphore: a send takes a slot, a receive
	// returns it. It is taken BEFORE Accept, so an excess connection waits
	// in the kernel's backlog and costs this process nothing — see maxConns.
	slots := make(chan struct{}, maxConns)
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return nil // orderly shutdown while every slot was busy
		}
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil // orderly shutdown
			}
			return fmt.Errorf("accept: %w", err)
		}
		conns.Add(1)
		go func() {
			defer conns.Done()
			defer func() { <-slots }()
			// Shutdown reaches a connection blocked in a read or a write
			// only by closing it under the goroutine, which makes that
			// call fail and serveConn return.
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stop()
			serveConn(conn, keyring, logger)
		}()
	}
}

// serveConn handles one client connection: read message, dispatch, reply,
// wipe. Any protocol error ends the connection; any semantic error (bad
// passphrase, unknown key, unsupported operation) returns AGENT_FAILURE
// and the connection continues, which is what OpenSSH clients expect.
//
// Each message read and each reply write runs under a fresh messageTimeout
// deadline, so the goroutine — and the connection slot it holds — cannot be
// pinned by a client that goes quiet, stalls mid-message, or stops reading
// its replies. The deadline is per message, not per connection: a client
// that keeps making requests is never disconnected for being long-lived.
func serveConn(conn net.Conn, keyring *Keyring, logger *slog.Logger) {
	defer func() { _ = conn.Close() }()
	for {
		// Armed before the length prefix and covering the body too, so a
		// half-sent message lapses like a silent connection does.
		if err := conn.SetReadDeadline(time.Now().Add(messageTimeout)); err != nil {
			logger.Debug("connection ended", "err", err)
			return
		}
		msg, err := readMessage(conn)
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				// Clean disconnect.
			case errors.Is(err, os.ErrDeadlineExceeded):
				logger.Debug("connection idle past deadline", "timeout", messageTimeout)
			default:
				logger.Debug("connection ended", "err", err)
			}
			return
		}
		reply := dispatch(msg, keyring, logger)

		// THE wipe: msg may contain a private key (ADD_IDENTITY) or a
		// lock passphrase (LOCK/UNLOCK). Every parser returned aliases
		// into msg, so this one call destroys all transient copies.
		// After it, key material exists only inside sealed SecureBuffers.
		secmem.SecureWipe(msg)

		// The write deadline starts now, after dispatch, so a reply that
		// waited its turn behind other requests (Keyring serializes them)
		// is not charged for the wait. A client that stops draining its
		// replies eventually fills the socket buffer and then lapses here.
		if err := conn.SetWriteDeadline(time.Now().Add(messageTimeout)); err != nil {
			logger.Debug("connection ended", "err", err)
			return
		}
		if err := writeMessage(conn, reply); err != nil {
			logger.Debug("write failed", "err", err)
			return
		}
	}
}

var (
	replyFailure = []byte{agentFailure}
	replySuccess = []byte{agentSuccess}
)

func dispatch(msg []byte, keyring *Keyring, logger *slog.Logger) []byte {
	if len(msg) == 0 {
		return replyFailure
	}
	msgType, body := msg[0], msg[1:]

	switch msgType {
	case agentcRequestIdentities:
		ids := keyring.List()
		reply := []byte{agentIdentitiesAnswer, 0, 0, 0, 0}
		//nolint:gosec // G115: identity count, bounded far below uint32 max.
		binary.BigEndian.PutUint32(reply[1:5], uint32(len(ids)))
		for _, id := range ids {
			reply = appendString(reply, id.Blob)
			reply = appendString(reply, []byte(id.Comment))
		}
		return reply

	case agentcSignRequest:
		req, err := parseSignRequest(body)
		if err != nil {
			logger.Debug("malformed sign request", "err", err)
			return replyFailure
		}
		sig, err := keyring.Sign(req.keyBlob, req.data)
		if err != nil {
			logger.Debug("sign refused", "err", err)
			return replyFailure
		}
		reply := []byte{agentSignResponse}
		return appendString(reply, ssh.Marshal(sig))

	case agentcAddIdentity, agentcAddIDConstrained:
		req, err := parseAddIdentity(body, msgType == agentcAddIDConstrained)
		if err != nil {
			logger.Debug("add refused", "err", err)
			return replyFailure
		}
		if err := keyring.Add(req); err != nil {
			// A policy refusal is logged where the operator will see it:
			// ssh-add only reports "agent refused operation".
			if errors.Is(err, secmemcrypto.ErrHeapTransients) {
				logger.Warn("ECDSA identity refused on this build",
					"remedy", "build with GOEXPERIMENT=runtimesecret on linux/amd64 or linux/arm64, or restart with -allow-heap-transients")
			} else {
				logger.Debug("add refused", "err", err)
			}
			return replyFailure
		}
		logger.Info("identity added", "comment", req.comment)
		return replySuccess

	case agentcRemoveIdentity:
		blob, _, err := readString(body)
		if err != nil || keyring.Remove(blob) != nil {
			return replyFailure
		}
		logger.Info("identity removed")
		return replySuccess

	case agentcRemoveAll:
		if keyring.RemoveAll() != nil {
			return replyFailure
		}
		logger.Info("all identities removed")
		return replySuccess

	case agentcLock:
		pass, _, err := readString(body)
		if err != nil || keyring.Lock(pass) != nil {
			return replyFailure
		}
		logger.Info("agent locked")
		return replySuccess

	case agentcUnlock:
		pass, _, err := readString(body)
		if err != nil || keyring.Unlock(pass) != nil {
			logger.Info("unlock refused")
			return replyFailure
		}
		logger.Info("agent unlocked")
		return replySuccess

	default:
		// sk-* keys, certificates, protocol extensions: honest failure,
		// clean connection. See README "Forking guide".
		logger.Debug("unsupported message", "type", msgType)
		return replyFailure
	}
}
