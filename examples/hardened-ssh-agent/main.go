//go:build unix

// secmem-agent: a minimal SSH agent whose keys never touch the Go heap.
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
//	log output cannot leak secrets        redact.NewHandler       main.go
//	honest capability report at boot      Probe().Warnings()      main.go
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
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/redact"
)

func main() {
	socketPath := flag.String("socket", "", "unix socket path (default: private dir under $XDG_RUNTIME_DIR or the system temp dir)")
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

	if err := run(*socketPath, logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(socketPath string, logger *slog.Logger) error {
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

	keyring := NewKeyring()
	defer keyring.DestroyAll()

	// Orderly shutdown: destroy keys (full wipe + unmap), remove socket.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		logger.Info("shutting down", "signal", s.String())
		keyring.DestroyAll()
		_ = ln.Close()
	}()

	logger.Info("agent ready", "socket", socketPath)
	fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", socketPath)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil // orderly shutdown
			}
			return fmt.Errorf("accept: %w", err)
		}
		go serveConn(conn, keyring, logger)
	}
}

// serveConn handles one client connection: read message, dispatch, reply,
// wipe. Any protocol error ends the connection; any semantic error (bad
// passphrase, unknown key, unsupported operation) returns AGENT_FAILURE
// and the connection continues, which is what OpenSSH clients expect.
func serveConn(conn net.Conn, keyring *Keyring, logger *slog.Logger) {
	defer func() { _ = conn.Close() }()
	for {
		msg, err := readMessage(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
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
			logger.Debug("add refused", "err", err)
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
