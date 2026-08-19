// password-login is a minimal registration + login flow showing the two
// habits that matter when handling passwords in Go:
//
//  1. The password ceases to exist as plaintext the moment it has been
//     used: the input bytes are wiped with secmem.SecureWipe, and only an
//     Argon2id derivation — held in a SecureBuffer, off the Go heap —
//     survives.
//
//  2. Verification is a constant-time comparison of derivations
//     (SecureBuffer.ConstantTimeEqual), never a byte-wise compare of
//     anything an attacker can time.
//
// Contrast with the common pattern this replaces:
//
//	hash, _ := argon2.IDKey(password, salt, ...)   // BAD: derivation on GC heap
//	if bytes.Equal(hash, stored) { ... }           // BAD: not constant-time
//	// ... and `password` is never wiped at all.
//
// Run it:
//
//	go run . register alice
//	go run . login alice
//
// (Passwords are read from stdin; the "database" is a file of salt +
// derivation, which is safe to store — that is the point of a KDF.)
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/deadpoets/secmem"
	secmemcrypto "github.com/deadpoets/secmem/secmem-crypto"
)

const (
	saltLen = 16
	keyLen  = 32

	// maxPasswordLen bounds the secure allocation. Longer input is an error,
	// not a silent truncation — truncating would let a prefix log in.
	maxPasswordLen = 256
)

func main() {
	if len(os.Args) != 3 || (os.Args[1] != "register" && os.Args[1] != "login") {
		fmt.Fprintln(os.Stderr, "usage: password-login {register|login} <user>")
		os.Exit(2)
	}
	cmd, user := os.Args[1], os.Args[2]

	if err := run(cmd, user); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(cmd, user string) error {
	// The username keys the on-disk record file, so validate it before it can
	// reach WriteFile/ReadFile: a crafted argument like "../secrets" must not
	// steer the path outside the working directory. Checking untrusted input at
	// the boundary is the habit worth teaching — the KDF is not the only part
	// that has to be right.
	if user == "" || strings.ContainsAny(user, `/\`) || user == "." || user == ".." {
		return fmt.Errorf("invalid user %q: use a bare name with no path separators", user)
	}

	fmt.Print("password: ")
	password, err := readPassword(os.Stdin)
	if err != nil {
		return err
	}
	// The password now lives only in secure memory, and is destroyed on every
	// path out of this function. From here down it is borrowed, never copied.
	defer func() { _ = password.Destroy() }()

	switch cmd {
	case "register":
		return register(user, password)
	default:
		return login(user, password)
	}
}

func register(user string, password *secmem.SecureBuffer) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	// Derive straight into secure memory: the derivation never exists as
	// a plain []byte the GC could copy or that could linger unwiped.
	derived, err := secmem.NewEmptyBuffer(keyLen)
	if err != nil {
		return err
	}
	defer func() { _ = derived.Destroy() }()
	if err := password.WithBytesErr(func(p []byte) error {
		return secmemcrypto.Argon2DeriveInto(p, salt, derived)
	}); err != nil {
		return err
	}

	// The stored record is salt + derivation — designed to be safe at
	// rest, so borrowing it out for persistence is correct, not a leak.
	var record string
	err = derived.WithBytesErr(func(d []byte) error {
		record = hex.EncodeToString(salt) + ":" + hex.EncodeToString(d) + "\n"
		return nil
	})
	if err != nil {
		return err
	}
	//nolint:gosec // G703: user is validated to a bare name (no path separators) in run().
	if err := os.WriteFile(dbPath(user), []byte(record), 0o600); err != nil {
		return err
	}
	fmt.Println("registered", user)
	return nil
}

func login(user string, password *secmem.SecureBuffer) error {
	//nolint:gosec // G703: user is validated to a bare name (no path separators) in run().
	raw, err := os.ReadFile(dbPath(user))
	if err != nil {
		return fmt.Errorf("no such user (register first?): %w", err)
	}
	parts := strings.SplitN(strings.TrimSpace(string(raw)), ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("corrupt record for %s", user)
	}
	salt, err1 := hex.DecodeString(parts[0])
	stored, err2 := hex.DecodeString(parts[1])
	if err1 != nil || err2 != nil || len(salt) != saltLen || len(stored) != keyLen {
		return fmt.Errorf("corrupt record for %s", user)
	}

	candidate, err := secmem.NewEmptyBuffer(keyLen)
	if err != nil {
		return err
	}
	defer func() { _ = candidate.Destroy() }()
	if err := password.WithBytesErr(func(p []byte) error {
		return secmemcrypto.Argon2DeriveInto(p, salt, candidate)
	}); err != nil {
		return err
	}

	// Constant time: the comparison's duration is independent of how
	// many leading bytes match, so response timing teaches an attacker
	// nothing about the derivation.
	ok, err := candidate.ConstantTimeEqual(stored)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("login failed")
	}
	fmt.Println("welcome,", user)
	return nil
}

// readPassword reads one line from f into secure memory with terminal echo
// disabled, a byte at a time.
//
// The obvious version leaks the password three times over:
//
//	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')  // 4 KiB buffer keeps a copy
//	password := []byte(strings.TrimRight(line, "\r\n"))    // via two immutable strings
//
// A Go string cannot be wiped and neither copy is reachable to try, so the
// plaintext outlives the program's care by however long the GC takes. Reading
// straight into a SecureBuffer keeps it in memory this program can erase, which
// is the whole claim the example is making.
func readPassword(f *os.File) (*secmem.SecureBuffer, error) {
	fd := int(f.Fd())
	if term.IsTerminal(fd) {
		// Raw mode does two jobs here: the password does not appear on screen,
		// and bytes arrive as typed rather than through a line buffer nobody
		// can wipe.
		state, err := term.MakeRaw(fd)
		if err != nil {
			return nil, fmt.Errorf("disabling terminal echo: %w", err)
		}
		defer func() {
			_ = term.Restore(fd, state)
			fmt.Fprintln(os.Stderr) // the un-echoed Enter still needs a newline
		}()
	}

	buf, err := secmem.NewEmptyBuffer(maxPasswordLen)
	if err != nil {
		return nil, err
	}
	var one [1]byte
	defer secmem.SecureWipe(one[:])

	n := 0
readLoop:
	for {
		read, rerr := f.Read(one[:])
		if read == 0 {
			if n == 0 && rerr != nil {
				_ = buf.Destroy()
				return nil, rerr
			}
			break // EOF ends the line, same as Enter
		}
		switch c := one[0]; {
		case c == '\n' || c == '\r':
			break readLoop
		case c == 0x03: // ^C, which raw mode delivers to us instead of the kernel
			_ = buf.Destroy()
			return nil, errors.New("interrupted")
		case c == 0x7f || c == 0x08: // backspace
			if n > 0 {
				n--
				_ = buf.SetByteAt(n, 0)
			}
		case n == maxPasswordLen:
			_ = buf.Destroy()
			return nil, fmt.Errorf("password longer than %d bytes", maxPasswordLen)
		default:
			if err := buf.SetByteAt(n, c); err != nil {
				_ = buf.Destroy()
				return nil, err
			}
			n++
		}
	}
	if err := buf.Truncate(n); err != nil {
		_ = buf.Destroy()
		return nil, err
	}
	return buf, nil
}

func dbPath(user string) string {
	return "pwdb-" + user + ".txt"
}
