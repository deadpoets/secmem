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
//     anything an attacker can time — and a failed login is uniform in
//     both message and cost, so neither tells whether the account exists
//     (see login).
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
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"unicode/utf8"

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

// errLoginFailed is the one answer a refused login gets, whether the user
// does not exist or the password was wrong. A message that distinguished the
// two ("no such user") would hand out the list of accounts to anyone who can
// try to log in; so would a refusal that comes back in a microsecond instead
// of after a derivation. Which of the two it was is logged at debug level
// (see login), a level this program never enables — the reason is for a
// developer with the source, not for the person typing the password.
var errLoginFailed = errors.New("login failed")

// errUserExists is register's refusal of a name that already has a record.
// Unlike a login, a registration cannot hide whether the name is taken:
// accepting it would mean replacing the account.
var errUserExists = errors.New("user already exists")

// dummySalt and dummyStored stand in for the record of a user who does not
// exist, so that login runs the same Argon2id derivation against them that it
// runs against a real record and a refusal costs the same either way. Their
// values are arbitrary: dummyStored is not the derivation of anything, and
// login does not rely on that — a missing user fails by construction after
// the comparison, whatever the comparison said. Fixed, not per-process
// random, because nothing about them is ever revealed: the derivation is
// discarded.
var (
	dummySalt   = [saltLen]byte{0x73, 0x65, 0x63, 0x6d, 0x65, 0x6d, 0x2d, 0x6e, 0x6f, 0x2d, 0x75, 0x73, 0x65, 0x72, 0x21, 0x21}
	dummyStored = [keyLen]byte{0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
		0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a}
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
	// secmem-lint flags the hex encoding as a heap copy of borrowed bytes,
	// which it is; the copy is the verifier this function exists to write.
	var record string
	err = derived.WithBytesErr(func(d []byte) error {
		record = hex.EncodeToString(salt) + ":" + hex.EncodeToString(d) + "\n" //nolint:secmem-lint // the derivation is the stored verifier; persisting it is the point
		return nil
	})
	if err != nil {
		return err
	}
	// O_EXCL: the record is created, never replaced. Writing over an
	// existing one would let whoever can register set a new password on
	// someone else's account.
	//nolint:gosec // G703: user is validated to a bare name (no path separators) in run().
	f, err := os.OpenFile(dbPath(user), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%w: %s", errUserExists, user)
	}
	if err != nil {
		return err
	}
	if _, err := f.WriteString(record); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Println("registered", user)
	return nil
}

func login(user string, password *secmem.SecureBuffer) error {
	// Whether the user exists is decided here and acted on only at the very
	// end: an unknown user gets the dummy record and the same derivation and
	// comparison a real one gets, so the two refusals differ by one
	// predictable branch, not by a 64 MiB Argon2id derivation.
	salt, stored, known, err := loadRecord(user)
	if err != nil {
		return err
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
	if !known || !ok {
		// One error for both reasons — see errLoginFailed. The reason is
		// kept for whoever is debugging with the source, at a level the
		// program never turns on; it is never part of the answer.
		slog.Debug("login refused", "user", user, "known", known)
		return errLoginFailed
	}
	fmt.Println("welcome,", user)
	return nil
}

// loadRecord reads user's stored salt and verifier. A user with no record is
// not an error: known is false and the dummy record is returned in place of
// theirs, so that login's cost does not depend on the answer. A record that
// exists but cannot be parsed IS an error, and a specific one: it names a
// damaged file the operator has to fix, not the outcome of a guess, and a
// guesser learns nothing from it that registering the name would not tell
// them. Any other failure to read the file (permissions, I/O) is likewise
// the operator's, and is returned as is.
func loadRecord(user string) (salt, stored []byte, known bool, err error) {
	//nolint:gosec // G703: user is validated to a bare name (no path separators) in run().
	raw, err := os.ReadFile(dbPath(user))
	if errors.Is(err, fs.ErrNotExist) {
		// Deliberately not "no such user (register first?)": that message,
		// and the instant it would have come back in, are the leak.
		return dummySalt[:], dummyStored[:], false, nil
	}
	if err != nil {
		return nil, nil, false, err
	}
	parts := strings.SplitN(strings.TrimSpace(string(raw)), ":", 2)
	if len(parts) != 2 {
		return nil, nil, false, fmt.Errorf("corrupt record for %s", user)
	}
	salt, err1 := hex.DecodeString(parts[0])
	stored, err2 := hex.DecodeString(parts[1])
	if err1 != nil || err2 != nil || len(salt) != saltLen || len(stored) != keyLen {
		return nil, nil, false, fmt.Errorf("corrupt record for %s", user)
	}
	return salt, stored, true, nil
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
//
// Raw mode also means the terminal edits nothing, so the keys a person uses
// to fix a typo are handled here: backspace removes the last character (all
// of its bytes, when it is not ASCII), ^U clears the line and ^D ends it.
// Any other control byte — ^W, a tab, the escape sequence of an arrow key —
// is refused: stored, it would be a password the user did not type and
// could not type again.
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
		case c == 0x04: // ^D: end of input, as a terminal's line mode treats it
			break readLoop
		case c == 0x7f || c == 0x08: // backspace
			if n, err = eraseLast(buf, n); err != nil {
				_ = buf.Destroy()
				return nil, err
			}
		case c == 0x15: // ^U: start over
			for n > 0 {
				n--
				if err := buf.SetByteAt(n, 0); err != nil {
					_ = buf.Destroy()
					return nil, err
				}
			}
		case c < 0x20:
			_ = buf.Destroy()
			return nil, errors.New("unsupported key in the password (backspace, ^U and ^D are the editing keys)")
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

// eraseLast removes the last character of the n bytes typed so far, zeroing
// what it removes, and returns the new length. A character is one byte or,
// in UTF-8, a lead byte and its continuation bytes; removing only the last
// byte of "é" would leave half a character in the password. Continuation
// bytes with no lead byte before them (input that is not UTF-8) are removed
// on their own, and the ASCII byte before them is left alone.
func eraseLast(buf *secmem.SecureBuffer, n int) (int, error) {
	for removed := 0; n > 0 && removed < utf8.UTFMax; removed++ {
		c, err := buf.ByteAt(n - 1)
		if err != nil {
			return n, err
		}
		continuation := c&0xC0 == 0x80
		if removed > 0 && c < 0x80 {
			break // the ASCII character before a run of stray continuation bytes
		}
		n--
		if err := buf.SetByteAt(n, 0); err != nil {
			return n, err
		}
		if !continuation {
			break // an ASCII byte or a lead byte: the character is gone
		}
	}
	return n, nil
}

func dbPath(user string) string {
	return "pwdb-" + user + ".txt"
}
