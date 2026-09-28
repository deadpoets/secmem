// main_test.go proves the login path's two claims the way the rest of the
// repository proves its guarantees: by behavior an outsider can observe, not
// by inspecting how it is produced. Here the outsider is someone who can try
// to log in and would like to learn which accounts exist.
package main

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/deadpoets/secmem"
)

// pw puts a test password into secure memory the way readPassword does for a
// real one, destroyed at the end of the test.
func pw(t *testing.T, s string) *secmem.SecureBuffer {
	t.Helper()
	buf, err := secmem.NewBuffer([]byte(s))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	t.Cleanup(func() { _ = buf.Destroy() })
	return buf
}

// timed runs f and returns how long it took.
func timed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

// TestLogin_UnknownUserIsIndistinguishableFromWrongPassword: the refusal for
// a user who does not exist and the refusal for a wrong password are the same
// error, and cost the same. The cost half is what would leak in practice: a
// refusal that skipped the derivation would come back in microseconds where
// the real one takes a 64 MiB Argon2id derivation, a gap of three orders of
// magnitude that no network jitter hides. Each timing is the minimum of two
// interleaved runs, so a scheduling hiccup during one run cannot fail it, and
// the bar — a quarter of the wrong-password time — leaves the same margin the
// other way for a hiccup during the other. Beforehand, the correct password
// must still log in: the fix is not allowed to have broken the login.
func TestLogin_UnknownUserIsIndistinguishableFromWrongPassword(t *testing.T) {
	t.Chdir(t.TempDir()) // the record file lives in the working directory
	if err := register("alice", pw(t, "correct horse battery staple")); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := login("alice", pw(t, "correct horse battery staple")); err != nil {
		t.Fatalf("login with the registered password: %v", err)
	}

	var wrongErr, unknownErr error
	wrongMin, unknownMin := time.Duration(1<<62), time.Duration(1<<62)
	for i := 0; i < 2; i++ {
		wrongMin = min(wrongMin, timed(func() { wrongErr = login("alice", pw(t, "wrong")) }))
		unknownMin = min(unknownMin, timed(func() { unknownErr = login("nobody", pw(t, "wrong")) }))
	}

	// Same error, same text: the message says which of the two it was to no one.
	if !errors.Is(wrongErr, errLoginFailed) {
		t.Fatalf("wrong password: %v, want errLoginFailed", wrongErr)
	}
	if !errors.Is(unknownErr, errLoginFailed) {
		t.Fatalf("unknown user: %v, want errLoginFailed", unknownErr)
	}
	if wrongErr.Error() != unknownErr.Error() {
		t.Fatalf("messages differ: wrong password %q, unknown user %q", wrongErr, unknownErr)
	}

	// Same cost: the unknown user paid for a derivation too.
	if unknownMin < wrongMin/4 {
		t.Fatalf("unknown-user refusal took %v against %v for a wrong password: the derivation was skipped, and the timing says the account does not exist", unknownMin, wrongMin)
	}
	t.Logf("refusal cost: wrong password %v, unknown user %v", wrongMin, unknownMin)
}

// TestLogin_CorruptRecordIsAnOperatorError pins the one refusal that is
// deliberately NOT uniform: a record that exists but cannot be parsed names a
// damaged file for the operator to fix. It is not a guess outcome — the name
// is known to be registered, which a guesser could learn by registering it —
// so folding it into "login failed" would hide a real fault for no gain.
func TestLogin_CorruptRecordIsAnOperatorError(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile(dbPath("bob"), []byte("not a record\n"), 0o600); err != nil {
		t.Fatalf("writing corrupt record: %v", err)
	}
	err := login("bob", pw(t, "anything"))
	if err == nil {
		t.Fatal("login against a corrupt record succeeded")
	}
	if errors.Is(err, errLoginFailed) {
		t.Fatalf("corrupt record reported as %v; want an error naming the damaged record", err)
	}
}
