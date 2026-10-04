package main

import (
	"errors"
	"testing"
)

// TestRegister_RefusesAnExistingUser: registering a name that is already
// taken must fail and leave the account as it was. If it replaced the
// record, anyone who could reach registration could set a new password on
// someone else's account and log in as them.
func TestRegister_RefusesAnExistingUser(t *testing.T) {
	t.Chdir(t.TempDir())

	if err := register("alice", pw(t, "alice's own password")); err != nil {
		t.Fatalf("register: %v", err)
	}
	err := register("alice", pw(t, "someone else's password"))
	if !errors.Is(err, errUserExists) {
		t.Errorf("second register of the same name = %v, want errUserExists", err)
	}
	if err := login("alice", pw(t, "alice's own password")); err != nil {
		t.Errorf("the original password no longer logs in: %v", err)
	}
	if err := login("alice", pw(t, "someone else's password")); !errors.Is(err, errLoginFailed) {
		t.Errorf("login with the second registration's password = %v, want errLoginFailed", err)
	}
}
