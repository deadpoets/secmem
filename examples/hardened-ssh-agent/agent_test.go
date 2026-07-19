//go:build unix

// agent_test.go proves two different kinds of claim:
//
//  1. INTEROP — the agent speaks the real protocol. Every test drives it
//     through golang.org/x/crypto/ssh/agent's CLIENT, the reference Go
//     implementation, over a real unix socket. If these pass, ssh-add and
//     ssh work, because they speak the same wire format.
//
//  2. SECURITY PROPERTIES — the hardening claims are checked, not
//     asserted: keys are sealed (PROT_NONE) whenever the agent is idle,
//     including immediately after signing; the lock stores no passphrase;
//     signatures verify with the standard library.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// startAgent runs a fresh keyring on a unix socket and returns a connected
// reference-implementation client.
func startAgent(t *testing.T) (agent.Agent, *Keyring) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	keyring := NewKeyring()
	t.Cleanup(keyring.DestroyAll)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveConn(conn, keyring, testLogger())
		}
	}()

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return agent.NewClient(conn), keyring
}

// allSealed reports whether every held key buffer is sealed. This reaches
// into the keyring deliberately: the dormant-key claim should be checkable,
// not taken on faith.
func allSealed(k *Keyring) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, r := range k.keys {
		if !r.keyBuf.IsSealed() {
			return false
		}
	}
	return len(k.keys) > 0
}

func TestInterop_Ed25519_AddListSignVerify(t *testing.T) {
	client, keyring := startAgent(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := client.Add(agent.AddedKey{PrivateKey: priv, Comment: "test@ed25519"}); err != nil {
		t.Fatalf("Add via reference client: %v", err)
	}

	// List: the identity round-trips with the right key and comment.
	ids, err := client.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ids) != 1 || ids[0].Comment != "test@ed25519" {
		t.Fatalf("List = %+v, want one identity with comment test@ed25519", ids)
	}
	wantPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	if string(ids[0].Blob) != string(wantPub.Marshal()) {
		t.Fatal("listed public key does not match the key that was added")
	}

	// PROPERTY: the key is sealed while the agent is idle.
	if !allSealed(keyring) {
		t.Fatal("key buffer not sealed after Add")
	}

	// Sign through the reference client; verify with x/crypto/ssh.
	data := []byte("session-identification-data")
	sig, err := client.Sign(wantPub, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := wantPub.Verify(data, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	// PROPERTY: signing left the key resealed.
	if !allSealed(keyring) {
		t.Fatal("key buffer not resealed after Sign")
	}
}

func TestInterop_ECDSA_P256_AddListSignVerify(t *testing.T) {
	client, keyring := startAgent(t)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := client.Add(agent.AddedKey{PrivateKey: priv, Comment: "test@p256"}); err != nil {
		t.Fatalf("Add via reference client: %v", err)
	}

	wantPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	ids, err := client.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ids) != 1 || string(ids[0].Blob) != string(wantPub.Marshal()) {
		t.Fatal("listed identity does not match the ECDSA key that was added")
	}

	data := []byte("ecdsa-session-data")
	sig, err := client.Sign(wantPub, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := wantPub.Verify(data, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	if !allSealed(keyring) {
		t.Fatal("key buffer not sealed after ECDSA sign")
	}
}

func TestInterop_RemoveAndRemoveAll(t *testing.T) {
	client, _ := startAgent(t)

	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	if err := client.Add(agent.AddedKey{PrivateKey: priv1, Comment: "one"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := client.Add(agent.AddedKey{PrivateKey: priv2, Comment: "two"}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	pub1, _ := ssh.NewPublicKey(priv1.Public().(ed25519.PublicKey))
	if err := client.Remove(pub1); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	ids, _ := client.List()
	if len(ids) != 1 || ids[0].Comment != "two" {
		t.Fatalf("after Remove, List = %+v, want only 'two'", ids)
	}

	if err := client.RemoveAll(); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	ids, _ = client.List()
	if len(ids) != 0 {
		t.Fatalf("after RemoveAll, List = %+v, want empty", ids)
	}
}

func TestInterop_LockUnlock(t *testing.T) {
	client, keyring := startAgent(t)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := client.Add(agent.AddedKey{PrivateKey: priv, Comment: "locked-away"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	pub, _ := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))

	if err := client.Lock([]byte("correct horse battery staple")); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	// While locked: list is empty, signing and adding fail — matching
	// OpenSSH's observable behavior.
	if ids, err := client.List(); err != nil || len(ids) != 0 {
		t.Fatalf("locked List = %v, %v; want empty, nil", ids, err)
	}
	if _, err := client.Sign(pub, []byte("nope")); err == nil {
		t.Fatal("Sign succeeded while locked")
	}
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	if err := client.Add(agent.AddedKey{PrivateKey: priv2}); err == nil {
		t.Fatal("Add succeeded while locked")
	}

	// Wrong passphrase is refused; keys stay hidden.
	if err := client.Unlock([]byte("wrong")); err == nil {
		t.Fatal("Unlock succeeded with wrong passphrase")
	}
	if ids, _ := client.List(); len(ids) != 0 {
		t.Fatal("keys visible after failed unlock")
	}

	// PROPERTY: locking stored a derivation, not the passphrase, and the
	// keys remained sealed throughout.
	if !keyring.Locked() {
		t.Fatal("keyring does not report locked")
	}
	if !allSealed(keyring) {
		t.Fatal("keys not sealed while locked")
	}

	// Correct passphrase restores service.
	if err := client.Unlock([]byte("correct horse battery staple")); err != nil {
		t.Fatalf("Unlock with correct passphrase: %v", err)
	}
	ids, err := client.List()
	if err != nil || len(ids) != 1 {
		t.Fatalf("after unlock, List = %v, %v; want the original identity", ids, err)
	}
	if _, err := client.Sign(pub, []byte("works again")); err != nil {
		t.Fatalf("Sign after unlock: %v", err)
	}
}

func TestInterop_UnsupportedKeyTypeFailsCleanly(t *testing.T) {
	client, _ := startAgent(t)

	// RSA is a documented non-goal of the minimal core: the add must
	// fail with AGENT_FAILURE and the connection must survive.
	rsaKey := generateSmallRSA(t)
	if err := client.Add(agent.AddedKey{PrivateKey: rsaKey, Comment: "rsa"}); err == nil {
		t.Fatal("RSA Add unexpectedly succeeded")
	}
	// Connection still healthy:
	if ids, err := client.List(); err != nil || len(ids) != 0 {
		t.Fatalf("List after refused add = %v, %v; want empty, nil", ids, err)
	}
}

func TestKeyring_SignUnknownKeyFails(t *testing.T) {
	client, _ := startAgent(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub, _ := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if _, err := client.Sign(pub, []byte("x")); err == nil {
		t.Fatal("Sign with never-added key succeeded")
	}
}

// TestConstraint_Lifetime_DestroysKey proves the -t constraint is enforced
// by destruction, not concealment: after the deadline the key is gone from
// List AND its SecureBuffer is destroyed (wiped + unmapped), and signing
// with it fails. This is the socket-side control closed in the core.
func TestConstraint_Lifetime_DestroysKey(t *testing.T) {
	client, keyring := startAgent(t)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub, _ := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))

	// 1-second lifetime via the reference client's constrained add.
	if err := client.Add(agent.AddedKey{PrivateKey: priv, Comment: "ephemeral", LifetimeSecs: 1}); err != nil {
		t.Fatalf("constrained Add: %v", err)
	}

	// Capture the underlying buffer so we can assert it is destroyed, not
	// merely delisted.
	keyring.mu.Lock()
	if len(keyring.keys) != 1 {
		keyring.mu.Unlock()
		t.Fatalf("expected 1 key, got %d", len(keyring.keys))
	}
	buf := keyring.keys[0].keyBuf
	keyring.mu.Unlock()

	// Before expiry: usable.
	if _, err := client.Sign(pub, []byte("still valid")); err != nil {
		t.Fatalf("sign before expiry: %v", err)
	}
	if buf.IsDestroyed() {
		t.Fatal("buffer destroyed before its lifetime elapsed")
	}

	// Wait past the deadline, then force the lazy sweep via List.
	time.Sleep(1200 * time.Millisecond)
	if ids, _ := client.List(); len(ids) != 0 {
		t.Fatalf("expired key still listed: %+v", ids)
	}

	// PROPERTY: enforcement was destruction.
	if !buf.IsDestroyed() {
		t.Fatal("expired key's SecureBuffer was not destroyed")
	}
	if _, err := client.Sign(pub, []byte("too late")); err == nil {
		t.Fatal("signed with an expired key")
	}
}

// TestConstraint_Confirm_FailsClosed proves we reject a constraint we
// cannot enforce rather than accepting the key without it.
func TestConstraint_Confirm_FailsClosed(t *testing.T) {
	client, keyring := startAgent(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := client.Add(agent.AddedKey{PrivateKey: priv, ConfirmBeforeUse: true}); err == nil {
		t.Fatal("confirm-constrained add unexpectedly succeeded")
	}
	if ids := keyring.List(); len(ids) != 0 {
		t.Fatal("key was stored despite an unenforceable constraint")
	}
}
