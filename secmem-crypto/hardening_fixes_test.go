package secmemcrypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/deadpoets/secmem"
)

// TestNewRSASigner_RejectsECDHKey covers L1: a PKCS#8 blob holding an X25519
// (ECDH) key must be rejected with a clear error and without panicking. The
// reject path also best-effort wipes the parsed scalar (verified by code); this
// test guards the reachable branch and its error.
func TestNewRSASigner_RejectsECDHKey(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	buf, err := secmem.NewBuffer(der) // copies into secure memory, wipes der
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	defer func() { _ = buf.Destroy() }()

	if _, err := NewRSASigner(buf); err == nil {
		t.Fatal("NewRSASigner accepted an X25519 key; want rejection")
	} else if !strings.Contains(err.Error(), "ECDH") && !strings.Contains(err.Error(), "not RSA") {
		t.Fatalf("unexpected rejection error: %v", err)
	}
}

// TestSignEd25519Direct_ShortMessagesMatchStdlib covers H3's correctness: after
// moving the nonce hash off the streaming SHA-512 hasher onto Sum512 over a
// wiped scratch, signatures must remain byte-identical to crypto/ed25519 —
// especially for short messages (< one 128-byte SHA-512 block), where the
// change is most likely to matter.
func TestSignEd25519Direct_ShortMessagesMatchStdlib(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	sk := ed25519.NewKeyFromSeed(seed)
	cases := [][]byte{
		{},
		[]byte("x"),
		bytes.Repeat([]byte("m"), 31),
		bytes.Repeat([]byte("m"), 95), // 32 (prefix) + 95 = 127 < 128: still one block
		bytes.Repeat([]byte("m"), 96), // exactly one block boundary
		bytes.Repeat([]byte("m"), 200),
	}
	for _, msg := range cases {
		want := ed25519.Sign(sk, msg)
		// Pass a fresh seed copy: signEd25519Direct may wipe its input.
		got, err := signEd25519Direct(append([]byte(nil), seed...), msg)
		if err != nil {
			t.Fatalf("signEd25519Direct(len %d): %v", len(msg), err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("len %d: signature = %x, want %x", len(msg), got, want)
		}
	}
}
