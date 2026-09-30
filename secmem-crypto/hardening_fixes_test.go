package secmemcrypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

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

	if _, err := NewRSASigner(buf, AllowHeapTransients()); err == nil {
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

// TestParsePrivateKey_RejectsTrailingElements pins a fix found by the
// PBES2 damage sweep (pbes2_test.go): ECPrivateKey's parameters and
// publicKey, and PrivateKeyInfo's attributes and publicKey, are OPTIONAL,
// so a damaged tag reads as "absent" — and the readers then left the
// element behind unread. An EC file whose [1] publicKey tag is damaged
// opened with its public-key cross-check silently skipped; it is malformed
// now, as is any element after the last one the structure defines. Shown
// to open against the readers without their trailing check.
func TestParsePrivateKey_RejectsTrailingElements(t *testing.T) {
	k := testKeyNamed(t, "p256")
	sec1, err := x509.MarshalECPrivateKey(k.priv.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(k.priv)
	if err != nil {
		t.Fatal(err)
	}

	// Walk the SEC 1 structure to the [1] publicKey element and damage its
	// tag to [2], which no field has. Located structurally: the public key
	// is random bytes and may well contain the tag value.
	in := cryptobyte.String(sec1)
	var seq cryptobyte.String
	var version int64
	var d, params cryptobyte.String
	var haveParams bool
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1Integer(&version) ||
		!seq.ReadASN1(&d, cbasn1.OCTET_STRING) ||
		!seq.ReadOptionalASN1(&params, &haveParams, cbasn1.Tag(0).ContextSpecific().Constructed()) ||
		!seq.PeekASN1Tag(cbasn1.Tag(1).ContextSpecific().Constructed()) {
		t.Fatal("not the SEC 1 shape x509 writes")
	}
	damaged := bytes.Clone(sec1)
	damaged[len(sec1)-len(seq)] = 0xa2

	// A PrivateKeyInfo with one element more than the structure defines,
	// re-encoded so every length is right.
	in = cryptobyte.String(p8)
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() {
		t.Fatal("not a PKCS#8 SEQUENCE")
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(seq)
		b.AddASN1NULL()
	})
	extra, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	for name, der := range map[string][]byte{"sec1 damaged [1] tag": damaged, "pkcs8 trailing element": extra} {
		t.Run(name, func(t *testing.T) {
			s, err := ParsePrivateKey(der, AllowHeapTransients())
			if err == nil {
				s.Destroy()
				t.Fatal("opened")
			}
			if !errors.Is(err, errMalformed) {
				t.Fatalf("%v, want errMalformed", err)
			}
		})
	}
	// The controls: both undamaged forms open.
	for name, der := range map[string][]byte{"sec1": sec1, "pkcs8": p8} {
		s, err := ParsePrivateKey(der, AllowHeapTransients())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		s.Destroy()
	}
}
