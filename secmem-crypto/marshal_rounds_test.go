package secmemcrypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/deadpoets/secmem"
)

// containerOf strips the PEM armour a marshal produced and returns the raw
// OpenSSH container, which both this package's parser and readOpenSSHHeader
// accept directly.
func containerOf(t *testing.T, buf *secmem.SecureBuffer) []byte {
	t.Helper()
	block, _ := pem.Decode(bufferBytes(t, buf))
	if block == nil {
		t.Fatal("marshal did not produce a PEM block")
	}
	if !bytes.HasPrefix(block.Bytes, opensshMagic) {
		t.Fatal("decoded body is not an OpenSSH container")
	}
	return block.Bytes
}

// TestMarshalWithPassphraseParams_RoundsAreWrittenAndHonoured is the core
// of the feature: the cost the caller asks for is the cost recorded in the
// file, and the file still opens — here, with the parser in this package and
// with the x/crypto/ssh function a consumer would use. Reading the count
// back from the header is what distinguishes "the parameter was used" from
// "the parameter was accepted and ignored", which a round-trip alone cannot
// tell apart, since this package would then read the file with the same
// wrong cost it wrote.
func TestMarshalWithPassphraseParams_RoundsAreWrittenAndHonoured(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()

	// One above the default is the case that shows the count is not
	// clamped to it; a higher count proves nothing more and costs linearly.
	for _, rounds := range []int{1, 4, OpenSSHKDFRounds, OpenSSHKDFRounds + 1} {
		t.Run(strconv.Itoa(rounds), func(t *testing.T) {
			file, err := signer.MarshalOpenSSHPrivateKeyWithPassphraseParams(
				"a comment", []byte(testPassphrase), OpenSSHPassphraseParams{Rounds: rounds})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Destroy() }()

			container := containerOf(t, file)
			if _, got := kdfOptsOf(t, container); got != uint32(rounds) {
				t.Errorf("file records %d rounds, asked for %d", got, rounds)
			}

			loaded, err := ParsePrivateKeyWithPassphrase(container, []byte(testPassphrase))
			if err != nil {
				t.Fatal(err)
			}
			defer loaded.Destroy()
			if !loaded.Public().(ed25519.PublicKey).Equal(signer.Public()) {
				t.Error("parsed key is not the one marshalled")
			}

			// The consumer's path: x/crypto/ssh must open it too, at the
			// same cost, or the file is only readable by us.
			key, err := ssh.ParseRawPrivateKeyWithPassphrase(bufferBytes(t, file), []byte(testPassphrase))
			if err != nil {
				t.Fatalf("x/crypto/ssh could not open a %d-round file: %v", rounds, err)
			}
			priv, ok := key.(*ed25519.PrivateKey)
			if !ok {
				t.Fatalf("x/crypto/ssh returned %T", key)
			}
			if !priv.Public().(ed25519.PublicKey).Equal(signer.Public()) {
				t.Error("x/crypto/ssh parsed a different key")
			}
		})
	}
}

// oddLengthBlock rebuilds container with one byte added to its private
// block, so the block is no longer a multiple of the cipher block size. The
// parser rejects that AFTER the rounds check and BEFORE any decryption, so
// it is the probe that says which of the two gates a file tripped without
// paying for a derivation.
func oddLengthBlock(t *testing.T, container []byte) []byte {
	t.Helper()
	h, err := readOpenSSHHeader(container)
	if err != nil {
		t.Fatal(err)
	}
	head := container[:len(container)-len(h.privBlock)-4]
	out := make([]byte, 0, len(container)+1)
	out = append(out, head...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(h.privBlock)+1))
	out = append(out, h.privBlock...)
	return append(out, 0x00)
}

// TestOpenSSHKDFRounds_CapMatchesXCrypto anchors this package's write cap
// to the number the readers actually enforce, rather than to itself.
//
// MaxOpenSSHKDFRounds exists so that a file written here can be opened
// again; that is only true while it equals x/crypto/ssh's own maximum. A
// test comparing our constant to our constant would pass however far the
// two drifted, so this one asks x/crypto instead: it is handed a file
// claiming a cost far above any plausible cap, which x/crypto refuses
// before running the KDF, and its refusal names the maximum it enforces.
// That number must be ours. The check is instant in both drift directions —
// if x/crypto lowered its cap, or if this package raised its own, the
// extracted number stops matching.
//
// It reads x/crypto's error text, which is not part of its API. If the
// wording changes this test fails rather than silently stops checking, and
// the fix is to re-read x/crypto/ssh's maxRounds and update the pattern —
// not to delete the test.
func TestOpenSSHKDFRounds_CapMatchesXCrypto(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	file, err := signer.MarshalOpenSSHPrivateKeyWithPassphraseParams(
		"a comment", []byte(testPassphrase), OpenSSHPassphraseParams{Rounds: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Destroy() }()

	container := containerOf(t, file)
	h, err := readOpenSSHHeader(container)
	if err != nil {
		t.Fatal(err)
	}
	// Far above any cap either side would plausibly choose, so the refusal
	// is immediate whatever the two constants currently are.
	binary.BigEndian.PutUint32(h.kdfOpts[len(h.kdfOpts)-4:], 1<<30)
	armoured := pem.EncodeToMemory(&pem.Block{Type: opensshPEMType, Bytes: container})

	_, err = ssh.ParseRawPrivateKeyWithPassphrase(armoured, []byte(testPassphrase))
	if err == nil {
		t.Fatal("x/crypto/ssh accepted a file claiming 2^30 bcrypt rounds")
	}
	m := xcryptoMaxRounds.FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatalf("x/crypto/ssh refused the file with %q, which does not name the maximum it enforces; "+
			"re-read maxRounds in x/crypto/ssh/keys.go and update this test", err)
	}
	got, perr := strconv.Atoi(m[1])
	if perr != nil {
		t.Fatal(perr)
	}
	if got != MaxOpenSSHKDFRounds {
		t.Errorf("x/crypto/ssh enforces a maximum of %d rounds, this package writes up to %d; "+
			"a file at this package's cap would not open", got, MaxOpenSSHKDFRounds)
	}
}

// xcryptoMaxRounds pulls the maximum out of x/crypto/ssh's own refusal:
// "ssh: bcrypt KDF rounds 1073741824 exceed maximum 2048".
var xcryptoMaxRounds = regexp.MustCompile(`exceed(?:s)? maximum (\d+)`)

// TestOpenSSHKDFRounds_ReadCapIsWhereTheWriteCapStops pins the boundary the
// write cap exists to respect: MaxOpenSSHKDFRounds is accepted by the reader
// and one more is refused. If the two ever drifted apart this package would
// write files it could not open.
//
// It is deliberately not an end-to-end marshal-and-parse at the maximum
// cost. That would prove the same thing and cost about half a minute of
// bcrypt on every CI job — 128x the default, three times over — while
// testing the gate less precisely, since a failure could come from anywhere
// in the pipeline. Instead the count in the header is patched to each side
// of the boundary and the private block is made an odd length, so the parse
// stops at the check immediately after the rounds gate: ErrUnsupportedKey
// means the gate fired, errMalformed means the file got past it. The
// composition that makes this equivalent is covered by the tests either
// side of it — the marshaller writes the count it is given, and the reader
// accepts everything up to the cap.
func TestOpenSSHKDFRounds_ReadCapIsWhereTheWriteCapStops(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	file, err := signer.MarshalOpenSSHPrivateKeyWithPassphraseParams(
		"a comment", []byte(testPassphrase), OpenSSHPassphraseParams{Rounds: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Destroy() }()
	probe := oddLengthBlock(t, containerOf(t, file))

	h, err := readOpenSSHHeader(probe)
	if err != nil {
		t.Fatal(err)
	}
	opts := h.kdfOpts // aliases probe, so writing through it patches the file
	if len(opts) < 4 {
		t.Fatal("kdf options too short")
	}

	parse := func() error {
		s, err := ParsePrivateKeyWithPassphrase(probe, []byte(testPassphrase))
		if s != nil {
			s.Destroy()
			t.Fatal("the probe file must never parse successfully")
		}
		return err
	}

	// The control: with a cost the reader allows, the parse gets past the
	// rounds gate and stops at the block-length check. Without this, the
	// assertion below could pass because the file was malformed in some
	// way that never reached the gate at all.
	binary.BigEndian.PutUint32(opts[len(opts)-4:], MaxOpenSSHKDFRounds)
	if err := parse(); !errors.Is(err, errMalformed) || errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("at exactly %d rounds the parse gave %v, want the block-length error that follows the rounds gate", MaxOpenSSHKDFRounds, err)
	}

	binary.BigEndian.PutUint32(opts[len(opts)-4:], MaxOpenSSHKDFRounds+1)
	if err := parse(); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("at %d rounds the parse gave %v, want ErrUnsupportedKey", MaxOpenSSHKDFRounds+1, err)
	}
}

func TestMarshalWithPassphraseParams_Errors(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()

	wantRange := fmt.Sprintf("rounds must be between 1 and %d", MaxOpenSSHKDFRounds)
	cases := []struct {
		name       string
		passphrase []byte
		rounds     int
		want       string
	}{
		{"zero rounds", []byte(testPassphrase), 0, wantRange},
		{"negative rounds", []byte(testPassphrase), -1, wantRange},
		{"above the cap", []byte(testPassphrase), MaxOpenSSHKDFRounds + 1, wantRange},
		{"empty passphrase", nil, OpenSSHKDFRounds, "empty passphrase"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf, err := signer.MarshalOpenSSHPrivateKeyWithPassphraseParams(
				"a comment", c.passphrase, OpenSSHPassphraseParams{Rounds: c.rounds})
			if err == nil {
				buf.Destroy()
				t.Fatal("want an error, got nil")
			}
			if buf != nil {
				t.Error("a rejected call returned a buffer")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

// TestMarshalWithPassphrase_UsesTheDocumentedDefault pins the claim the
// convenience method's doc makes, so the two cannot drift.
func TestMarshalWithPassphrase_UsesTheDocumentedDefault(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	file, err := signer.MarshalOpenSSHPrivateKeyWithPassphrase("a comment", []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Destroy() }()
	if _, got := kdfOptsOf(t, bufferBytes(t, file)); got != OpenSSHKDFRounds {
		t.Errorf("the default marshal wrote %d rounds, want OpenSSHKDFRounds (%d)", got, OpenSSHKDFRounds)
	}
	if OpenSSHKDFRounds != 16 {
		t.Errorf("OpenSSHKDFRounds is %d; ssh-keygen's default is 16 and the docs say so", OpenSSHKDFRounds)
	}
}

// TestMarshalWithPassphraseParams_SSHKeygenOpensNonDefaultRounds is the
// interop proof for the cost knob against the real tool: a cost other than
// the default is not something x/crypto and this package could agree on
// while both being wrong, because ssh-keygen has to read the same header.
func TestMarshalWithPassphraseParams_SSHKeygenOpensNonDefaultRounds(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	sshPub, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	for _, rounds := range []int{1, OpenSSHKDFRounds + 1} {
		t.Run(strconv.Itoa(rounds), func(t *testing.T) {
			file, err := signer.MarshalOpenSSHPrivateKeyWithPassphraseParams(
				"interop", []byte(testPassphrase), OpenSSHPassphraseParams{Rounds: rounds})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Destroy() }()
			if got := sshKeygenPublicKey(t, bufferBytes(t, file), testPassphrase); got != want {
				t.Errorf("ssh-keygen read a different key from a %d-round file:\n got %s\nwant %s", rounds, got, want)
			}
		})
	}
}
