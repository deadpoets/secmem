//go:build linux && (amd64 || arm64) && !race

package secmemcrypto

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/x509"
	"encoding"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"hash"
	"io"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"unsafe"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/secmem-crypto/internal/bcryptpbkdf"
)

// residueClass is what a scenario asserts; see residue_linux_test.go.
type residueClass int

const (
	// residueContained: no encoding outside locked memory after
	// construction, between operations, after GC, or after Destroy.
	residueContained residueClass = iota
	// residueTransient: every operation leaves copies outside locked memory;
	// a runtimesecret build erases them within residueSettleRounds GC cycles.
	residueTransient
	// residueControlScrub: a heap copy made inside secmem.Scrub — erased by
	// the collector on a runtimesecret build, surviving it on a legacy one.
	// It pins the premise every transient verdict rests on.
	residueControlScrub
	// residueControlPlain: a heap copy made outside Scrub survives the
	// collector on every build.
	residueControlPlain
	// residueControlSpill: a copy the runtime saved onto a goroutine stack by
	// preempting it outside Scrub is there after use, on every build. Whether
	// it is still there after GC depends on what reuses that stack, so only
	// its presence is asserted.
	residueControlSpill
)

type residueScenario struct {
	name  string
	class residueClass
	nOps  int // operations per 'o' command; 0 means 32
	// minCore is the first core release whose behaviour the scenario's class
	// depends on, or "" when any will do. Against an older released core the
	// scenario is skipped with the reason; against a local or workspace tree
	// (no release version) it always runs.
	minCore string
	// material runs in the parent: the secret the victim receives in a
	// SecureBuffer, public inputs, and every encoding to hunt for.
	material func(t *testing.T) (secret, aux []byte, pats []residuePattern)
	// victim runs in the child. It builds the object from buf (taking
	// ownership or not) and returns one operation and a destroy that
	// releases everything, buf included.
	victim func(buf *secmem.SecureBuffer, aux []byte) (op, destroy func() error, err error)
}

func (s residueScenario) ops() int {
	if s.nOps > 0 {
		return s.nOps
	}
	return 32
}

func residueScenarioByName(name string) (residueScenario, bool) {
	for _, s := range residueScenarios {
		if s.name == name {
			return s, true
		}
	}
	return residueScenario{}, false
}

const residueMessage = "secmem residue scan: the message every signing scenario signs"

var residueScenarios = []residueScenario{
	{
		name: "control/heap-copy-in-scrub", class: residueControlScrub,
		material: randomSecret(32, "secret"),
		victim: func(buf *secmem.SecureBuffer, _ []byte) (func() error, func() error, error) {
			op := func() error {
				return secmem.ScrubErr(func() error {
					return buf.WithBytesErr(func(p []byte) error { residueHeapCopy(p); return nil })
				})
			}
			return op, buf.Destroy, nil
		},
	},
	{
		name: "control/heap-copy-outside-scrub", class: residueControlPlain,
		material: randomSecret(32, "secret"),
		victim: func(buf *secmem.SecureBuffer, _ []byte) (func() error, func() error, error) {
			op := func() error {
				return buf.WithBytesErr(func(p []byte) error { residueHeapCopy(p); return nil })
			}
			return op, buf.Destroy, nil
		},
	},
	{
		// A 32-byte copy leaves the secret's two halves in the vector
		// registers it moved them through; a goroutine then preempted
		// asynchronously has its register file saved onto its stack, where
		// nothing erases it. This is what Scrub's signal mask and register
		// clear exist for, and the pair below proves both halves of that.
		name: "control/preempted-copy-outside-scrub", class: residueControlSpill, nOps: 4,
		material: randomSecret(32, "secret"),
		victim:   preemptedCopy(false),
	},
	{
		// The copy runs inside two WithBytesErr borrows and no Scrub window,
		// and the spin — and the preemptions — come after both have returned.
		// What the copy left in the registers is gone only if the borrow
		// clears them on the way out.
		name: "WithBytesErr/copy-then-preempted", class: residueContained, nOps: 4,
		minCore:  "v0.6.0", // the borrow paths clear the registers from this release
		material: randomSecret(32, "secret"),
		victim:   copyThenPreempted,
	},
	{
		name: "control/preempted-copy-in-scrub", class: residueContained, nOps: 4,
		minCore:  "v0.6.0", // Scrub clears the general-purpose registers (arm64 memmove uses them) from this release
		material: randomSecret(32, "secret"),
		victim:   preemptedCopy(true),
	},
	{
		name: "Ed25519Signer", class: residueContained,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			seed := residueRandom(t, 32)
			return seed, nil, ed25519Patterns(seed)
		},
		victim: func(buf *secmem.SecureBuffer, _ []byte) (func() error, func() error, error) {
			s, err := NewEd25519Signer(buf)
			if err != nil {
				return nil, nil, err
			}
			return signOp(s, crypto.Hash(0), []byte(residueMessage)), s.Destroy, nil
		},
	},
	{
		name: "ParsePrivateKey/Ed25519-PKCS8", class: residueContained,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			seed := residueRandom(t, 32)
			der, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(seed))
			if err != nil {
				t.Fatal(err)
			}
			return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil, ed25519Patterns(seed)
		},
		victim: func(buf *secmem.SecureBuffer, _ []byte) (func() error, func() error, error) {
			op := func() error {
				return buf.WithBytesErr(func(file []byte) error {
					parsed, err := ParsePrivateKey(file)
					if err != nil {
						return err
					}
					defer parsed.Destroy()
					return signOp(parsed, crypto.Hash(0), []byte(residueMessage))()
				})
			}
			return op, buf.Destroy, nil
		},
	},
	{
		name: "ParsePrivateKeyWithPassphrase/Ed25519-OpenSSH", class: residueContained,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			seed := residueRandom(t, 32)
			pass := residueRandom(t, 24)
			file := marshalEncryptedOpenSSH(t, seed, pass, 2)
			salt, rounds := openSSHKDFOptions(t, file)
			kiv := make([]byte, 48)
			if err := bcryptpbkdf.Derive(kiv, pass, salt, rounds, bcryptpbkdf.NewWorkspace()); err != nil {
				t.Fatal(err)
			}
			pats := append(ed25519Patterns(seed), residuePattern{"passphrase", pass}, residuePattern{"bcrypt-key+iv", kiv})
			pats = append(pats, aesSchedulePatterns(t, "aes256", kiv[:32])...)
			aux := binary.BigEndian.AppendUint32(nil, uint32(len(file)))
			return append(file, pass...), aux, pats
		},
		victim: func(buf *secmem.SecureBuffer, aux []byte) (func() error, func() error, error) {
			n := int(binary.BigEndian.Uint32(aux))
			op := func() error {
				return buf.WithBytesErr(func(p []byte) error {
					s, err := ParsePrivateKeyWithPassphrase(p[:n], p[n:])
					if err != nil {
						return err
					}
					defer s.Destroy()
					return signOp(s, crypto.Hash(0), []byte(residueMessage))()
				})
			}
			return op, buf.Destroy, nil
		},
	},
	{
		// The salt is drawn fresh inside every export, so the derived key and
		// round keys cannot be predicted; the seed's and the passphrase's own
		// encodings can.
		name: "MarshalOpenSSHPrivateKeyWithPassphrase/Ed25519", class: residueContained,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			seed := residueRandom(t, 32)
			pass := residueRandom(t, 24)
			return append(slices.Clone(seed), pass...), nil, append(ed25519Patterns(seed), residuePattern{"passphrase", pass})
		},
		victim: func(buf *secmem.SecureBuffer, _ []byte) (func() error, func() error, error) {
			seedBuf, err := secmem.NewEmptyBuffer(32)
			if err != nil {
				return nil, nil, err
			}
			if err := copyWithin(seedBuf, buf, 0, 32); err != nil {
				return nil, nil, err
			}
			s, err := NewEd25519Signer(seedBuf)
			if err != nil {
				return nil, nil, err
			}
			op := func() error {
				return buf.WithBytesErr(func(p []byte) error {
					out, err := s.MarshalOpenSSHPrivateKeyWithPassphraseParams("residue", p[32:], OpenSSHPassphraseParams{Rounds: 2})
					if err != nil {
						return err
					}
					return out.Destroy()
				})
			}
			return op, destroyAll(s.Destroy, buf.Destroy), nil
		},
	},
	{
		name: "Argon2IDKeyInto", class: residueContained, nOps: 8,
		material: argon2Material,
		victim: func(buf *secmem.SecureBuffer, aux []byte) (func() error, func() error, error) {
			op := func() error {
				out, err := secmem.NewEmptyBuffer(32)
				if err != nil {
					return err
				}
				defer out.Destroy()
				return buf.WithBytesErr(func(pw []byte) error {
					return Argon2IDKeyInto(pw, aux, residueArgon2Time, residueArgon2Memory, 1, out)
				})
			}
			return op, buf.Destroy, nil
		},
	},
	{
		name: "Argon2Workspace", class: residueContained, nOps: 8,
		material: argon2Material,
		victim: func(buf *secmem.SecureBuffer, aux []byte) (func() error, func() error, error) {
			ws, err := NewArgon2Workspace(residueArgon2Memory, 1)
			if err != nil {
				return nil, nil, err
			}
			params := Argon2Params{Mode: Argon2id, Time: residueArgon2Time, Memory: residueArgon2Memory, Threads: 1}
			op := func() error {
				out, err := secmem.NewEmptyBuffer(32)
				if err != nil {
					return err
				}
				defer out.Destroy()
				return buf.WithBytesErr(func(pw []byte) error { return ws.Derive(pw, aux, params, out) })
			}
			return op, destroyAll(ws.Destroy, buf.Destroy), nil
		},
	},
	{
		name: "BcryptPBKDFInto", class: residueContained, nOps: 8,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			pw, salt := residueRandom(t, 32), residueRandom(t, 16)
			kiv := make([]byte, 48)
			if err := bcryptpbkdf.Derive(kiv, pw, salt, 2, bcryptpbkdf.NewWorkspace()); err != nil {
				t.Fatal(err)
			}
			return pw, salt, []residuePattern{{"password", pw}, {"output", kiv}}
		},
		victim: func(buf *secmem.SecureBuffer, aux []byte) (func() error, func() error, error) {
			op := func() error {
				out, err := secmem.NewEmptyBuffer(48)
				if err != nil {
					return err
				}
				defer out.Destroy()
				return buf.WithBytesErr(func(pw []byte) error { return BcryptPBKDFInto(pw, aux, 2, out) })
			}
			return op, buf.Destroy, nil
		},
	},
	{
		// The AEAD key is the caller's and lives in the caller's cipher.AEAD
		// (public here, in aux); what these two functions keep off the heap is
		// the plaintext.
		name: "SealFrom+OpenInto/plaintext", class: residueContained,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			pt := residueRandom(t, 64)
			return pt, residueRandom(t, 32), []residuePattern{{"plaintext", pt}}
		},
		victim: func(buf *secmem.SecureBuffer, aux []byte) (func() error, func() error, error) {
			blk, err := aes.NewCipher(aux)
			if err != nil {
				return nil, nil, err
			}
			gcm, err := cipher.NewGCM(blk)
			if err != nil {
				return nil, nil, err
			}
			back, err := secmem.NewEmptyBuffer(64)
			if err != nil {
				return nil, nil, err
			}
			nonce := make([]byte, gcm.NonceSize())
			op := func() error {
				ct, err := SealFrom(nil, gcm, nonce, buf, nil)
				if err != nil {
					return err
				}
				return OpenInto(back, gcm, nonce, ct, nil)
			}
			return op, destroyAll(back.Destroy, buf.Destroy), nil
		},
	},
	{
		// Key and plaintext both in locked memory: the AEAD is lent by
		// WithAESGCM, and SealFrom and OpenInto run inside its callback.
		name: "WithAESGCM+SealFrom+OpenInto", class: residueContained,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			key, pt := residueRandom(t, 32), residueRandom(t, 64)
			pats := append([]residuePattern{{"key", key}, {"plaintext", pt}}, aesSchedulePatterns(t, "aes256", key)...)
			layout, err := aesGCMLayoutReady()
			if err != nil {
				t.Fatal(err)
			}
			blk, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			g, err := cipher.NewGCM(blk)
			if err != nil {
				t.Fatal(err)
			}
			// The GHASH table is populated from its start and zero after, so
			// the pattern is its populated prefix.
			if table, ok := aesGCMViews(t, layout, g)["productTable"]; ok {
				n := len(table)
				for n > 0 && table[n-1] == 0 {
					n--
				}
				if n >= 16 && !isLowEntropy(table[:16]) {
					used := slices.Clone(table[:n])
					if tail := (n - 16) / 8 * 8; tail < 16 || !isLowEntropy(used[tail:tail+16]) {
						pats = append(pats, residuePattern{"ghash-table", used})
					} else {
						pats = append(pats, residuePattern{"ghash-table", used[:16]})
					}
				}
			}
			return append(slices.Clone(key), pt...), nil, pats
		},
		victim: func(buf *secmem.SecureBuffer, _ []byte) (func() error, func() error, error) {
			keyBuf, err := secmem.NewEmptyBuffer(32)
			if err != nil {
				return nil, nil, err
			}
			ptBuf, err := secmem.NewEmptyBuffer(64)
			if err != nil {
				return nil, nil, err
			}
			back, err := secmem.NewEmptyBuffer(64)
			if err != nil {
				return nil, nil, err
			}
			if err := copyWithin(keyBuf, buf, 0, 32); err != nil {
				return nil, nil, err
			}
			if err := copyWithin(ptBuf, buf, 32, 64); err != nil {
				return nil, nil, err
			}
			nonce := make([]byte, 12)
			op := func() error {
				return WithAESGCM(keyBuf, func(a cipher.AEAD) error {
					ct, err := SealFrom(nil, a, nonce, ptBuf, nil)
					if err != nil {
						return err
					}
					return OpenInto(back, a, nonce, ct, nil)
				})
			}
			return op, destroyAll(keyBuf.Destroy, ptBuf.Destroy, back.Destroy, buf.Destroy), nil
		},
	},
	{
		// The decapsulation key and everything derived from it that recovers
		// it: the seed halves, the secret polynomial s, sigma, and the SHAKE
		// state that absorbed z. In go1.26 crypto/mlkem keeps its hash states
		// and polynomials on the stack, which the Scrub window wipes.
		name: "MLKEM768Key/decapsulation-key", class: residueContained,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			seed, ct, _, shared := mlkemMaterial(t)
			dk, err := mlkem.NewDecapsulationKey768(seed)
			if err != nil {
				t.Fatal(err)
			}
			var pats []residuePattern
			for _, f := range mlkemSecretFields {
				v, err := mlkemSecretBytes(dk, f)
				if err != nil {
					t.Fatal(err)
				}
				pats = append(pats, residuePattern{"dk." + f, slices.Clone(v)})
			}
			g := sha3.Sum512(append(slices.Clone(seed[:32]), 3))
			j := sha3.NewSHAKE256()
			j.Write(seed[32:])
			j.Write(ct)
			absorbed := sha3State(t, j)
			_, _ = j.Read(make([]byte, 32))
			pats = append(pats,
				residuePattern{"sigma", g[32:]},
				residuePattern{"J(z||c)-absorbed", absorbed},
				residuePattern{"J(z||c)-squeezed", sha3State(t, j)},
				residuePattern{"shared-key", shared},
			)
			return seed, ct, pats
		},
		victim: mlkemVictim,
	},
	{
		// The message decapsulation recovers. With the public key's hash it
		// gives this ciphertext's shared key — not the decapsulation key.
		// crypto/mlkem returns it from an unexported function as a fresh heap
		// slice that nothing outside the package can reach to wipe.
		name: "MLKEM768Key/recovered-message", class: residueTransient,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			seed, ct, m, _ := mlkemMaterial(t)
			return seed, ct, []residuePattern{{"m", m}}
		},
		victim: mlkemVictim,
	},
	{
		name: "ECDSASigner/P-256", class: residueTransient,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			d, err := k.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			return d, nil, beAndLE("d", d)
		},
		victim: func(buf *secmem.SecureBuffer, _ []byte) (func() error, func() error, error) {
			s, err := NewECDSASigner(elliptic.P256(), buf, AllowHeapTransients())
			if err != nil {
				return nil, nil, err
			}
			digest := sha256.Sum256([]byte(residueMessage))
			return signOp(s, crypto.SHA256, digest[:]), s.Destroy, nil
		},
	},
	{
		name: "RSASigner/2048", class: residueTransient, nOps: 16,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			var pats []residuePattern
			for _, v := range []struct {
				n string
				b []byte
			}{{"d", k.D.Bytes()}, {"p", k.Primes[0].Bytes()}, {"q", k.Primes[1].Bytes()},
				{"dP", k.Precomputed.Dp.Bytes()}, {"dQ", k.Precomputed.Dq.Bytes()}, {"qInv", k.Precomputed.Qinv.Bytes()}} {
				pats = append(pats, beAndLE(v.n, v.b)...)
			}
			fips, err := rsaFIPSKey(k)
			if err != nil {
				t.Fatal(err)
			}
			views, err := rsaFIPSSecretViews(fips)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range views {
				if len(v) >= 16 && !isLowEntropy(v[:16]) {
					pats = append(pats, residuePattern{"fips-form", slices.Clone(v)})
				}
			}
			return x509.MarshalPKCS1PrivateKey(k), nil, pats
		},
		victim: func(buf *secmem.SecureBuffer, _ []byte) (func() error, func() error, error) {
			s, err := NewRSASigner(buf, AllowHeapTransients())
			if err != nil {
				return nil, nil, err
			}
			digest := sha256.Sum256([]byte(residueMessage))
			return signOp(s, crypto.SHA256, digest[:]), s.Destroy, nil
		},
	},
	{
		name: "X25519Key", class: residueContained,
		material: x25519Material,
		victim: func(buf *secmem.SecureBuffer, aux []byte) (func() error, func() error, error) {
			k, err := NewX25519Key(buf)
			if err != nil {
				return nil, nil, err
			}
			op := func() error {
				ss, err := k.SharedSecret([32]byte(aux))
				if err != nil {
					return err
				}
				return ss.Destroy()
			}
			return op, k.Destroy, nil
		},
	},
	{
		name: "HKDFSHA256Into", class: residueContained,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			secret, salt := residueRandom(t, 32), residueRandom(t, 16)
			prk := hmacSHA256(salt, secret)
			out := make([]byte, 32)
			if _, err := io.ReadFull(hkdf.New(sha256.New, secret, salt, []byte(residueMessage)), out); err != nil {
				t.Fatal(err)
			}
			pats := append([]residuePattern{{"secret", secret}, {"output", out}}, hmacKeyPatterns(t, "prk", prk, "sha256")...)
			return secret, salt, pats
		},
		victim: func(buf *secmem.SecureBuffer, aux []byte) (func() error, func() error, error) {
			op := func() error {
				out, err := secmem.NewEmptyBuffer(32)
				if err != nil {
					return err
				}
				defer out.Destroy()
				return buf.WithBytesErr(func(secret []byte) error {
					return HKDFSHA256Into(secret, aux, []byte(residueMessage), out)
				})
			}
			return op, buf.Destroy, nil
		},
	},
	{
		name: "HMACSHA256Into", class: residueContained,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			secret := residueRandom(t, 32)
			pats := append([]residuePattern{{"output", hmacSHA256(secret, []byte(residueMessage))}}, hmacKeyPatterns(t, "key", secret, "sha256")...)
			return secret, nil, pats
		},
		victim: func(buf *secmem.SecureBuffer, _ []byte) (func() error, func() error, error) {
			op := func() error {
				out, err := secmem.NewEmptyBuffer(32)
				if err != nil {
					return err
				}
				defer out.Destroy()
				return buf.WithBytesErr(func(secret []byte) error {
					return HMACSHA256Into(secret, []byte(residueMessage), out)
				})
			}
			return op, buf.Destroy, nil
		},
	},
	{
		// A secret too long for the stack region: the working region is a
		// locked buffer, and SHA-512's state is 64-bit words.
		name: "HKDFInto/SHA-512-long-secret", class: residueContained, nOps: 8,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			secret, salt := residueRandom(t, 3000), residueRandom(t, 16)
			m := hmac.New(sha512.New, salt)
			m.Write(secret)
			prk := m.Sum(nil)
			out := make([]byte, 64)
			if _, err := io.ReadFull(hkdf.New(sha512.New, secret, salt, []byte(residueMessage)), out); err != nil {
				t.Fatal(err)
			}
			pats := append([]residuePattern{{"secret", secret}, {"output", out}}, hmacKeyPatterns(t, "prk", prk, "sha512")...)
			return secret, salt, pats
		},
		victim: func(buf *secmem.SecureBuffer, aux []byte) (func() error, func() error, error) {
			op := func() error {
				out, err := secmem.NewEmptyBuffer(64)
				if err != nil {
					return err
				}
				defer out.Destroy()
				return buf.WithBytesErr(func(secret []byte) error {
					return HKDFInto(sha512.New, secret, aux, []byte(residueMessage), out)
				})
			}
			return op, buf.Destroy, nil
		},
	},
	{
		// An info too long for the stack region, over SHA3-256, whose HMAC
		// block is its 136-byte rate and whose state is the Keccak lanes.
		name: "HMACInto/SHA3-256-long-info", class: residueContained, nOps: 8,
		material: func(t *testing.T) ([]byte, []byte, []residuePattern) {
			key, info := residueRandom(t, 32), residueRandom(t, 3000)
			m := hmac.New(func() hash.Hash { return sha3.New256() }, key)
			m.Write(info)
			pats := append([]residuePattern{{"output", m.Sum(nil)}}, hmacKeyPatterns(t, "key", key, "sha3-256")...)
			return key, info, pats
		},
		victim: func(buf *secmem.SecureBuffer, aux []byte) (func() error, func() error, error) {
			op := func() error {
				out, err := secmem.NewEmptyBuffer(32)
				if err != nil {
					return err
				}
				defer out.Destroy()
				return buf.WithBytesErr(func(key []byte) error {
					return HMACInto(func() hash.Hash { return sha3.New256() }, key, aux, out)
				})
			}
			return op, buf.Destroy, nil
		},
	},
}

// ---------------------------------------------------------------- victims

// mlkemMaterial is a seed, a ciphertext encapsulated to its key with a known
// message m through the standard library's derandomized test helper, m, and
// the shared key.
func mlkemMaterial(t *testing.T) (seed, ct, m, shared []byte) {
	t.Helper()
	seed, m = residueRandom(t, 64), residueRandom(t, 32)
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		t.Fatal(err)
	}
	shared, ct, err = mlkemtest.Encapsulate768(dk.EncapsulationKey(), m)
	if err != nil {
		t.Fatal(err)
	}
	return seed, ct, m, shared
}

func mlkemVictim(buf *secmem.SecureBuffer, aux []byte) (func() error, func() error, error) {
	k, err := NewMLKEM768Key(buf)
	if err != nil {
		return nil, nil, err
	}
	op := func() error {
		ss, err := k.Decapsulate(aux)
		if err != nil {
			return err
		}
		return ss.Destroy()
	}
	return op, k.Destroy, nil
}

var residueSink []byte

//go:noinline
func residueHeapCopy(p []byte) {
	b := make([]byte, len(p))
	copy(b, p)
	residueSink = b
	residueSink = nil
}

func signOp(s crypto.Signer, opts crypto.SignerOpts, digest []byte) func() error {
	return func() error {
		_, err := s.Sign(rand.Reader, digest, opts)
		return err
	}
}

func destroyAll(fs ...func() error) func() error {
	return func() error {
		var errs []error
		for _, f := range fs {
			errs = append(errs, f())
		}
		return errors.Join(errs...)
	}
}

// copyWithin copies src[off:off+n] into dst, locked memory to locked memory,
// inside a Scrub window: the copy moves the bytes through vector registers,
// and outside a window an asynchronous preemption before they are reused
// saves them onto the goroutine stack (control/preempted-copy-outside-scrub
// shows it, and an earlier version of this helper left seeds there).
func copyWithin(dst, src *secmem.SecureBuffer, off, n int) error {
	return secmem.ScrubErr(func() error {
		return src.WithBytesErr(func(s []byte) error {
			return dst.WithBytesErr(func(d []byte) error {
				copy(d, s[off:off+n])
				return nil
			})
		})
	})
}

var residueSpinAcc uint64

// residueSpin burns CPU without a call, so the scheduler can take the
// goroutine off it only by asynchronous preemption.
//
//go:noinline
func residueSpin(n int) {
	for i := 0; i < n; i++ {
		residueSpinAcc += uint64(i) ^ residueSpinAcc>>3
	}
}

// copyThenPreempted copies the secret between two locked buffers with nested
// WithBytesErr calls and then, after both have returned, spins while another
// goroutine collects continuously.
func copyThenPreempted(buf *secmem.SecureBuffer, _ []byte) (func() error, func() error, error) {
	dst, err := secmem.NewEmptyBuffer(32)
	if err != nil {
		return nil, nil, err
	}
	var stop atomic.Bool
	collected := make(chan struct{})
	go func() {
		defer close(collected)
		for !stop.Load() {
			runtime.GC()
		}
	}()
	op := func() error {
		err := buf.WithBytesErr(func(s []byte) error {
			return dst.WithBytesErr(func(d []byte) error {
				copy(d, s[:32])
				return nil
			})
		})
		residueSpin(200_000_000)
		return err
	}
	destroy := func() error {
		stop.Store(true)
		<-collected
		return destroyAll(dst.Destroy, buf.Destroy)()
	}
	return op, destroy, nil
}

// preemptedCopy copies the secret between two locked buffers and, with the
// halves still in the registers, spins while another goroutine collects
// continuously — so the spin is asynchronously preempted — optionally
// inside a Scrub window.
func preemptedCopy(inScrub bool) func(buf *secmem.SecureBuffer, _ []byte) (func() error, func() error, error) {
	return func(buf *secmem.SecureBuffer, _ []byte) (func() error, func() error, error) {
		dst, err := secmem.NewEmptyBuffer(32)
		if err != nil {
			return nil, nil, err
		}
		var stop atomic.Bool
		collected := make(chan struct{})
		go func() {
			defer close(collected)
			for !stop.Load() {
				runtime.GC()
			}
		}()
		body := func() error {
			return buf.WithBytesErr(func(s []byte) error {
				return dst.WithBytesErr(func(d []byte) error {
					copy(d, s[:32])
					residueSpin(200_000_000)
					return nil
				})
			})
		}
		op := body
		if inScrub {
			op = func() error { return secmem.ScrubErr(body) }
		}
		destroy := func() error {
			stop.Store(true)
			<-collected
			return destroyAll(dst.Destroy, buf.Destroy)()
		}
		return op, destroy, nil
	}
}

// ---------------------------------------------------------------- patterns

func residueRandom(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func randomSecret(n int, label string) func(t *testing.T) ([]byte, []byte, []residuePattern) {
	return func(t *testing.T) ([]byte, []byte, []residuePattern) {
		s := residueRandom(t, n)
		return s, nil, []residuePattern{{label, s}}
	}
}

// beAndLE is a big-endian integer and its byte-reversed form, which is how
// math/big and bigmod limbs lay it out in little-endian memory.
func beAndLE(label string, be []byte) []residuePattern {
	le := slices.Clone(be)
	slices.Reverse(le)
	return []residuePattern{{label + "-be", be}, {label + "-le", le}}
}

func xorAll(b []byte, x byte) []byte {
	c := slices.Clone(b)
	for i := range c {
		c[i] ^= x
	}
	return c
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// hmacKeyPatterns covers everything an HMAC implementation derives from a
// key no longer than the hash's block that recovers the MAC: the key, the key
// XORed into the inner and outer pads, and the hash state after each pad
// block — SHA-2's chaining value in marshalled (big-endian) and in-memory
// (native little-endian words) order, or SHA-3's whole Keccak state. The
// states are key-equivalent: with them, anyone can compute the MAC.
func hmacKeyPatterns(t *testing.T, label string, key []byte, alg string) []residuePattern {
	t.Helper()
	var (
		newHash func() hash.Hash
		state   func(st []byte) []residuePattern
	)
	switch alg {
	case "sha256":
		newHash = sha256.New
		state = func(st []byte) []residuePattern { // "sha\x03", h[0..7] as big-endian uint32
			cv := slices.Clone(st[4:36])
			return []residuePattern{{"state-be", cv}, {"state-mem", wordSwap(cv, 4)}}
		}
	case "sha512":
		newHash = sha512.New
		state = func(st []byte) []residuePattern { // "sha\x07", h[0..7] as big-endian uint64
			cv := slices.Clone(st[4:68])
			return []residuePattern{{"state-be", cv}, {"state-mem", wordSwap(cv, 8)}}
		}
	case "sha3-256":
		newHash = func() hash.Hash { return sha3.New256() }
		state = func(st []byte) []residuePattern { // "sha\x08", rate, a[200]
			return []residuePattern{{"state", slices.Clone(st[5:205])}}
		}
	default:
		t.Fatalf("hmacKeyPatterns: unknown hash %q", alg)
	}
	pats := []residuePattern{{label, key}, {label + "^ipad", xorAll(key, 0x36)}, {label + "^opad", xorAll(key, 0x5c)}}
	for _, pad := range []struct {
		name string
		x    byte
	}{{"inner", 0x36}, {"outer", 0x5c}} {
		h := newHash()
		block := make([]byte, h.BlockSize())
		copy(block, key)
		for i := range block {
			block[i] ^= pad.x
		}
		h.Write(block)
		st, err := h.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range state(st) {
			pats = append(pats, residuePattern{label + "-" + pad.name + "-" + p.label, p.b})
		}
	}
	return pats
}

// wordSwap reverses each w-byte word of b.
func wordSwap(b []byte, w int) []byte {
	c := slices.Clone(b)
	for i := 0; i+w <= len(c); i += w {
		slices.Reverse(c[i : i+w])
	}
	return c
}

// sha3State is the 200-byte Keccak state of d, from its marshalled form
// ("sha\x09" magic, rate byte, state, n, direction).
func sha3State(t *testing.T, d *sha3.SHAKE) []byte {
	t.Helper()
	st, err := d.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 4+1+200+2 {
		t.Fatalf("SHAKE marshalled state is %d bytes; the layout this test reads has changed", len(st))
	}
	return slices.Clone(st[5:205])
}

// ed25519Patterns covers the seed and everything RFC 8032 signing derives
// from it that recovers the key: the expanded secret h = SHA-512(seed), the
// private scalar in edwards25519's internal (Montgomery-domain) layout, the
// nonce digest for residueMessage and the nonce scalar in both layouts — a
// nonce and its signature together give the private scalar.
func ed25519Patterns(seed []byte) []residuePattern {
	h := sha512.Sum512(seed)
	s, _ := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	nonce := sha512.Sum512(append(slices.Clone(h[32:]), residueMessage...))
	r, _ := edwards25519.NewScalar().SetUniformBytes(nonce[:])
	return []residuePattern{
		{"seed", seed},
		{"h[:32]", slices.Clone(h[:32])},
		{"h[32:]", slices.Clone(h[32:])},
		{"scalar-mem", scalarMemory(s)},
		{"nonce-digest", nonce[:]},
		{"nonce-scalar", r.Bytes()},
		{"nonce-scalar-mem", scalarMemory(r)},
	}
}

func scalarMemory(s *edwards25519.Scalar) []byte {
	//nolint:gosec // G103: reading this test's own Scalar value to learn its in-memory layout.
	return slices.Clone(unsafe.Slice((*byte)(unsafe.Pointer(s)), unsafe.Sizeof(*s)))
}

// aesSchedulePatterns is the expanded AES key schedule, encryption and
// decryption, exactly as crypto/aes lays it out on this architecture.
func aesSchedulePatterns(t *testing.T, label string, key []byte) []residuePattern {
	t.Helper()
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	var pats []residuePattern
	for _, f := range aesRoundKeyFields {
		v, err := aesRoundKeys(blk, f)
		if err != nil {
			t.Fatal(err)
		}
		// Only the populated words: (rounds+1)*4 of the array.
		n := (len(key) + 28) * 4
		pats = append(pats, residuePattern{label + "-" + f, slices.Clone(v[:n])})
	}
	return pats
}

const (
	residueArgon2Time   = 1
	residueArgon2Memory = 1024 // KiB
)

func argon2Material(t *testing.T) ([]byte, []byte, []residuePattern) {
	pw, salt := residueRandom(t, 32), residueRandom(t, 16)
	out := argon2.IDKey(pw, salt, residueArgon2Time, residueArgon2Memory, 1, 32)
	// H0 per RFC 9106 §3.2: parallelism, tag length, memory, time, version,
	// type, then each of P, S, K, X length-prefixed.
	var in []byte
	for _, v := range []uint32{1, 32, residueArgon2Memory, residueArgon2Time, 0x13, 2} {
		in = binary.LittleEndian.AppendUint32(in, v)
	}
	for _, part := range [][]byte{pw, salt, nil, nil} {
		in = binary.LittleEndian.AppendUint32(in, uint32(len(part)))
		in = append(in, part...)
	}
	h0 := blake2b.Sum512(in)
	return pw, salt, []residuePattern{{"password", pw}, {"H0", h0[:]}, {"output", out}}
}

func x25519Material(t *testing.T) ([]byte, []byte, []residuePattern) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := priv.ECDH(peer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	scalar := priv.Bytes()
	clamped := slices.Clone(scalar)
	clamped[0] &= 248
	clamped[31] &= 127
	clamped[31] |= 64
	return scalar, peer.PublicKey().Bytes(), []residuePattern{{"scalar", scalar}, {"clamped", clamped}, {"shared", shared}}
}

// marshalEncryptedOpenSSH writes seed as an aes256-ctr, bcrypt-protected
// OpenSSH key file at the given cost.
func marshalEncryptedOpenSSH(t *testing.T, seed, pass []byte, rounds int) []byte {
	t.Helper()
	buf, err := secmem.NewBuffer(slices.Clone(seed))
	if err != nil {
		t.Skipf("NewBuffer: %v", err)
	}
	s, err := NewEd25519Signer(buf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()
	out, err := s.MarshalOpenSSHPrivateKeyWithPassphraseParams("residue", pass, OpenSSHPassphraseParams{Rounds: rounds})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Destroy()
	var file []byte
	if err := out.WithBytesErr(func(p []byte) error {
		file = slices.Clone(p) //nolint:secmem-lint // parent side: the scan needs the file it hunts the victim's memory for
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return file
}

// openSSHKDFOptions reads the bcrypt salt and rounds from an openssh-key-v1
// PEM file.
func openSSHKDFOptions(t *testing.T, file []byte) ([]byte, int) {
	t.Helper()
	blk, _ := pem.Decode(file)
	if blk == nil {
		t.Fatal("not PEM")
	}
	b := blk.Bytes
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b, []byte(magic)) {
		t.Fatal("not openssh-key-v1")
	}
	b = b[len(magic):]
	str := func() []byte {
		if len(b) < 4 {
			t.Fatal("truncated")
		}
		n := binary.BigEndian.Uint32(b)
		if int(n) > len(b)-4 {
			t.Fatal("truncated")
		}
		s := b[4 : 4+n]
		b = b[4+n:]
		return s
	}
	_ = str() // cipher
	_ = str() // kdf
	opts := str()
	b = opts
	salt := str()
	if len(b) != 4 {
		t.Fatal("bad kdf options")
	}
	return slices.Clone(salt), int(binary.BigEndian.Uint32(b))
}
