package secmemcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"testing"
)

// rfc8032Vector holds one test vector from RFC 8032 §7.1.
type rfc8032Vector struct {
	name    string
	seedHex string
	pubHex  string
	msgHex  string
	sigHex  string
}

// RFC 8032 §7.1 — all five official Ed25519 test vectors, including TEST 4
// (the only official vector whose message spans multiple SHA-512 blocks)
// and TEST 5. Beyond matching the RFC's expected bytes, every vector's
// signature is also cross-checked against crypto/ed25519.Verify at test
// time, so a transcription error in this table cannot pass silently.
var rfc8032Vectors = []rfc8032Vector{
	{
		name:    "TEST 1",
		seedHex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		pubHex:  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		msgHex:  "",
		sigHex:  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
	},
	{
		name:    "TEST 2",
		seedHex: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		pubHex:  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
		msgHex:  "72",
		sigHex:  "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
	},
	{
		name:    "TEST 3",
		seedHex: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
		pubHex:  "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
		msgHex:  "af82",
		sigHex:  "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
	},
	{
		// RFC 8032 TEST 4 — 1023-byte message: the multi-block SHA-512 case.
		name:    "TEST 4 (1023-byte msg)",
		seedHex: "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
		pubHex:  "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
		msgHex: "08b8b2b733424243760fe426a4b54908" +
			"632110a66c2f6591eabd3345e3e4eb98" +
			"fa6e264bf09efe12ee50f8f54e9f77b1" +
			"e355f6c50544e23fb1433ddf73be84d8" +
			"79de7c0046dc4996d9e773f4bc9efe57" +
			"38829adb26c81b37c93a1b270b20329d" +
			"658675fc6ea534e0810a4432826bf58c" +
			"941efb65d57a338bbd2e26640f89ffbc" +
			"1a858efcb8550ee3a5e1998bd177e93a" +
			"7363c344fe6b199ee5d02e82d522c4fe" +
			"ba15452f80288a821a579116ec6dad2b" +
			"3b310da903401aa62100ab5d1a36553e" +
			"06203b33890cc9b832f79ef80560ccb9" +
			"a39ce767967ed628c6ad573cb116dbef" +
			"efd75499da96bd68a8a97b928a8bbc10" +
			"3b6621fcde2beca1231d206be6cd9ec7" +
			"aff6f6c94fcd7204ed3455c68c83f4a4" +
			"1da4af2b74ef5c53f1d8ac70bdcb7ed1" +
			"85ce81bd84359d44254d95629e9855a9" +
			"4a7c1958d1f8ada5d0532ed8a5aa3fb2" +
			"d17ba70eb6248e594e1a2297acbbb39d" +
			"502f1a8c6eb6f1ce22b3de1a1f40cc24" +
			"554119a831a9aad6079cad88425de6bd" +
			"e1a9187ebb6092cf67bf2b13fd65f270" +
			"88d78b7e883c8759d2c4f5c65adb7553" +
			"878ad575f9fad878e80a0c9ba63bcbcc" +
			"2732e69485bbc9c90bfbd62481d9089b" +
			"eccf80cfe2df16a2cf65bd92dd597b07" +
			"07e0917af48bbb75fed413d238f5555a" +
			"7a569d80c3414a8d0859dc65a46128ba" +
			"b27af87a71314f318c782b23ebfe808b" +
			"82b0ce26401d2e22f04d83d1255dc51a" +
			"ddd3b75a2b1ae0784504df543af8969b" +
			"e3ea7082ff7fc9888c144da2af58429e" +
			"c96031dbcad3dad9af0dcbaaaf268cb8" +
			"fcffead94f3c7ca495e056a9b47acdb7" +
			"51fb73e666c6c655ade8297297d07ad1" +
			"ba5e43f1bca32301651339e22904cc8c" +
			"42f58c30c04aafdb038dda0847dd988d" +
			"cda6f3bfd15c4b4c4525004aa06eeff8" +
			"ca61783aacec57fb3d1f92b0fe2fd1a8" +
			"5f6724517b65e614ad6808d6f6ee34df" +
			"f7310fdc82aebfd904b01e1dc54b2927" +
			"094b2db68d6f903b68401adebf5a7e08" +
			"d78ff4ef5d63653a65040cf9bfd4aca7" +
			"984a74d37145986780fc0b16ac451649" +
			"de6188a7dbdf191f64b5fc5e2ab47b57" +
			"f7f7276cd419c17a3ca8e1b939ae49e4" +
			"88acba6b965610b5480109c8b17b80e1" +
			"b7b750dfc7598d5d5011fd2dcc5600a3" +
			"2ef5b52a1ecc820e308aa342721aac09" +
			"43bf6686b64b2579376504ccc493d97e" +
			"6aed3fb0f9cd71a43dd497f01f17c0e2" +
			"cb3797aa2a2f256656168e6c496afc5f" +
			"b93246f6b1116398a346f1a641f3b041" +
			"e989f7914f90cc2c7fff357876e506b5" +
			"0d334ba77c225bc307ba537152f3f161" +
			"0e4eafe595f6d9d90d11faa933a15ef1" +
			"369546868a7f3a45a96768d40fd9d034" +
			"12c091c6315cf4fde7cb68606937380d" +
			"b2eaaa707b4c4185c32eddcdd306705e" +
			"4dc1ffc872eeee475a64dfac86aba41c" +
			"0618983f8741c5ef68d3a101e8a3b8ca" +
			"c60c905c15fc910840b94c00a0b9d0",
		sigHex: "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
	},
	{
		// RFC 8032 TEST 5 — the message is SHA-512("abc").
		name:    "TEST 5",
		seedHex: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
		pubHex:  "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
		msgHex:  "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		sigHex:  "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
	},
}

func TestSignEd25519Direct_RFC8032Vectors(t *testing.T) {
	t.Parallel()
	for _, vec := range rfc8032Vectors {
		t.Run(vec.name, func(t *testing.T) {
			t.Parallel()
			seed := mustDecodeHex(t, vec.seedHex)
			wantPub := mustDecodeHex(t, vec.pubHex)
			msg := mustDecodeHex(t, vec.msgHex)
			wantSig := mustDecodeHex(t, vec.sigHex)

			sig, err := signEd25519Direct(seed, msg)
			if err != nil {
				t.Fatalf("signEd25519Direct: %v", err)
			}
			if !bytes.Equal(sig, wantSig) {
				t.Errorf("signature mismatch\n  got:  %x\n  want: %x", sig, wantSig)
			}
			if !ed25519.Verify(ed25519.PublicKey(wantPub), msg, sig) {
				t.Error("stdlib ed25519.Verify rejected our signature")
			}
		})
	}
}

func TestSignEd25519Direct_ByteIdenticalToStdlib(t *testing.T) {
	t.Parallel()
	for i := range 20 {
		t.Run("random_key_"+strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			msg := []byte("secmem-crypto attestation payload " + strconv.Itoa(i))

			ourSig, err := signEd25519Direct(priv.Seed(), msg)
			if err != nil {
				t.Fatalf("signEd25519Direct: %v", err)
			}
			stdlibSig := ed25519.Sign(priv, msg)

			if !bytes.Equal(ourSig, stdlibSig) {
				t.Errorf("signature differs from stdlib\n  ours:   %x\n  stdlib: %x", ourSig, stdlibSig)
			}
			if !ed25519.Verify(pub, msg, ourSig) {
				t.Error("stdlib Verify rejected our signature")
			}
		})
	}
}

func TestDeriveEd25519PublicKey_MatchesStdlib(t *testing.T) {
	t.Parallel()
	for _, vec := range rfc8032Vectors {
		t.Run(vec.name, func(t *testing.T) {
			t.Parallel()
			seed := mustDecodeHex(t, vec.seedHex)
			wantPub := mustDecodeHex(t, vec.pubHex)

			gotPub, err := deriveEd25519PublicKey(seed)
			if err != nil {
				t.Fatalf("deriveEd25519PublicKey: %v", err)
			}
			if !bytes.Equal(gotPub, wantPub) {
				t.Errorf("public key mismatch\n  got:  %x\n  want: %x", gotPub, wantPub)
			}
		})
	}
}

// TestDeriveEd25519PublicKey_RandomKeysMatchStdlib exercises the derive path
// against stdlib key generation across many random seeds — deriveEd25519PublicKey
// has its own SHA-512+clamp+ScalarBaseMult code path (not shared with
// signEd25519Direct), so the signing cross-checks do not transitively cover it.
func TestDeriveEd25519PublicKey_RandomKeysMatchStdlib(t *testing.T) {
	t.Parallel()
	for i := range 50 {
		t.Run("random_"+strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			gotPub, err := deriveEd25519PublicKey(priv.Seed())
			if err != nil {
				t.Fatalf("deriveEd25519PublicKey: %v", err)
			}
			if !bytes.Equal(gotPub, pub) {
				t.Errorf("derived pubkey differs from stdlib\n  got:  %x\n  want: %x", gotPub, pub)
			}
		})
	}
}

func TestSignEd25519Direct_BadSeedLength(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 16, 31, 33, 64} {
		t.Run(strconv.Itoa(n)+"_bytes", func(t *testing.T) {
			t.Parallel()
			_, err := signEd25519Direct(make([]byte, n), []byte("msg"))
			if err == nil {
				t.Fatal("expected error for bad seed length, got nil")
			}
		})
	}
}

func TestSignEd25519Direct_NilSeed(t *testing.T) {
	t.Parallel()
	_, err := signEd25519Direct(nil, []byte("msg"))
	if err == nil {
		t.Fatal("expected error for nil seed, got nil")
	}
}

func TestDeriveEd25519PublicKey_BadSeedLength(t *testing.T) {
	t.Parallel()
	if _, err := deriveEd25519PublicKey(make([]byte, 31)); err == nil {
		t.Fatal("expected error for bad seed length")
	}
	if _, err := deriveEd25519PublicKey(nil); err == nil {
		t.Fatal("expected error for nil seed")
	}
}

func TestSignEd25519Direct_EmptyMessage(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig, err := signEd25519Direct(priv.Seed(), nil)
	if err != nil {
		t.Fatalf("signEd25519Direct: %v", err)
	}
	if !ed25519.Verify(pub, nil, sig) {
		t.Error("stdlib Verify rejected empty-message signature")
	}
	if stdlibSig := ed25519.Sign(priv, nil); !bytes.Equal(sig, stdlibSig) {
		t.Errorf("empty-message sig differs from stdlib\n  ours:   %x\n  stdlib: %x", sig, stdlibSig)
	}
}

// TestSignEd25519Direct_SScalarIsReduced checks the response scalar S is
// canonically reduced mod the group order L — a real historical class of
// Ed25519 malleability bug when implementations skip this reduction.
func TestSignEd25519Direct_SScalarIsReduced(t *testing.T) {
	t.Parallel()
	// L = 2^252 + 27742317777372353535851937790883648493, little-endian bytes.
	lBytes := mustDecodeHex(t, "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")

	for i := range 10 {
		t.Run("key_"+strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			sig, err := signEd25519Direct(priv.Seed(), []byte("malleability check "+strconv.Itoa(i)))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if S := sig[32:]; !isLessThanLE(S, lBytes) {
				t.Errorf("S scalar is not reduced mod L: %x", S)
			}
		})
	}
}

func TestSignEd25519Direct_Deterministic(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	seed := priv.Seed()
	msg := []byte("determinism check")

	sig1, err := signEd25519Direct(seed, msg)
	if err != nil {
		t.Fatalf("sign 1: %v", err)
	}
	sig2, err := signEd25519Direct(seed, msg)
	if err != nil {
		t.Fatalf("sign 2: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Error("same seed+message produced different signatures — nonce derivation is non-deterministic")
	}
}

func TestSignEd25519Direct_SeedReadOnly(t *testing.T) {
	t.Parallel()
	seed := mustDecodeHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	seedCopy := append([]byte(nil), seed...)

	if _, err := signEd25519Direct(seed, []byte("wipe test")); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !bytes.Equal(seed, seedCopy) {
		t.Error("signEd25519Direct modified the seed — must be read-only access")
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

// isLessThanLE compares two equal-length little-endian byte slices: a < b.
func isLessThanLE(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := len(a) - 1; i >= 0; i-- {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return false
}
