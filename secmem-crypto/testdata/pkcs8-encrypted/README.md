# PKCS#8 PBES2 fixtures

Throwaway keys encrypted by a real `openssl pkcs8 -topk8` (OpenSSL 3.5.6)
and, for one file, by `ssh-keygen -p -m PKCS8` (OpenSSH 10.x, which writes
through its own libcrypto call and picks a different profile), so the parser
is tested against what the tools write rather than against an encoder of
this module's own. The passphrase for every file is `secmem-test-passphrase`;
the three keys were generated for this directory and are used for nothing
else. Their public halves are `ed25519.pub`, `ecdsa-p256.pub` and
`rsa-2048.pub` (SubjectPublicKeyInfo PEM, from `openssl pkey -pubout`).

Each `.b64` is the base64 body of the `ENCRYPTED PRIVATE KEY` file with the
PEM header and footer lines removed — the tests put the armour back. The
armour is stripped so the repository's secret scanner, which keys on the
PEM header, does not flag test fixtures as leaked keys.

Every file was written by `openssl pkcs8 -topk8 -in <key> -passout
pass:secmem-test-passphrase` plus the options in the table, unless the row
says otherwise. OpenSSL's default iteration count is 2048; with `-scrypt` its
defaults are N=16384, r=8, p=1 and aes-256-cbc, and it writes no `keyLength`.

| File | Options | Covers |
|---|---|---|
| `ed25519-aes256-cbc-sha256` | `-v2 aes-256-cbc -v2prf hmacWithSHA256` | OpenSSL 3's defaults, spelled out |
| `ed25519-aes128-cbc-sha256` | `-v2 aes-128-cbc -v2prf hmacWithSHA256` | a 16-byte key: the scheme decides how much PBKDF2 derives |
| `ed25519-aes192-cbc-sha256` | `-v2 aes-192-cbc -v2prf hmacWithSHA256` | a 24-byte key |
| `ed25519-aes256-cbc-sha1` | `-v2 aes-256-cbc -v2prf hmacWithSHA1` | the ASN.1 DEFAULT PRF: the `prf` field is absent from the file, not present naming SHA-1 |
| `ed25519-aes256-cbc-sha224` | `-v2prf hmacWithSHA224` | each PRF OID the parser maps |
| `ed25519-aes256-cbc-sha384` | `-v2prf hmacWithSHA384` | |
| `ed25519-aes256-cbc-sha512` | `-v2prf hmacWithSHA512` | a 128-byte HMAC block |
| `ed25519-aes256-cbc-sha512-224` | `-v2prf hmacWithSHA512-224` | |
| `ed25519-aes256-cbc-sha512-256` | `-v2prf hmacWithSHA512-256` | |
| `ed25519-iter1` | `-v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 1` | one iteration, for the tests that parse many times |
| `ed25519-iter600k` | `-v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 600000` | the count modern guidance recommends, and a three-byte INTEGER |
| `ed25519-sshkeygen` | `ssh-keygen -p -m PKCS8 -f <key> -P "" -N secmem-test-passphrase` | a second writer: aes-128-cbc with hmacWithSHA256 |
| `ed25519-scrypt` | `-scrypt` | the scrypt KDF as openssl writes it by default: a 16 MiB working set, locked for the parse |
| `ed25519-scrypt-n1024` | `-scrypt -scrypt_N 1024 -scrypt_r 8 -scrypt_p 1` | a 1 MiB working set, for the tests that parse many times, the fuzzer's seeds and the residue scan |
| `ed25519-scrypt-n1024-p2` | `-scrypt -scrypt_N 1024 -scrypt_r 8 -scrypt_p 2` | p > 1: two passes of the memory-hard step over B |
| `ed25519-scrypt-n1024-aes128` | `-scrypt -scrypt_N 1024 -scrypt_r 8 -scrypt_p 1 -v2 aes-128-cbc` | a 16-byte key from scrypt: the scheme decides how much it derives |
| `ed25519-scrypt-n32768-r1` | `-scrypt -scrypt_N 32768 -scrypt_r 1 -scrypt_p 1` | r = 1, at the largest N scrypt defines for it (N < 2^16); openssl refuses to write the next one |
| `ecdsa-p256-aes256-cbc-sha256` | `-v2 aes-256-cbc -v2prf hmacWithSHA256` on a P-256 key | the heap-transients gate, which can only run after decryption here |
| `rsa-2048-aes256-cbc-sha256` | `-v2 aes-256-cbc -v2prf hmacWithSHA256` on a 2048-bit RSA key | the same gate, and an RSA key that keeps the whole decrypted buffer |

`refused/` holds real files the parser must not open, so the refusals are
tested against what the tools write rather than against hand-made DER:

| File | Options | Refused as |
|---|---|---|
| `refused/scrypt-rfc7914` | none: the example file of RFC 7914 §13, copied from the RFC (passphrase `Rabbit`; N=1048576, r=8, p=1) | unsupported (`ErrUnsupportedKey`): a 1 GiB working set, over `MaxScryptMemory`. openssl cannot write such a file — it refuses scrypt parameters past 32 MiB — so the RFC's is the real one there is |
| `refused/pbes2-des-ede3-cbc` | `-v2 des3 -v2prf hmacWithSHA256` | retired (`ErrRetiredAlgorithm`) |
| `refused/pbes2-rc2-cbc` | `-v2 rc2-cbc -v2prf hmacWithSHA256 -provider legacy -provider default` | retired; this file also carries an explicit `keyLength` in its PBKDF2 parameters |
| `refused/pbe-sha1-3des` | `-v1 PBE-SHA1-3DES` | retired: PKCS#12 PBE, the default `openssl pkcs8 -topk8` wrote before 1.1.0 |
| `refused/pbe-sha1-rc2-40` | `-v1 PBE-SHA1-RC2-40 -provider legacy -provider default` | retired: PKCS#12 PBE |
| `refused/pbe-md5-des` | `-v1 PBE-MD5-DES -provider legacy -provider default` | retired: PBES1 |

To regenerate, run the commands above and strip the first and last line of
each private-key file into the `.b64`.
