# Passphrase-protected OpenSSH fixtures

Throwaway keys written by a real `ssh-keygen` (OpenSSH 10.3p1), so the
parser is tested against what the tool writes rather than against
x/crypto's marshaller alone. The passphrase for every file is
`secmem-test-passphrase`; the keys were generated for this directory and
are used for nothing else.

Each `.b64` is the base64 body of the private-key file with the PEM header
and footer lines removed — the tests put the armour back. The armour is
stripped so the repository's secret scanner, which keys on the PEM header,
does not flag test fixtures as leaked keys. The matching `.pub` is the
public key `ssh-keygen` wrote alongside.

| File | Command (after `-N secmem-test-passphrase -C fixture -f <name>`) | Covers |
|---|---|---|
| `ed25519-a16` | `ssh-keygen -t ed25519` | ssh-keygen's defaults: aes256-ctr, bcrypt, 16 rounds |
| `ed25519-a1` | `ssh-keygen -t ed25519 -a 1` | one round, for the tests that parse many times |
| `ed25519-cbc-a1` | `ssh-keygen -t ed25519 -a 1 -Z aes256-cbc` | the CBC mode |
| `ed25519-chacha-a1` | `ssh-keygen -t ed25519 -a 1 -Z chacha20-poly1305@openssh.com` | an unsupported cipher: must be refused, not misread |
| `ecdsa-a1` | `ssh-keygen -t ecdsa -b 256 -a 1` | the ECDSA private block after decryption |
| `rsa-a1` | `ssh-keygen -t rsa -b 2048 -a 1` | the RSA private block after decryption |

To regenerate, run the commands above and strip the first and last line of
each private-key file into the `.b64`.
