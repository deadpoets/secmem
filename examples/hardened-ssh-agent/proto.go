//go:build unix

// proto.go implements the SSH agent wire protocol
// (draft-miller-ssh-agent / OpenSSH PROTOCOL.agent) with one design rule
// that separates it from a generic implementation:
//
//	Incoming messages can contain private keys. Every parser here returns
//	SUBSLICES of the single message buffer — never copies — so that one
//	secmem.SecureWipe of the message buffer provably destroys every
//	transient copy of key material this file ever touched. The only copy
//	that outlives the message is the one written directly into a
//	SecureBuffer.
//
// This is why the file does NOT use ssh.Unmarshal: unmarshalling into a
// struct with string fields would scatter untracked copies of the private
// key across the Go heap, defeating the wipe.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Agent protocol message numbers (draft-miller-ssh-agent §5.1).
const (
	agentFailure            = 5
	agentSuccess            = 6
	agentcRequestIdentities = 11
	agentIdentitiesAnswer   = 12
	agentcSignRequest       = 13
	agentSignResponse       = 14
	agentcAddIdentity       = 17
	agentcRemoveIdentity    = 18
	agentcRemoveAll         = 19
	agentcLock              = 22
	agentcUnlock            = 23

	// SSH_AGENTC_ADD_ID_CONSTRAINED: an add carrying constraints. The
	// spec is strict: an agent that does not support a listed constraint
	// MUST fail the whole add. This agent supports LIFETIME (the key is
	// destroyed — wiped, not hidden — at the deadline) and refuses
	// CONFIRM and extensions, failing closed rather than accepting a key
	// under protections it would not enforce.
	agentcAddIDConstrained = 25
)

// Constraint type bytes (OpenSSH PROTOCOL.agent).
const (
	constrainLifetime  = 1   // uint32 seconds
	constrainConfirm   = 2   // no payload; requires an askpass UI we don't have
	constrainExtension = 255 // string name + payload
)

// maxAgentMessage caps a single agent message. OpenSSH uses 256 KiB; the
// keys this agent accepts fit in a few hundred bytes, but staying
// protocol-tolerant costs nothing — the cap exists so a hostile client
// cannot make the agent allocate unbounded memory.
const maxAgentMessage = 256 * 1024

var (
	errShortMessage = errors.New("agent: truncated message")
	errOversized    = errors.New("agent: message exceeds maximum size")
)

// readMessage reads one length-prefixed agent message from r.
//
// OWNERSHIP: the returned slice may contain private key material (for
// ADD_IDENTITY it always does). The caller MUST secmem.SecureWipe it when
// done — the connection loop in main.go does this unconditionally for
// every message, so parsers below never need to.
func readMessage(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err // io.EOF here is a clean disconnect
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 {
		return nil, errShortMessage
	}
	if n > maxAgentMessage {
		return nil, errOversized
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, fmt.Errorf("agent: reading %d-byte message: %w", n, err)
	}
	return msg, nil
}

// writeMessage writes one length-prefixed agent message. payload contains
// only public data on every path in this program (signatures, public key
// blobs, status bytes), so no wipe discipline is needed on the way out.
func writeMessage(w io.Writer, payload []byte) error {
	var lenBuf [4]byte
	//nolint:gosec // G115: an agent reply is far below uint32 max (and well under maxAgentMessage).
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readUint32 consumes a big-endian uint32 from buf.
func readUint32(buf []byte) (v uint32, rest []byte, err error) {
	if len(buf) < 4 {
		return 0, nil, errShortMessage
	}
	return binary.BigEndian.Uint32(buf), buf[4:], nil
}

// readString consumes an SSH "string" (uint32 length + bytes) from buf.
// The returned value ALIASES buf — see the file comment for why.
func readString(buf []byte) (val, rest []byte, err error) {
	n, rest, err := readUint32(buf)
	if err != nil {
		return nil, nil, err
	}
	//nolint:gosec // G115: rest is a subslice of a message already capped at maxAgentMessage.
	if uint32(len(rest)) < n {
		return nil, nil, errShortMessage
	}
	return rest[:n], rest[n:], nil
}

// appendString appends an SSH "string" encoding of val to dst.
func appendString(dst, val []byte) []byte {
	var lenBuf [4]byte
	//nolint:gosec // G115: an SSH string in an agent reply is bounded far below uint32 max.
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(val)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, val...)
}

// trimLeadingZeros strips the leading zero octets an SSH mpint carries to
// keep positive numbers unsigned. The result still aliases the input.
func trimLeadingZeros(b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

// addIdentityRequest is a parsed SSH_AGENTC_ADD_IDENTITY message. Every
// []byte field aliases the message buffer; the struct must not outlive it.
type addIdentityRequest struct {
	keyType []byte // "ssh-ed25519" or "ecdsa-sha2-nistp{256,384,521}"

	// Ed25519 fields (keyType == "ssh-ed25519"):
	edPub  []byte // 32-byte public key, used to cross-check the seed
	edSeed []byte // first 32 bytes of the wire ENC(A)||k private field

	// ECDSA fields (keyType == "ecdsa-sha2-nistp*"):
	ecCurveName []byte // "nistp256" etc., must agree with keyType suffix
	ecScalar    []byte // private scalar d, leading zeros already trimmed

	comment string // safe to retain: comments are not secret

	// lifetimeSecs > 0 means the identity self-destructs — SecureBuffer
	// destroyed and wiped — this many seconds after being added.
	lifetimeSecs uint32
}

// parseAddIdentity parses the body (message type byte already consumed) of
// an ADD_IDENTITY or ADD_ID_CONSTRAINED request for the key types this
// agent supports. It validates structure only; cryptographic validation
// (seed→pubkey consistency, scalar range) happens in keyring.Add where
// the material is moved into secure memory. When constrained is true, the
// bytes after the comment are parsed as constraints; any constraint this
// agent does not enforce fails the add, per spec.
func parseAddIdentity(body []byte, constrained bool) (*addIdentityRequest, error) {
	keyType, rest, err := readString(body)
	if err != nil {
		return nil, err
	}
	req := &addIdentityRequest{keyType: keyType}

	switch string(keyType) {
	case "ssh-ed25519":
		// string pub(32) | string priv(64 = seed || pub) | string comment
		pub, r, err := readString(rest)
		if err != nil {
			return nil, err
		}
		priv, r, err := readString(r)
		if err != nil {
			return nil, err
		}
		if len(pub) != 32 || len(priv) != 64 {
			return nil, fmt.Errorf("agent: malformed ssh-ed25519 key (pub=%d priv=%d bytes)", len(pub), len(priv))
		}
		comment, r, err := readString(r)
		if err != nil {
			return nil, err
		}
		req.edPub = pub
		req.edSeed = priv[:32]
		req.comment = string(comment)
		return req, parseConstraints(req, r, constrained)

	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		// string curve_name | string Q | mpint d | string comment
		curveName, r, err := readString(rest)
		if err != nil {
			return nil, err
		}
		if want := string(keyType[len("ecdsa-sha2-"):]); string(curveName) != want {
			return nil, fmt.Errorf("agent: curve name %q does not match key type %q", curveName, keyType)
		}
		if _, r, err = readString(r); err != nil { // Q: recomputed from d, not trusted
			return nil, err
		}
		d, r, err := readString(r)
		if err != nil {
			return nil, err
		}
		comment, r, err := readString(r)
		if err != nil {
			return nil, err
		}
		req.ecCurveName = curveName
		req.ecScalar = trimLeadingZeros(d)
		req.comment = string(comment)
		return req, parseConstraints(req, r, constrained)

	default:
		// RSA, DSA, sk-* (FIDO), and certificates are deliberate
		// non-goals of the minimal core — see README "Forking guide".
		return nil, fmt.Errorf("agent: unsupported key type %q", keyType)
	}
}

// parseConstraints parses the constraint block trailing a constrained add.
// Fail-closed is the entire design: the dangerous bug class for agents is
// accepting a key while silently dropping a constraint the user believes
// is in force. Anything other than a well-formed LIFETIME fails the add.
func parseConstraints(req *addIdentityRequest, rest []byte, constrained bool) error {
	if !constrained {
		if len(rest) != 0 {
			return errors.New("agent: trailing bytes after unconstrained add")
		}
		return nil
	}
	for len(rest) > 0 {
		ctype := rest[0]
		rest = rest[1:]
		switch ctype {
		case constrainLifetime:
			secs, r, err := readUint32(rest)
			if err != nil {
				return err
			}
			if secs == 0 {
				return errors.New("agent: zero lifetime constraint")
			}
			req.lifetimeSecs = secs
			rest = r
		case constrainConfirm:
			return errors.New("agent: confirm constraint requires a UI channel this agent does not have (see README forking guide)")
		default:
			return fmt.Errorf("agent: unsupported constraint type %d", ctype)
		}
	}
	return nil
}

// signRequest is a parsed SSH_AGENTC_SIGN_REQUEST. keyBlob and data alias
// the message buffer, which is public-safe here (a sign request carries no
// private material) but keeps the aliasing rule uniform.
type signRequest struct {
	keyBlob []byte
	data    []byte
	flags   uint32
}

func parseSignRequest(body []byte) (*signRequest, error) {
	blob, rest, err := readString(body)
	if err != nil {
		return nil, err
	}
	data, rest, err := readString(rest)
	if err != nil {
		return nil, err
	}
	flags, _, err := readUint32(rest)
	if err != nil {
		return nil, err
	}
	return &signRequest{keyBlob: blob, data: data, flags: flags}, nil
}
