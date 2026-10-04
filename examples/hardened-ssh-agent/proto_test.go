//go:build unix

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// stallingReader delivers a length prefix, then part of the body, then
// fails — a client that stalls or disconnects halfway through a message. It
// keeps the slice io.ReadFull handed it for the body, which is the message
// buffer itself, so the test can read that buffer after readMessage has
// dropped it.
type stallingReader struct {
	prefix  []byte // the 4-byte length, served first
	partial []byte // the part of the body that arrives
	failure error  // what the read after it returns

	body []byte // readMessage's buffer, as passed to Read
}

func (r *stallingReader) Read(p []byte) (int, error) {
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	if r.body == nil {
		r.body = p
		return copy(p, r.partial), nil
	}
	return 0, r.failure
}

// A message that never completes must not leave what did arrive in a heap
// buffer nobody will wipe: for ADD_IDENTITY that is the private key.
func TestReadMessage_WipesPartialMessageOnReadError(t *testing.T) {
	seed := bytes.Repeat([]byte{0xA5}, 32)
	for _, failure := range []error{io.ErrUnexpectedEOF, errors.New("i/o timeout")} {
		r := &stallingReader{
			prefix:  binary.BigEndian.AppendUint32(nil, uint32(len(seed)+8)),
			partial: seed,
			failure: failure,
		}
		msg, err := readMessage(r)
		if err == nil || msg != nil {
			t.Fatalf("readMessage = (%d bytes, %v), want an error and no message", len(msg), err)
		}
		if r.body == nil {
			t.Fatal("the reader was never handed the message buffer")
		}
		if len(r.body) != len(seed)+8 {
			t.Fatalf("captured %d bytes, want the whole %d-byte message buffer", len(r.body), len(seed)+8)
		}
		if bytes.Contains(r.body, seed) {
			t.Errorf("after %v: the dropped message buffer still holds the %d key bytes that arrived", failure, len(seed))
		}
		if !bytes.Equal(r.body, make([]byte, len(r.body))) {
			t.Errorf("after %v: the dropped message buffer is not zero", failure)
		}
	}
}
