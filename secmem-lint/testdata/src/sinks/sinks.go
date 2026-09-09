// Package sinks covers the sink table: standard-library functions and methods
// that copy, log or persist whatever they are handed.
package sinks

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/deadpoets/secmem"
)

var (
	sinkB   []byte
	sinkS   string
	sinkAny any
	sinkBuf bytes.Buffer
)

func writers(buf *secmem.SecureBuffer, w io.Writer, conn net.Conn, f *os.File, bw *bufio.Writer) {
	_ = buf.WithBytes(func(b []byte) {
		sinkBuf.Write(b) // want `secmem-lint: borrowed secret bytes passed to bytes.Buffer.Write`
		var sb strings.Builder
		sb.Write(b)                    // want `secmem-lint: borrowed secret bytes passed to strings.Builder.Write`
		bw.Write(b)                    // want `secmem-lint: borrowed secret bytes passed to bufio.Writer.Write`
		f.Write(b)                     // want `secmem-lint: borrowed secret bytes passed to os.File.Write`
		os.Stdout.Write(b)             // want `secmem-lint: borrowed secret bytes passed to os.File.Write`
		os.WriteFile("k", b, 0o600)    // want `secmem-lint: borrowed secret bytes passed to os.WriteFile`
		w.Write(b)                     // ok: an io.Writer is the intended egress
		conn.Write(b)                  // ok: so is a net.Conn
		io.Copy(w, bytes.NewReader(b)) // ok
	})
}

func decoders(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		json.Unmarshal(b, &sinkAny)                          // want `secmem-lint: borrowed secret bytes passed to encoding/json.Unmarshal`
		json.NewDecoder(bytes.NewReader(b)).Decode(&sinkAny) // want `secmem-lint: borrowed secret bytes passed to encoding/json.NewDecoder`
		sinkAny = bytes.NewBuffer(b)                         // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkAny = strings.NewReader(string(b))               // want `secmem-lint: string\(\) copies borrowed secret bytes`
	})
}

func cryptoKeys(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		aes.NewCipher(b)               // want `secmem-lint: borrowed secret bytes passed to crypto/aes.NewCipher`
		chacha20poly1305.New(b)        // want `secmem-lint: borrowed secret bytes passed to golang.org/x/crypto/chacha20poly1305.New`
		hmac.New(sha256.New, b)        // want `secmem-lint: borrowed secret bytes passed to crypto/hmac.New`
		ed25519.NewKeyFromSeed(b)      // want `secmem-lint: borrowed secret bytes passed to crypto/ed25519.NewKeyFromSeed`
		x509.ParsePKCS8PrivateKey(b)   // want `secmem-lint: borrowed secret bytes passed to crypto/x509.ParsePKCS8PrivateKey`
		ecdh.X25519().NewPrivateKey(b) // want `secmem-lint: borrowed secret bytes passed to crypto/ecdh.Curve.NewPrivateKey`
		_ = sha256.Sum256(b)           // ok: hashing is not in the table
	})
}

func encoders(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sinkS = hex.Dump(b)                             // want `secmem-lint: borrowed secret bytes passed to encoding/hex.Dump`
		sinkB = hex.AppendEncode(nil, b)                // want `secmem-lint: borrowed secret bytes passed to encoding/hex.AppendEncode`
		sinkB = base64.StdEncoding.AppendEncode(nil, b) // want `secmem-lint: borrowed secret bytes passed to encoding/base64.Encoding.AppendEncode`
		sinkS = base64.RawURLEncoding.EncodeToString(b) // want `secmem-lint: borrowed secret bytes passed to encoding/base64.Encoding.EncodeToString`
		sinkB = slices.Concat(b)                        // want `secmem-lint: borrowed secret bytes passed to slices.Concat`
		sinkB = bytes.Join([][]byte{b}, nil)            // want `secmem-lint: borrowed secret bytes passed to bytes.Join`
		sinkB = bytes.Repeat(b, 2)                      // want `secmem-lint: borrowed secret bytes passed to bytes.Repeat`
	})
}

func loggers(buf *secmem.SecureBuffer, l *slog.Logger, t *testing.T, tb testing.TB) {
	_ = buf.WithBytes(func(b []byte) {
		slog.Info("x", slog.Any("k", b))            // want `secmem-lint: borrowed secret bytes passed to log/slog.Any`
		slog.Info("x", slog.String("k", string(b))) // want `secmem-lint: string\(\) copies borrowed secret bytes`
		sinkAny = l.With("k", b)                    // want `secmem-lint: borrowed secret bytes passed to log/slog.Logger.With`
		l.WithGroup("g").Info("x", "k", b)          // want `secmem-lint: borrowed secret bytes passed to log/slog.Logger.Info`
		t.Logf("%x", b)                             // want `secmem-lint: borrowed secret bytes passed to testing.T.Logf`
		t.Errorf("%x", b)                           // want `secmem-lint: borrowed secret bytes passed to testing.T.Errorf`
		tb.Fatalf("%x", b)                          // want `secmem-lint: borrowed secret bytes passed to testing.TB.Fatalf`
		t.Logf("n=%d", len(b))                      // ok
	})
}

func fmtPositions(buf *secmem.SecureBuffer, w io.Writer) {
	_ = buf.WithBytes(func(b []byte) {
		sinkS = fmt.Sprintf("%x", b[1:])        // want `secmem-lint: borrowed secret bytes passed to fmt.Sprintf`
		sinkS = fmt.Sprintf("%v %v", 1, any(b)) // want `secmem-lint: borrowed secret bytes passed to fmt.Sprintf`
		args := []any{b}
		sinkS = fmt.Sprintf("%s", args...) // want `secmem-lint: borrowed secret bytes passed to fmt.Sprintf`
		fmt.Fprintf(w, "%x", b)            // want `secmem-lint: borrowed secret bytes passed to fmt.Fprintf`
		sinkS = fmt.Sprintf("%d", len(b))  // ok
		fmt.Fprintf(w, "n=%d", len(b))     // ok
	})
}
