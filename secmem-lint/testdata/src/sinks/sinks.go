// Package sinks covers the sink table: standard-library functions and methods
// that copy, log or persist whatever they are handed.
package sinks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/deadpoets/secmem"
)

var (
	sinkB   []byte
	sinkS   string
	sinkSS  [][]byte
	sinkAny any
	sinkBuf bytes.Buffer
	sinkCtx context.Context
	syncMap sync.Map
	atomicV atomic.Value
	atomicP atomic.Pointer[[]byte]
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

// bytesHelpers: the bytes / slices functions that return a SUB-SLICE of their
// argument (the strip-the-newline-off-a-password idiom) yield the same secure
// memory, so their result carries taint and is reported where it escapes; the
// ones that return a NEW slice are heap copies and sinks in their own right.
func bytesHelpers(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		sinkB = bytes.TrimSpace(b)                // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkB = bytes.TrimSuffix(b, []byte("\n")) // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkB = bytes.TrimPrefix(b, []byte("k=")) // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkB = bytes.Trim(b, " ")                // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkSS = bytes.Split(b, []byte(":"))      // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkSS = bytes.Fields(b)                  // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		before, after, _ := bytes.Cut(b, []byte(":"))
		sinkB = before // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkB = after  // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		rest, _ := bytes.CutPrefix(b, []byte("k="))
		sinkB = rest                   // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkB = slices.Clip(b)         // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkB = slices.Grow(b, 8)      // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		sinkB = slices.Clip[[]byte](b) // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		for line := range bytes.Lines(b) {
			sinkB = line // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		}
		sinkB = bytes.ToUpper(b)                                        // want `secmem-lint: borrowed secret bytes passed to bytes.ToUpper`
		sinkB = bytes.ToLower(b)                                        // want `secmem-lint: borrowed secret bytes passed to bytes.ToLower`
		sinkB = bytes.ReplaceAll(b, []byte("a"), []byte("b"))           // want `secmem-lint: borrowed secret bytes passed to bytes.ReplaceAll`
		sinkB = bytes.Map(func(r rune) rune { return r }, b)            // want `secmem-lint: borrowed secret bytes passed to bytes.Map`
		sinkB = bytes.ToValidUTF8(b, nil)                               // want `secmem-lint: borrowed secret bytes passed to bytes.ToValidUTF8`
		_, _ = io.Copy(io.Discard, bytes.NewReader(bytes.TrimSpace(b))) // ok: the trimmed window is consumed inside the lease
		_ = bytes.Equal(bytes.TrimSpace(b), []byte("x"))                // ok: a comparison
		_ = bytes.HasPrefix(b, []byte("k="))                            // ok: a bool
	})
}

// slogWith: the package-level slog.With retains its arguments in the logger it
// returns, exactly as the *Logger method does.
func slogWith(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		slog.With("password", b).Info("login") // want `secmem-lint: borrowed secret bytes passed to log/slog.With`
		slog.SetDefault(slog.With("k", b))     // want `secmem-lint: borrowed secret bytes passed to log/slog.With`
		l := slog.With("k", b)                 // want `secmem-lint: borrowed secret bytes passed to log/slog.With`
		l.Info("x")                            // reported once, at the With
	})
}

// bigIntAndEd25519: math/big.Int keeps its magnitude on the heap, and
// crypto/ed25519.PrivateKey's methods take the same paths as the package
// functions already in the table — a method sink fires on a tainted RECEIVER,
// not only on tainted arguments.
func bigIntAndEd25519(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		d := new(big.Int).SetBytes(b) // want `secmem-lint: borrowed secret bytes passed to math/big.Int.SetBytes`
		var x big.Int
		x.SetBytes(b)                                                                                                // want `secmem-lint: borrowed secret bytes passed to math/big.Int.SetBytes`
		x.SetString(unsafe.String(unsafe.SliceData(b), len(b)), 16)                                                  // want `secmem-lint: borrowed secret bytes passed to math/big.Int.SetString`
		sinkAny = &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}, D: new(big.Int).SetBytes(b)} // want `secmem-lint: borrowed secret bytes passed to math/big.Int.SetBytes`
		_, _ = ed25519.PrivateKey(b).Sign(nil, []byte("m"), nil)                                                     // want `secmem-lint: borrowed secret bytes passed to crypto/ed25519.PrivateKey.Sign`
		sinkB = ed25519.PrivateKey(b).Seed()                                                                         // want `secmem-lint: borrowed secret bytes passed to crypto/ed25519.PrivateKey.Seed`
		_ = d
		_ = x.FillBytes(make([]byte, 32)) // ok: writes INTO the argument, and x is not tainted
	})
}

// encoderMethods: the streaming encoders serialise through a heap buffer just
// as json.Marshal does.
func encoderMethods(buf *secmem.SecureBuffer, w io.Writer) {
	_ = buf.WithBytes(func(b []byte) {
		_ = json.NewEncoder(w).Encode(b)                     // want `secmem-lint: borrowed secret bytes passed to encoding/json.Encoder.Encode`
		_ = json.NewEncoder(w).Encode(struct{ K []byte }{b}) // want `secmem-lint: borrowed secret bytes passed to encoding/json.Encoder.Encode`
		_ = xml.NewEncoder(w).Encode(b)                      // want `secmem-lint: borrowed secret bytes passed to encoding/xml.Encoder.Encode`
		_ = gob.NewEncoder(w).Encode(b)                      // want `secmem-lint: borrowed secret bytes passed to encoding/gob.Encoder.Encode`
		_ = json.NewEncoder(w).Encode(len(b))                // ok: a length
	})
}

type ctxKey struct{}

// retainingStores: the concurrency-safe forms of outerMap["k"] = b, and a
// context that carries the value for as long as it lives.
func retainingStores(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		syncMap.Store("k", b)                                          // want `secmem-lint: borrowed secret bytes passed to sync.Map.Store`
		_, _ = syncMap.LoadOrStore("k", b)                             // want `secmem-lint: borrowed secret bytes passed to sync.Map.LoadOrStore`
		_, _ = syncMap.Swap("k", b)                                    // want `secmem-lint: borrowed secret bytes passed to sync.Map.Swap`
		atomicV.Store(b)                                               // want `secmem-lint: borrowed secret bytes passed to sync/atomic.Value.Store`
		_ = atomicV.Swap(b)                                            // want `secmem-lint: borrowed secret bytes passed to sync/atomic.Value.Swap`
		atomicP.Store(&b)                                              // want `secmem-lint: borrowed secret bytes passed to sync/atomic.Pointer.Store`
		sinkCtx = context.WithValue(context.Background(), ctxKey{}, b) // want `secmem-lint: borrowed secret bytes assigned to a variable outside the closure`
		_ = context.WithValue(context.Background(), ctxKey{}, len(b))  // ok: a length
		syncMap.Store("n", len(b))                                     // ok: a length
	})
}
