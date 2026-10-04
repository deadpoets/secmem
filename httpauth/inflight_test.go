package httpauth_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"testing"
	"time"

	"github.com/deadpoets/secmem/httpauth"
)

// TestRoundTrip_LeavesTheRequestAloneWhileTheTransportWritesIt forces the
// window in which net/http's transport has returned a response but is still
// writing the request: the server answers before the request head is out, and
// a trace hook holds the transport's write loop — after the request line and
// Host, before it reads Request.Header — until RoundTrip has returned.
//
// A RoundTripper must not touch the request in that window. Deleting the
// credential from it there is a write to a map another goroutine is reading,
// and the head goes out without the header; this asserts on the head the
// server received, so it fails with or without the race detector.
func TestRoundTrip_LeavesTheRequestAloneWhileTheTransportWritesIt(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	const wait = 10 * time.Second
	writing := make(chan struct{})  // the write loop has started on the head
	returned := make(chan struct{}) // RoundTrip has returned
	finish := make(chan struct{})   // the test is done with the connection
	head := make(chan http.Header, 1)
	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer func() { _ = conn.Close() }()
		select {
		case <-writing:
		case <-time.After(wait):
			srvErr <- context.DeadlineExceeded
			return
		}
		// The early answer. Its body is withheld so the transport keeps the
		// connection, and the pending write, alive.
		if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"); err != nil {
			srvErr <- err
			return
		}
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			srvErr <- err
			return
		}
		head <- req.Header
		_, _ = io.WriteString(conn, "ok")
		<-finish
	}()
	t.Cleanup(func() { close(finish) })

	var once sync.Once
	trace := &httptrace.ClientTrace{
		WroteHeaderField: func(key string, _ []string) {
			if key != "Host" {
				return
			}
			once.Do(func() {
				close(writing)
				select {
				case <-returned:
				case <-time.After(wait):
				}
			})
		},
	}

	base := &http.Transport{}
	t.Cleanup(base.CloseIdleConnections)
	tr := httpauth.NewBearer(tok, base)
	tr.AllowInsecureHTTP = true
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace),
		http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := tr.RoundTrip(req)
	select {
	case <-writing:
	default:
		t.Error("RoundTrip returned before the write loop reached the hook; the window was not forced")
	}
	close(returned)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	select {
	case h := <-head:
		if got := h.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("request head arrived with Authorization = %q, want %q: the request was mutated while the transport was still writing it", got, "Bearer tok")
		}
	case err := <-srvErr:
		t.Fatalf("server: %v", err)
	case <-time.After(wait):
		t.Fatal("the request head never arrived")
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if resp.Request == nil {
		t.Fatal("response has no Request")
	}
	if _, present := resp.Request.Header["Authorization"]; present {
		t.Errorf("response.Request carries the credential")
	}
}
